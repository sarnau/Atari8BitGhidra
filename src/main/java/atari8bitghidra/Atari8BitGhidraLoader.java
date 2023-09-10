/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package atari8bitghidra;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.opinion.AbstractProgramWrapperLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.Option;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.framework.model.DomainObject;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.lang.Language;

import org.python.jline.internal.Log;

import atari8bitghidra.AtariDiskImage.AtariDiskDirEntry;

/**
 * This loader supports various Atari 8-bit file formats (ATR, ATX for disk
 * images, CAR for a few cartridge types and XEX and COM for raw files)
 */
public class Atari8BitGhidraLoader extends AbstractProgramWrapperLoader {
	public static final String VERSION = "v1.0";

	public AtariDiskImage image = null;
	public Boolean isXEXfile = false;
	public Boolean isCartridge = false;
	public Boolean isBootfile = false;

	// Gets the Loader's name, which is used both for display purposes, and to
	// identify the Loader in the opinion files.
	@Override
	public String getName() {
		return "Atari 8-Bit File Formats";
	}

	// If this Loader supports loading the given ByteProvider, this methods returns
	// a Collection of all supported LoadSpecs that contain discovered load
	// specification information that this Loader will need to load.
	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();
		BinaryReader br = new BinaryReader(provider, true);

		String name = provider.getFile().getName().toLowerCase();
		try {
			image = null;
			if (name.endsWith(".atr"))
				image = new AtariATRImage(br);
			else if (name.endsWith(".atx"))
				image = new AtariATXImage(br);
			else if (name.endsWith(".xex") || name.endsWith(".com"))
				isXEXfile = true;
			else if (name.endsWith(".car"))
				isCartridge = true;
			else if (name.endsWith(".atboot"))
				isBootfile = true;
			if (image != null || isXEXfile || isCartridge || isBootfile)
				loadSpecs.add(
						new LoadSpec(this, 0, new LanguageCompilerSpecPair("6502:LE:16:default", "default"), true));
		} catch (Exception ex) {
			Log.error(ex.getMessage());
		}
		return loadSpecs;
	}

	private void loadDiskSectors(BinaryReader br, int startSector, int sectorCount, int addr, Program program,
			TaskMonitor monitor, MessageLog log) throws Exception {
		FlatProgramAPI api = new FlatProgramAPI(program);
		byte[] bootFile = image.ReadSectors(br, startSector, sectorCount);
		ByteArrayProvider bap = new ByteArrayProvider(bootFile);
		MemoryBlockUtils.createInitializedBlock(program, false, String.format("SECTORS_%3d", startSector),
				api.toAddr(addr), bap.getInputStream(0), bootFile.length, null,
				String.format("SECTORS #%d (%d sectors)", startSector, sectorCount), true, true, true, log, monitor);
		bap.close();
	}

	private void loadAtariBootFile(BinaryReader br, int loadAddr, Program program, TaskMonitor monitor,
			MessageLog log) throws Exception {
		FlatProgramAPI api = new FlatProgramAPI(program);
		byte[] bootFile = br.readByteArray(0, (int)br.length());
//		byte DFLAGS = bootFile[0];
		int DBSECT = bootFile[1] & 0xFF;
		if (DBSECT == 0)
			DBSECT = 256;
		int BOOTAD = (bootFile[2] & 0xFF) + ((bootFile[3] & 0xFF) << 8);
		int DOSINI = (bootFile[4] & 0xFF) + ((bootFile[5] & 0xFF) << 8);

		ByteArrayProvider bap = new ByteArrayProvider(bootFile);
		if (loadAddr != 0)
			BOOTAD = loadAddr;
		MemoryBlockUtils.createInitializedBlock(program, false, String.format("BOOTFILE_%04X", BOOTAD),
				api.toAddr(BOOTAD), bap.getInputStream(0), bootFile.length, null, "BOOTFILE", true, true, true, log,
				monitor);
		bap.close();

		// Define the BOOT Sector header
		api.createByte(api.toAddr(BOOTAD));
		api.setEOLComment(api.toAddr(BOOTAD), "DBFLAGS");
		api.createByte(api.toAddr(BOOTAD + 1));
		api.setEOLComment(api.toAddr(BOOTAD + 1), "DBSECT");
		api.setEOLComment(api.toAddr(BOOTAD + 2), "BOOTAD");
		api.createData(api.toAddr(BOOTAD + 2), PointerDataType.dataType);
		api.setEOLComment(api.toAddr(BOOTAD + 4), "DOSINI");
		api.createData(api.toAddr(BOOTAD + 4), PointerDataType.dataType);

		api.addEntryPoint(api.toAddr(DOSINI));
		api.createFunction(api.toAddr(DOSINI), "DOSINI");
		api.disassemble(api.toAddr(DOSINI));
		api.addEntryPoint(api.toAddr(BOOTAD + 6));
		api.createFunction(api.toAddr(BOOTAD + 6), "BOOT_CONTINUE");
		api.disassemble(api.toAddr(BOOTAD + 6));
	}

	private void loadDiskSectorFile(BinaryReader br, int startSector, Program program, TaskMonitor monitor,
			MessageLog log) throws Exception {
		FlatProgramAPI api = new FlatProgramAPI(program);
		byte[] bootSector = image.ReadSectors(br, startSector, 1);
//		byte DFLAGS = bootSector[0];
		int DBSECT = (bootSector[1] & 0xFF);
		if (DBSECT == 0)
			DBSECT = 256;
		int BOOTAD = (bootSector[2] & 0xFF) + ((bootSector[3] & 0xFF) << 8);
		int DOSINI = (bootSector[4] & 0xFF) + ((bootSector[5] & 0xFF) << 8);
		byte[] bootFile = image.ReadSectors(br, startSector, DBSECT);

		ByteArrayProvider bap = new ByteArrayProvider(bootFile);
		MemoryBlockUtils.createInitializedBlock(program, false, String.format("BOOTFILE_%04X", BOOTAD),
				api.toAddr(BOOTAD), bap.getInputStream(0), bootFile.length, null, "BOOTFILE", true, true, true, log,
				monitor);
		bap.close();

		// Define the BOOT Sector header
		api.createByte(api.toAddr(BOOTAD));
		api.setEOLComment(api.toAddr(BOOTAD), "DBFLAGS");
		api.createByte(api.toAddr(BOOTAD + 1));
		api.setEOLComment(api.toAddr(BOOTAD + 1), "DBSECT");
		api.setEOLComment(api.toAddr(BOOTAD + 2), "BOOTAD");
		api.createData(api.toAddr(BOOTAD + 2), PointerDataType.dataType);
		api.setEOLComment(api.toAddr(BOOTAD + 4), "DOSINI");
		api.createData(api.toAddr(BOOTAD + 4), PointerDataType.dataType);

		api.addEntryPoint(api.toAddr(DOSINI));
		api.createFunction(api.toAddr(DOSINI), "DOSINI");
		api.disassemble(api.toAddr(DOSINI));
		api.addEntryPoint(api.toAddr(BOOTAD + 6));
		api.createFunction(api.toAddr(BOOTAD + 6), "BOOT_CONTINUE");
		api.disassemble(api.toAddr(BOOTAD + 6));
	}

	private void loadDiskFile(BinaryReader br, int fileIndex, int loadAddr, Program program, TaskMonitor monitor,
			MessageLog log) throws Exception {
		AtariDiskDirEntry entry = image.entries.get(fileIndex);
		ByteArrayProvider bap = new ByteArrayProvider(image.ReadFile(br, entry));
		loadEXEFile(new BinaryReader(bap, true), entry.filename + "." + entry.extension, loadAddr, program, monitor,
				log);
		bap.close();
	}

	private void CreateChunk(BinaryReader br, String filename, long loadIndex, int chunkStart, int chunkEnd,
			Program program, MessageLog log) throws Exception {
		FlatProgramAPI api = new FlatProgramAPI(program);
		log.appendMsg(String.format("chunkStart:%#04x", chunkStart) + String.format(", chunkEnd:%#04x", chunkEnd)
				+ ", chunkSize:" + (chunkEnd - chunkStart + 1));
		MemoryBlock block = MemoryBlockUtils.createInitializedBlock(program, false,
				String.format("CHUNK_%04X", chunkStart), api.toAddr(chunkStart), chunkEnd - chunkStart + 1, null,
				filename, true, true, true, log);
		for (int c = 0; c < chunkEnd - chunkStart + 1; ++c) {
			block.putByte(api.toAddr(chunkStart + c), br.readByte(loadIndex + c));
		}
	}

	private void loadEXEFile(BinaryReader br, String filename, int loadAddr, Program program, TaskMonitor monitor,
			MessageLog log) throws Exception {
		FlatProgramAPI api = new FlatProgramAPI(program);
		int header = br.readUnsignedShort(0); // read the header
		if (header != 0xFFFF || loadAddr > 0) { // not an XEX file, load to supplied address or _force_ to load
			MemoryBlock block = MemoryBlockUtils.createInitializedBlock(program, false,
					String.format("FILE_%04X", loadAddr), api.toAddr(loadAddr), br.length(), null, filename, true, true,
					true, log);
			for (int c = 0; c < br.length(); ++c) {
				block.putByte(api.toAddr(loadAddr + c), br.readByte(c));
			}
		} else {
			long index = 2;
			int startAddr = -1, midLoadAddr = -1;
			long lastStartIndex = 0;
			int lastChunkStart = 0;
			int lastChunkEnd = 0;
			while (header == 0xFFFF && index < br.length()) { // The COM file header is 0xFFFF
				int chunkStart = br.readUnsignedShort(index);
				int chunkEnd = br.readUnsignedShort(index + 2);
				if (chunkStart == 0xFFFF) { // for other chunks the header is optional
					index += 2;
					continue;
				}
				index += 4;
				if (chunkStart == 0x02E0 && chunkEnd == 0x02E1) { // the last 0x02E0 chunk is the start address of
																	// the code
					if (lastChunkStart != 0) {
						CreateChunk(br, filename, lastStartIndex, lastChunkStart, lastChunkEnd, program, log);
						lastChunkStart = 0;
					}
					startAddr = br.readUnsignedShort(index);
					log.appendMsg(String.format("startAddr:%#04x", startAddr));
					index += 2;
				} else if (chunkStart == 0x02E2 && chunkEnd == 0x02E3) { // mid-load chunk code execution
					if (lastChunkStart != 0) {
						CreateChunk(br, filename, lastStartIndex, lastChunkStart, lastChunkEnd, program, log);
						lastChunkStart = 0;
					}
					midLoadAddr = br.readUnsignedShort(index);
					log.appendMsg(String.format("midLoadAddr:%#04x", midLoadAddr));
					if (midLoadAddr >= 0) {
						api.addEntryPoint(api.toAddr(midLoadAddr));
						api.createFunction(api.toAddr(midLoadAddr), String.format("ENTRY_%04X", midLoadAddr));
						api.disassemble(api.toAddr(midLoadAddr));
					}
					index += 2;
				} else {
					if (lastChunkEnd + 1 == chunkStart) {
						lastChunkEnd = chunkEnd;
					} else {
						if (lastChunkStart != 0) {
							CreateChunk(br, filename, lastStartIndex, lastChunkStart, lastChunkEnd, program, log);
						}
						lastStartIndex = index;
						lastChunkStart = chunkStart;
						lastChunkEnd = chunkEnd;
					}
					index += chunkEnd - chunkStart + 1;
				}
			}
			if (lastChunkStart != 0) {
				CreateChunk(br, filename, lastStartIndex, lastChunkStart, lastChunkEnd, program, log);
				lastChunkStart = 0;
			}
			if (startAddr >= 0) {
				api.addEntryPoint(api.toAddr(startAddr));
				api.createFunction(api.toAddr(startAddr), "START");
				api.disassemble(api.toAddr(startAddr));
			}
		}
	}

	private void loadCarFile(BinaryReader br, String filename, Program program, TaskMonitor monitor, MessageLog log)
			throws Exception {
		FlatProgramAPI api = new FlatProgramAPI(program);
		String magic = br.readAsciiString(0, 4);
		if (!magic.equals("CART"))
			throw new IOException("Invalid CART header detected");
		int cartridgeType = (br.readUnsignedByte(4) << 24) | (br.readUnsignedByte(5) << 16)
				| (br.readUnsignedByte(6) << 8) | (br.readUnsignedByte(7) << 0);
		if (cartridgeType != 1 && cartridgeType != 2 && cartridgeType != 4)
			throw new IOException("Unknown cartridge type");
		long index = 16; // header of the file
		long chunkStart = -1;
		long chunkEnd = 0xBFFF;
		if (cartridgeType == 1) {
			chunkStart = 0xA000; // 8kb cart
		} else if (cartridgeType == 2) {
			chunkStart = 0x8000; // 16kb cart
		} else if (cartridgeType == 4) {
			chunkStart = 0x4000; // 32kb cart
		}
		log.appendMsg(String.format("Cartridge %#04x", chunkStart) + "-" + String.format("%#04x", chunkEnd));
		MemoryBlock block = MemoryBlockUtils.createInitializedBlock(program, false,
				String.format("CHUNK_%04X", chunkStart), api.toAddr(chunkStart), chunkEnd - chunkStart + 1, null,
				filename, true, true, true, log);
		for (int c = 0; c < chunkEnd - chunkStart + 1; ++c) {
			block.putByte(api.toAddr(chunkStart + c), br.readByte(index + c));
		}
		api.addEntryPoint(api.toAddr(chunkStart));
		api.createFunction(api.toAddr(chunkStart), "START");
		api.disassemble(api.toAddr(chunkStart));
	}

	// Loads bytes in a particular format as a new DomainObject.
	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program,
			TaskMonitor monitor, MessageLog log) throws CancelledException, IOException {

		log.appendMsg(getName() + " (" + VERSION + ") loading \"" + provider.getFile().getName() + "\"");
		FlatProgramAPI api = new FlatProgramAPI(program);
		api.start();

		BinaryReader br = new BinaryReader(provider, true);
		try {
			int loadAddr = (int) getValForNamedOption(options, "LOADADDR");
			if (isCartridge) {
				loadCarFile(br, provider.getFile().getName(), program, monitor, log);
			} else if (isBootfile) {
				loadAtariBootFile(br, loadAddr, program, monitor, log);
			} else if (isXEXfile) {
				loadEXEFile(br, provider.getFile().getName(), loadAddr, program, monitor, log);
			} else {
				int fileIndex = 0;
				int startSector = (int) getValForNamedOption(options, "STARTSECTOR");
				int sectorCount = (int) getValForNamedOption(options, "SECTORCOUNT");
				if (startSector > 0) {
					loadDiskSectors(br, startSector, sectorCount, loadAddr, program, monitor, log);
					program.setName(String.format("SECTORS_%3d", startSector));
				} else {
					Boolean fileLoaded = false;
					for (Option option : options) {
						try {
							if (option.getGroup() == "Files") {
								if ((boolean) option.getValue()) {
									loadDiskFile(br, fileIndex, loadAddr, program, monitor, log);
									AtariDiskDirEntry entry = image.entries.get(fileIndex);
									program.setName(entry.filename + "." + entry.extension);
									fileLoaded = true;
								}
								fileIndex++;
							}
							if (option.getName() == "BOOTFILE" && (boolean) option.getValue()) {
								loadDiskSectorFile(br, 1, program, monitor, log);
								program.setName(option.getName());
								fileLoaded = true;
							}
						} catch (Exception ex) {
							log.appendException(ex);
						}
					}
					if (!fileLoaded) // nothing was loaded?
						throw new CancelledException();
				}
			}
		} catch (Exception ex) {
			log.appendException(ex);
		}
		api.end(true);
	}

	// Checks to see if this Loader supports loading into an existing Program.
	@Override
	public boolean supportsLoadIntoProgram() {
		return true;
	}

	@Override
	protected void createDefaultMemoryBlocks(Program program, Language language, MessageLog log) {
		// The 6502.pspec has default memory blocks that I don't want; these are
		// ZERO_PAGE and a STACK without execute priv. This override keeps that from
		// happening. In the load(), we can recreate STACK if we want.
		return;
	}

	// Gets the default Loader options.
	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec, DomainObject domainObject,
			boolean isLoadIntoProgram) {
		List<Option> list = super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);
		list.add(new Option("Load address", 0, Integer.class, "LOADADDR"));
		if (image != null) {
			list.add(new Option("BOOTFILE", true, Boolean.class, "BOOTFILE"));
			for (AtariDiskDirEntry entry : image.entries) {
				list.add(new Option("Files", "Load \"" + entry.filename + "." + entry.extension + "\"", false));
			}
			list.add(new Option("Start sector", Integer.class, 0, "STARTSECTOR", "Sectors"));
			list.add(new Option("Sector count", Integer.class, 1, "SECTORCOUNT", "Sectors"));
		}
		return list;
	}

	// Validates the Loader's options and returns null if all options are valid;
	// otherwise, an error message describing the problem is returned.
	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {

		int startSector;
		int sectorCount;
		int loadAddr;
		try {
			loadAddr = (int) getValForNamedOption(options, "LOADADDR");
		} catch (IOException e) {
			return "Error: cannot retreive option";
		}
		if (loadAddr >= 0x10000)
			return "Error: invalid loading address";

		if (image != null) {
			try {
				startSector = (int) getValForNamedOption(options, "STARTSECTOR");
				sectorCount = (int) getValForNamedOption(options, "SECTORCOUNT");
			} catch (IOException e) {
				return "Error: cannot retreive option";
			}
			if (startSector < 0 || startSector > AtariDiskImage.MAX_SECTOR_COUNT)
				return "Error: invalid sector number";
			if (sectorCount <= 0 || (sectorCount + startSector - 1) > AtariDiskImage.MAX_SECTOR_COUNT)
				return "Error: invalid sector count";
			if (loadAddr + sectorCount * image.SECTOR_SIZE >= 0x10000)
				return "Error: too large to load into address space";
		}
		return super.validateOptions(provider, loadSpec, options, program);
	}

	protected Object getValForNamedOption(List<Option> options, String optionName) throws IOException {
		for (Option option : options) {
			String arg = option.getArg();
			if (arg != null && arg.equals(optionName)) {
				return option.getValue();
			}
		}
		throw new IOException("Error: option not found");
	}
}
