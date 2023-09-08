package atari8bitghidra;

import java.util.ArrayList;
import java.io.ByteArrayOutputStream;
import ghidra.app.util.bin.BinaryReader;
import org.python.jline.internal.Log;
import java.nio.charset.Charset;

public class AtariDiskImage {
	static final int FIRST_SECTOR = 1; // Atari DOS starts with sector #1
	static final int MAX_SECTOR_COUNT = 720; // max. number of sectors
	static final int SECTOR_OF_VTOC = 360; // starting sector of the VTOC
	static final int SECTOR_OF_VTOC2 = 1024; // Enhanced density disks have a second VTOC at sector 1024
	static final int SECTOR_OF_DIR = 361; // starting sector of the directory
	static final int SECTORCOUNT_OF_DIR = 8; // number of sectors for the directory

	int SECTOR_SIZE = 128; // Bytes per sector on a single density disk, 256 is also possible

	public class AtariDiskDirEntry {
		static final int DIR_ENTRY_SIZE = 16; // Size of an entry in the directory

		public byte flag;
		public int sectorCount;
		public int firstSector;
		String filename;
		String extension;

		public AtariDiskDirEntry(BinaryReader br, long index) throws Exception {
			flag = br.readByte(index);
			sectorCount = br.readUnsignedShort(index + 1);
			firstSector = br.readUnsignedShort(index + 3);
			filename = br.readAsciiString(index + 5, 8).trim();
			extension = br.readAsciiString(index + 13, 3).trim();
		}
	}

	public byte[] ReadSectors(BinaryReader br, long sector, int sectorCount) throws Exception {
		ByteArrayOutputStream bop = new ByteArrayOutputStream();
		for (int i = 0; i < sectorCount; ++i) {
			bop.write(br.readByteArray(Sector2Index(br, sector + i), SECTOR_SIZE));
		}
		return bop.toByteArray();
	}

	public byte[] ReadFile(BinaryReader br, AtariDiskDirEntry entry) throws Exception {
		ByteArrayOutputStream bop = new ByteArrayOutputStream();
		long sector = entry.firstSector;
		while (sector != 0) {
			Log.debug("SECTOR #" + sector);
			long index = Sector2Index(br, sector);
			// int fileIndex = br.readUnsignedByte(index + SECTOR_SIZE - 3) >> 2;
			int forwardPointer = ((br.readUnsignedByte(index + SECTOR_SIZE - 3) & 3) << 8)
					| br.readUnsignedByte(index + SECTOR_SIZE - 2);
			int byteCount = br.readUnsignedByte(index + SECTOR_SIZE - 1);
			if ((byteCount & 0x80) == 0x80) {
				byteCount = SECTOR_SIZE - 3;
			} else {
				byteCount &= 0x7F;
			}
			bop.write(br.readByteArray(index, byteCount));
			sector = forwardPointer;
		}
		return bop.toByteArray();
	}

	protected long Sector2Index(BinaryReader br, long sector) throws Exception {
		return (sector - FIRST_SECTOR) * SECTOR_SIZE;
	}

	private static boolean isPureAscii(String v) {
		return Charset.forName("US-ASCII").newEncoder().canEncode(v);
		// or "ISO-8859-1" for ISO Latin 1
		// or StandardCharsets.US_ASCII with JDK1.7+
	}

	public ArrayList<AtariDiskDirEntry> entries = new ArrayList<AtariDiskDirEntry>();

	protected void LoadDirectory(BinaryReader br) throws Exception {
		for (long dirSector = SECTOR_OF_DIR; dirSector < SECTOR_OF_DIR + SECTORCOUNT_OF_DIR; ++dirSector) {
			for (long dOffset = 0; dOffset <= SECTOR_SIZE; dOffset += AtariDiskDirEntry.DIR_ENTRY_SIZE) {
				AtariDiskDirEntry dirEntry = new AtariDiskDirEntry(br, Sector2Index(br, dirSector) + dOffset);
				// check if the disk has valid entries in the directory, ignore all invalid ones
				if (dirEntry.firstSector < FIRST_SECTOR || dirEntry.firstSector > MAX_SECTOR_COUNT)
					continue;
				if (dirEntry.sectorCount < 1 || dirEntry.sectorCount > MAX_SECTOR_COUNT)
					continue;
				if (!isPureAscii(dirEntry.filename))
					continue;
				if (!isPureAscii(dirEntry.extension))
					continue;
				entries.add(dirEntry);
			}
		}
	}
}
