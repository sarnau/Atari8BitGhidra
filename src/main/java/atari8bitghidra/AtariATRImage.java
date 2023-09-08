package atari8bitghidra;

import java.io.IOException;
import ghidra.app.util.bin.BinaryReader;

public class AtariATRImage extends AtariDiskImage {
	static final int ATR_HEADER_SIZE = 16; // size of the header for an ATR file

	public class AtariATRImageHeader {
		public int magic; // 0x0296 as the header
		public long imageSize; // Image size in bytes
		public byte flags; // flags: Bit 4 = 1 means the disk image is treated as copy protected (has bad
							// sectors). Bit 5 = 1 means the disk is write protected.
		public long sectorCount; // number of sectors in the image

		public AtariATRImageHeader(BinaryReader br) throws Exception {
			magic = br.readUnsignedShort(0);
			if (magic != 0x0296)
				throw new IOException("Invalid ATR header detected");
			imageSize = (br.readUnsignedShort(2) | (br.readUnsignedShort(6) << 16)) * 16;
			SECTOR_SIZE = br.readUnsignedShort(4);
			if (SECTOR_SIZE != 128 && SECTOR_SIZE != 256)
				throw new IOException("Unknown sector size detected (only 128 or 256 are supported)");
			flags = br.readByte(8);
			if (SECTOR_SIZE == 128)
				sectorCount = imageSize / SECTOR_SIZE;
			else if (SECTOR_SIZE == 256)
				sectorCount = (imageSize + 3 * 128) / SECTOR_SIZE; // first 3 sectors are always 128 bytes
		}
	}

	@Override
	protected long Sector2Index(BinaryReader br, long sector) throws Exception {
		if (SECTOR_SIZE == 128) {
			return ATR_HEADER_SIZE + (sector - FIRST_SECTOR) * SECTOR_SIZE;
		} else if (SECTOR_SIZE == 256) {
			if (sector <= 3) { // the first 3 sectors are _always_ 128 bytes
				return ATR_HEADER_SIZE + (sector - FIRST_SECTOR) * 128;
			}
			// all other 717 sectors are then 256 bytes
			return ATR_HEADER_SIZE + 3 * 128 + (sector - 3 - FIRST_SECTOR) * SECTOR_SIZE;
		}
		// dummy return for unknown sector sizes, should never happen. If so, we always
		// return sector 1
		return ATR_HEADER_SIZE;
	}

	public AtariATRImage(BinaryReader br) throws Exception {
		new AtariATRImageHeader(br);
		LoadDirectory(br);
	}
}
