package atari8bitghidra;

import java.io.IOException;
import ghidra.app.util.bin.BinaryReader;

public class AtariATXImage extends AtariDiskImage {
	static final int ATX_HEADER_SIZE = 48; // size of the header for an ATX file
	static final int ATX_TRACK_HEADER_SIZE = 32;
	static final int ATX_SECTOR_LIST_HEADER_SIZE = 8;
	static final int ATX_SECTOR_HEADER_SIZE = 8;

	public class AtariATXImageHeader {
		public AtariATXImageHeader(BinaryReader br) throws Exception {
			String magic = br.readAsciiString(0, 4);
			if (!magic.equals("AT8X"))
				throw new IOException("Invalid ATX header detected");
			if (ATX_HEADER_SIZE != br.readUnsignedInt(28))
				throw new IOException("Invalid ATX header size detected");
			if (1 != br.readUnsignedShort(4))
				throw new IOException("Invalid ATX header version detected");
		}
	}

	@Override
	protected long Sector2Index(BinaryReader br, long sector) throws Exception {
		final long onTrack = (sector - 1) / 18;
		final long onSector = sector - onTrack * 18;

		long offset = ATX_HEADER_SIZE;
		while (offset < br.length()) {
			final long th_record_size = br.readUnsignedInt(offset);
			if (ATX_TRACK_HEADER_SIZE != br.readUnsignedInt(offset + 0x14))
				throw new IOException("Track Header Size != 32 bytes");
			if (0 != br.readUnsignedShort(offset + 4))
				throw new IOException("Track Header record type != data track");
			if (onTrack == br.readUnsignedByte(offset + 8)) {
				long o2 = offset + ATX_TRACK_HEADER_SIZE;
				if (1 != br.readByte(o2 + 4))
					throw new IOException("Sector List Header record type != sector list");
				long record_size = br.readUnsignedInt(o2);
				o2 += ATX_SECTOR_LIST_HEADER_SIZE;
				for (int i = 0; i < record_size; i += ATX_SECTOR_HEADER_SIZE) {
					int sector_number = br.readByte(o2 + i);
					if (sector_number == onSector) {
						long sector_offset = br.readUnsignedInt(o2 + i + 4);
						return offset + sector_offset;
					}
				}
			}
			offset += th_record_size;
		}
		return -1;
	}

	public AtariATXImage(BinaryReader br) throws Exception {
		new AtariATXImageHeader(br);
		LoadDirectory(br);
	}
}
