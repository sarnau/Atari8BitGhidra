# Ghidra Atari 8-Bit File Formats
This is generic Ghidra loader for various Atari 8-bit file formats. Currently supported are by file extensions are the following formats:

## Disk Images
DOS files can be read as well as the boot sector file. They are read to the original address and the entry points are marked. Also directly reading a number of sectors from disk to a specific RAM address is supported.

- ATR (80 and 128 byte sector size)
- ATX

## Binaries
Binaries can be simple binary blobs of data, which can be read to a specific RAM address or are XEX files, which start with $FFFF and have chunks of data. Each chunk becomes a memory block, but chunks that are adjacent in memory are merged into one. If you provide a loading address != 0, the XEX file will be forced loaded to that address and the file structure will be ignored.

- XEX
- COM

## Cartridges
There is very limited support for CAR files, only type 1 (8kb), 2 (16kb) and 4 (32kb) are supported. No bank switching, etc. cartridges are supported.

- CAR
