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

- ATBOOT
If you change the file extension to ATBOOT, the file will be treated like a boot sector and loaded as such (Byte 0: flags, Byte 1:# of sectors, Byte 2/3:load address, etc).

## Cartridges
There is very limited support for CAR files, only type 1 (8kb), 2 (16kb) and 4 (32kb) are supported. No bank switching, etc. cartridges are supported.

- CAR

# Installation

This loader is written and tested with Ghidra 10.3.3.

You can either build the loader via Eclipse directly for Ghidra or you launch Ghidra, select the "File" menu => "Install Extensions" and select the "+" at the top right. In the file selector navigate to the 'dist' directly of this repository (or download the ZIP file from Github manually, currently it is named "ghidra_10.3.3_PUBLIC_20230908_Atari8BitGhidra.zip"). It should then show up in the dialog below.

# Usage

To use the loader just select "Import File" in Ghidra. You should see "Atari 8-Bit File Formats" when a file recognized in the import dialog. Select "Options…" to pick what you like to read.

## Warning!

Select the correct file! Only one should be selected with "BOOTFILE" being the default. If you like to read a DOS file, deselect "BOOTFILE". To read multiple sectors, just enter a start sector != 0 and a sector count. The load address is often part of the file format (BOOTFILE, DOS files), but can be forced by entering a "Load address" != 0. To enter a hex address, just type e.g. "0x700" into the dialog.
