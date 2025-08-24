# Basic FAT12 fs implementation written in C
Provides basic functionality to read and write files from a FAT12 file system.

Currently supported:
- READ
- CREATE (PARTIALLY)

Todo:
- MODIFY
- DELETE

Should support files up to ~600kb in size

It includes functions to read the BIOS Parameter Block (BPB), locate files, and read/write file data.

The implementation is designed for educational purposes and may not cover all aspects of the FAT12 file system.

usage: prog 0-n<folder> 0-1<file>

example: prog afolder anotherfolder readme.txt

BUILD WITH openwatcom v2
```
wcl -lr -mt prog.c
```

write example can be found in write.c

The program only looks at the first floppy drive (A:)

can be used in dosbox with an mounted floppy image
```
z:\imgmount A <image_file> -t floppy
```