# BASIC READ-ONLY FAT12 FILE SYSTEM IMPLEMENTATION in C
This implementation provides basic functionality to read files from a FAT12 file system.

It includes functions to read the BIOS Parameter Block (BPB), locate files, and read file data.

The implementation is designed for educational purposes and may not cover all aspects of the FAT12 file system.

usage: prog 0-n<folder> 0-1<file>

example: prog afolder anotherfolder readme.txt

BUILD WITH openwatcom v2
```
wcl -lr -mt prog.c
```
