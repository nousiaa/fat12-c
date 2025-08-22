/**
 *  BASIC READ-ONLY FAT12 FILE SYSTEM IMPLEMENTATION
 *  This implementation provides basic functionality to read files from a FAT12 file system.
 *  It includes functions to read the BIOS Parameter Block (BPB), locate files, and read file data.
 *  The implementation is designed for educational purposes and may not cover all aspects of the FAT12 file system.
 *  usage: prog 0-n<folder> 0-1<file>
 *  example: prog afolder anotherfolder readme.txt
 * 
 *  BUILD WITH openwatcom v2 - "wcl -lr -mt prog.c"
 *  NOTE: compiling with tiny memory mode fails when allocating memory for file data where data+code>64K
 *  NOTE2: did some far pointer fuckery to allow more memory to be allocated for file data
 */

#include <i86.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>

const uint32_t MAX_FAR_MALLOC_SIZE = 0xFFFF - 512;

// Debugging flag
const uint8_t DEBUG = 0;

// Default file extension
const uint8_t DEFAULT_EXT[4] = "TXT";

// Consts for drive numbers
const uint8_t DRIVE_A = 0;
const uint8_t DRIVE_B = 1;

// Custom drive attributes
const uint8_t DRIVE_ATTR_RESET = 1;
const uint8_t DRIVE_ATTR_NONE = 0;

// File attributes
const uint8_t FILE_READ_ONLY = 0x01;
const uint8_t FILE_HIDDEN = 0x02;
const uint8_t FILE_SYSTEM = 0x04;
const uint8_t FILE_VOLUME_ID = 0x08;
const uint8_t FILE_DIRECTORY = 0x10;
const uint8_t FILE_ARCHIVE = 0x20;

struct far_data_list_t
{
    void __far *far_data;
    uint16_t data_size;
};

struct data_target_t
{
    struct far_data_list_t far_data_list[10]; // YES, limited, but should be enough for most cases
    void *data;
};

uint8_t char2upper(uint8_t c)
{
    if (c >= 'a' && c <= 'z') {
        return c - 32;
    }
    return c;
}

void print_str(char* message)
{
    union REGS inregs,outregs;
    uint32_t charIndex;
    inregs.h.ah = 0x0e; // BIOS teletype output function
    inregs.h.bh = 0; // Page number (0 for default)
    for (charIndex = 0; message[charIndex] != '\0'; charIndex++) {
        inregs.h.al = message[charIndex]; // Character to print
        int86(0x10, &inregs, &outregs);
    }
}

void reset_drive(uint8_t drive)
{
    union REGS inregs,outregs;
    inregs.h.ah = 0x00; // BIOS reset function
    inregs.h.dl = drive;
    int86(0x13, &inregs, &outregs);
}

/* Convert LBA (Logical Block Addressing) to CHS (Cylinder-Head-Sector) */
void lba_chs(uint32_t lba, uint8_t SECTORS_PER_TRACK, uint8_t HEADS, uint16_t* cyl, uint16_t* head, uint16_t* sector)
{
    *cyl    = lba / (HEADS * SECTORS_PER_TRACK);
    *head   = ((lba % (HEADS * SECTORS_PER_TRACK)) / SECTORS_PER_TRACK);
    *sector = ((lba % (HEADS * SECTORS_PER_TRACK)) % SECTORS_PER_TRACK + 1);
}

void get_drive_params(uint8_t drive, uint8_t* sectors, uint8_t* heads)
{
    union REGS inregs,outregs;
    inregs.h.ah = 0x08; // BIOS get drive parameters function
    inregs.h.dl = drive;
    int86(0x13, &inregs, &outregs);
    *sectors = outregs.h.cl & 0x3f;
    *heads = outregs.h.dh + 1;

    if (DEBUG) {
        printf("Drive parameters:\n");
        printf("Sectors: %d\n", *sectors);
        printf("Heads: %d\n", *heads);
    }
}

// Adjust segment and return minimum possible offset to avoid any boundary issues
uint16_t adjust_segment_min_offset(struct SREGS *segregs, uint16_t data_address)
{
    segregs->es += data_address >> 4;
    if(DEBUG) printf("Adjusted segment by : %x, Offset now: %x, was %x\n", segregs->es-segregs->ds, data_address & 0xF, data_address);
    return data_address & 0xF;
}

void get_data_from_disk(uint32_t lba, uint8_t size, void __far *data, uint8_t attributes, uint8_t drive_number)
{
    uint16_t offset;
    union REGS inregs,outregs;
    struct SREGS segregs;
    uint16_t cyl, head, sector;
    uint8_t sectors_count, heads_count;
    if(attributes & DRIVE_ATTR_RESET) reset_drive(drive_number);
    get_drive_params(drive_number, &sectors_count, &heads_count);

    lba_chs(lba, sectors_count, heads_count, &cyl, &head, &sector);
    segread( &segregs );
    offset = FP_OFF(data);
    segregs.es = FP_SEG(data);
    offset = adjust_segment_min_offset(&segregs, offset);
    if (DEBUG) {
        printf("LBA: %u\n", lba);
        printf("Drive: %d\n", drive_number);
        printf("Sectors to read: %x\n", size);
        printf("Cylinder: %d, Head: %d, Sector: %d\n", cyl, head, sector);
        printf("Segment: %x, Offset: %x\n", segregs.es, offset);
        printf("DS: %p, ES: %p, SS: %p, CS: %p\n", segregs.ds, segregs.es, segregs.ss, segregs.cs);
    }

    inregs.h.ah = 0x02; // BIOS read sector function
    inregs.h.al = size; // Number of sectors to read
    inregs.h.ch = cyl;
    inregs.h.cl = sector;
    inregs.h.dh = head;
    inregs.h.dl = drive_number;
    inregs.x.bx = offset;
    if (DEBUG) {
        printf("READ\n ES-BX %x %x \n", segregs.es, inregs.x.bx);
    }
    int86x(0x13, &inregs, &outregs, &segregs);
    if (DEBUG) {
        printf("READ DONE\n");
    }
}

// Structure for the BIOS Parameter Block (BPB)
// no padding for load purposes
_Packed struct param_block_t
{
    uint8_t jmp[3]; // Jump instruction to boot code
    uint8_t oem[8];
    uint16_t bytes_per_sector; //2b
    uint8_t sectors_per_cluster; //1b
    uint16_t reserved_sectors; //2b
    uint8_t fat_count; //1b
    uint16_t root_dir_entries; //2b
    uint16_t total_sectors; //2b
    uint8_t media_type; //1b
    uint16_t fat_size; //2b
    uint16_t sectors_per_track; //2b
    uint16_t head_count; //2b
    uint32_t hidden_sectors; //4b
    uint32_t total_sectors_large; //4b
    uint8_t drive_num;
    uint8_t flags_nt;
    uint8_t signature;
    uint32_t serial; //4b
    uint8_t label[11];
    uint8_t fs_type[8];
    uint8_t bootcode[448];
    uint16_t boot_part_signature;
};

_Packed struct dir_entry_t
{
    uint8_t name[8];
    uint8_t ext[3];
    uint8_t attr;
    uint8_t nt;
    uint8_t create_time_tenth;
    uint16_t create_time;
    uint16_t create_date;
    uint16_t last_access_date;
    uint16_t first_cluster_high;
    uint16_t time;
    uint16_t date;
    uint16_t start_cluster;
    uint32_t file_size;
};

struct disk_params_t
{
    uint16_t fat12_size_sectors;
    uint16_t start_of_root_dir;
    uint16_t root_dir_size;
    uint16_t root_dir_sectors;
    uint16_t start_of_data_sector;
    uint16_t fat12_size_bytes;
    uint16_t FAT_CLUSTER_OFFSET;
};

struct disk_info_t
{
    uint8_t *fat12_ptr;
    struct dir_entry_t *root_dir_ptr;
    struct dir_entry_t *current_dir_ptr;
    uint32_t current_dir_entries_max;
    struct disk_params_t disk_params;
    struct param_block_t param_block;
    uint8_t drive_number;
};

struct file_info_t
{
    struct data_target_t data;
    uint32_t malloc_size;
    struct dir_entry_t root_entry;
};

uint16_t parse_fat12(uint8_t *fat12_ptr, uint16_t cluster)
{
    uint32_t fat_entry = *(uint32_t *)(fat12_ptr + (cluster + (cluster / 2)));
    if (cluster & 1) fat_entry >>= 4;
    fat_entry &= 0xFFF;

    return fat_entry;
}

void print_dir(struct disk_info_t *disk_info)
{
    uint16_t dir_print_index, dirEntries = disk_info->current_dir_entries_max;
    struct dir_entry_t *dirToLookAt = disk_info->current_dir_ptr;
    uint16_t total_files = 0, total_dirs = 0;
    uint32_t total_bytes = 0;
    if(DEBUG) {
        printf("Number of entries: %d\n", dirEntries);
    }
    printf("Directory listing:\n");
    printf("Serial: %lu Label: %.11s\n\n", disk_info->param_block.serial, disk_info->param_block.label);

    printf("Name\tExt\tSize\tCreated\t\t\tAttributes\n");
    for(dir_print_index = 0; dir_print_index < dirEntries; dir_print_index++)
    {
        if(dirToLookAt[dir_print_index].name[0] == 0 || dirToLookAt[dir_print_index].start_cluster == 0) continue; // skip empty entries
        if(DEBUG) {
            printf("D: cluster %p\n", dirToLookAt[dir_print_index].start_cluster);
        }
        printf(
            "%.8s%.3s\t%lu\t%04d-%02d-%02d %02d:%02d\t%s%s%s%s%s%s\n",
            dirToLookAt[dir_print_index].name,
            dirToLookAt[dir_print_index].ext,
            dirToLookAt[dir_print_index].file_size,
            1980 + ((dirToLookAt[dir_print_index].create_date >> 9) & 0x7F),
            (dirToLookAt[dir_print_index].create_date >> 5) & 0xF,
            dirToLookAt[dir_print_index].create_date & 0xF,
            (dirToLookAt[dir_print_index].create_time>>11) & 0x1F,
            (dirToLookAt[dir_print_index].create_time>>5) & 0x3F,
            (dirToLookAt[dir_print_index].attr & FILE_DIRECTORY ? "DIR " : ""),
            (dirToLookAt[dir_print_index].attr & FILE_ARCHIVE ? "ARCHIVE " : ""),
            (dirToLookAt[dir_print_index].attr & FILE_HIDDEN ? "HIDDEN " : ""),
            (dirToLookAt[dir_print_index].attr & FILE_SYSTEM ? "SYSTEM " : ""),
            (dirToLookAt[dir_print_index].attr & FILE_VOLUME_ID ? "VOLUME_ID " : ""),
            (dirToLookAt[dir_print_index].attr & FILE_READ_ONLY ? "READ_ONLY " : "")
        );
        if (dirToLookAt[dir_print_index].attr & FILE_DIRECTORY) {
            total_dirs++;
        } else {
            total_files++;
        }
        total_bytes += dirToLookAt[dir_print_index].file_size;
    }
    printf("\nFiles: %d, total size: %lu bytes\n", total_files, total_bytes);
    printf("Dirs: %d\n", total_dirs);
}

struct data_target_t  init_datastruct() {
    struct data_target_t dataStruct;
    uint8_t i;
    dataStruct.data = NULL;
    for(i=0; i<10; i++) {
        dataStruct.far_data_list[i].far_data = NULL;
        dataStruct.far_data_list[i].data_size = 0;
    }
    return dataStruct;
}

struct file_info_t load_file(struct disk_info_t *disk_info, struct dir_entry_t *selectedFile)
{
    struct file_info_t file_info;
    uint32_t currentCluster = 0, file_offset = 0;
    uint32_t lbaTmp;
    uint32_t dataTmp;
    uint32_t segmentCount = 0, lastSegmentSize = 0;
    struct data_target_t dataStruct = init_datastruct();
    file_info.data = init_datastruct();
    dataStruct.data = NULL;
    memcpy(&file_info.root_entry, selectedFile, sizeof(struct dir_entry_t));


    // get size from fat as we cant trust size in root entry for directory entries
    currentCluster = selectedFile->start_cluster;
    while (currentCluster != 0xFFF && currentCluster != 0x000)
    {
        lbaTmp = disk_info->disk_params.start_of_data_sector + (currentCluster-disk_info->disk_params.FAT_CLUSTER_OFFSET) * disk_info->param_block.sectors_per_cluster;
        currentCluster = parse_fat12(disk_info->fat12_ptr, currentCluster);
        file_offset++;
    }

    file_info.malloc_size = file_offset * disk_info->param_block.sectors_per_cluster * disk_info->param_block.bytes_per_sector;

    if(DEBUG){
        printf("would malloc %lu bytes\n", file_info.malloc_size);
        printf("needs to be split in %lu parts\n",(file_info.malloc_size/MAX_FAR_MALLOC_SIZE)+1);
        printf("with last part %lu bytes\n", file_info.malloc_size % MAX_FAR_MALLOC_SIZE);
    }

    if(file_info.malloc_size < MAX_FAR_MALLOC_SIZE) {
        file_info.data.data = malloc(file_info.malloc_size); 
        file_info.data.far_data_list[0].far_data = (uint8_t __far *)file_info.data.data;
        file_info.data.far_data_list[0].data_size = file_info.malloc_size;
    }
    if (!file_info.data.data) {
        for(segmentCount = 0; segmentCount < (file_info.malloc_size/MAX_FAR_MALLOC_SIZE); segmentCount++) {
            file_info.data.far_data_list[segmentCount].far_data = _fmalloc(MAX_FAR_MALLOC_SIZE);
            file_info.data.far_data_list[segmentCount].data_size = MAX_FAR_MALLOC_SIZE;
            if (!file_info.data.far_data_list[segmentCount].far_data) {
                perror("Failed to allocate memory for file data");
                exit(EXIT_FAILURE);
            }
        }

        file_info.data.far_data_list[segmentCount].far_data = _fmalloc(file_info.malloc_size % MAX_FAR_MALLOC_SIZE);
        file_info.data.far_data_list[segmentCount].data_size = file_info.malloc_size % MAX_FAR_MALLOC_SIZE;

        if (!file_info.data.far_data_list[segmentCount].far_data) {
            perror("Failed to allocate memory for file data");
            exit(EXIT_FAILURE);
        }
        if (DEBUG) {
            printf("Using far memory allocation\n");
        }
    } else {
        if (DEBUG) {
            printf("Using near memory allocation\n");
        }
    }
    if(DEBUG)
        printf("Allocated memory for file data: %lu bytes\n", file_info.malloc_size);
    // then actually read the data
    file_offset = 0;
    currentCluster = selectedFile->start_cluster;
    while (currentCluster != 0xFFF && currentCluster != 0x000)
    {
        if (DEBUG) {
            printf("cluster %x would read at %x\n", currentCluster, disk_info->disk_params.start_of_data_sector + (currentCluster-disk_info->disk_params.FAT_CLUSTER_OFFSET) * disk_info->param_block.sectors_per_cluster);
        }
        lbaTmp = disk_info->disk_params.start_of_data_sector + (currentCluster-disk_info->disk_params.FAT_CLUSTER_OFFSET) * disk_info->param_block.sectors_per_cluster;
        
        dataTmp = (file_offset * disk_info->param_block.bytes_per_sector * disk_info->param_block.sectors_per_cluster);

        dataStruct.far_data_list[dataTmp / MAX_FAR_MALLOC_SIZE].far_data = (uint8_t __far *)file_info.data.far_data_list[dataTmp / MAX_FAR_MALLOC_SIZE].far_data+ dataTmp % MAX_FAR_MALLOC_SIZE;
        dataStruct.far_data_list[dataTmp / MAX_FAR_MALLOC_SIZE].data_size = file_info.data.far_data_list[dataTmp / MAX_FAR_MALLOC_SIZE].data_size;

        get_data_from_disk(lbaTmp, disk_info->param_block.sectors_per_cluster, dataStruct.far_data_list[dataTmp / MAX_FAR_MALLOC_SIZE].far_data, DRIVE_ATTR_NONE, disk_info->drive_number);
        currentCluster = parse_fat12(disk_info->fat12_ptr, currentCluster);
        file_offset++;
    }
    if (DEBUG) {
        printf("chain processed, clusters: %d file loaded at: %p\n", file_offset, file_info.data);
    }
    return file_info;
}

void print_file(struct file_info_t *file)
{
    uint32_t printIter = 0;
    printf("\nFile name: %.11s\n", file->root_entry.name);
    printf("File content: \n");
    for (printIter = 0; printIter < file->root_entry.file_size; printIter++)
    {
        printf("%c",((uint8_t __far *)file->data.far_data_list[printIter / MAX_FAR_MALLOC_SIZE].far_data)[printIter % MAX_FAR_MALLOC_SIZE]);
    }
    printf("\n");
}

void init_disk_params(struct disk_info_t *disk_info)
{
    disk_info->disk_params.fat12_size_sectors = disk_info->param_block.fat_size * disk_info->param_block.fat_count; // should be used but we are cheap and only use fat #1
    disk_info->disk_params.start_of_root_dir = disk_info->param_block.reserved_sectors + disk_info->disk_params.fat12_size_sectors;
    disk_info->disk_params.root_dir_size = disk_info->param_block.root_dir_entries * sizeof(struct dir_entry_t);
    disk_info->disk_params.root_dir_sectors = disk_info->disk_params.root_dir_size / disk_info->param_block.bytes_per_sector; // is this off by one?
    disk_info->disk_params.start_of_data_sector = disk_info->disk_params.start_of_root_dir + disk_info->disk_params.root_dir_sectors;
    disk_info->disk_params.fat12_size_bytes = disk_info->disk_params.fat12_size_sectors * disk_info->param_block.bytes_per_sector;
    disk_info->disk_params.FAT_CLUSTER_OFFSET = 2;
}

void load_bios_param_block(struct disk_info_t *disk_info)
{
    get_data_from_disk(0, 1, (uint8_t __far *)&disk_info->param_block, DRIVE_ATTR_RESET, disk_info->drive_number);
}

void load_root_dir(struct disk_info_t *disk_info)
{
    disk_info->root_dir_ptr = malloc(disk_info->disk_params.root_dir_size);
    disk_info->current_dir_ptr = disk_info->root_dir_ptr; // Set root as current directory
    disk_info->current_dir_entries_max = disk_info->param_block.root_dir_entries;
    get_data_from_disk(disk_info->disk_params.start_of_root_dir, disk_info->disk_params.root_dir_sectors, (uint8_t __far *)disk_info->root_dir_ptr, DRIVE_ATTR_NONE, disk_info->drive_number);
}

void load_fat12(struct disk_info_t *disk_info)
{
    disk_info->fat12_ptr = malloc(disk_info->disk_params.fat12_size_bytes/2);
    if (DEBUG) {
        printf("FAT12 size: %d bytes sectors %d\n", disk_info->disk_params.fat12_size_bytes, disk_info->disk_params.fat12_size_sectors);
    }
    get_data_from_disk(disk_info->param_block.reserved_sectors, disk_info->disk_params.fat12_size_sectors/2, (uint8_t __far *)disk_info->fat12_ptr, DRIVE_ATTR_NONE, disk_info->drive_number);
}

struct dir_entry_t *select_file(struct disk_info_t *disk_info, uint8_t *filename)
{
    uint16_t dirEntryIndex, filenameCharIndex, extCharIndex;
    uint8_t foundExt = 0;
    uint8_t filenameTmp[8] = "        ";
    uint8_t extTmp[3];
    memcpy(extTmp, DEFAULT_EXT, 3);

    for (filenameCharIndex = 0; filenameCharIndex < 8; filenameCharIndex++)
    {
        if (filename[filenameCharIndex] == ' ' || filename[filenameCharIndex] == '\0') {
            break;
        }
        if(filename[filenameCharIndex] == '.') {
            foundExt = 1;
            filenameCharIndex++;
            break; 
        }
        filenameTmp[filenameCharIndex] = char2upper(filename[filenameCharIndex]);
    }
    if(foundExt){

        for (extCharIndex=0; extCharIndex < 3; extCharIndex++)
        {
            if (filename[extCharIndex + filenameCharIndex] == ' ' || filename[extCharIndex + filenameCharIndex] == '\0') break;
            extTmp[extCharIndex] = char2upper(filename[extCharIndex + filenameCharIndex]);
        }
    }


    for (dirEntryIndex = 0; dirEntryIndex < disk_info->current_dir_entries_max; dirEntryIndex++)
    {
        if (disk_info->current_dir_ptr[dirEntryIndex].name[0] == 0 || disk_info->current_dir_ptr[dirEntryIndex].start_cluster == 0) continue;
        if (DEBUG) {
            printf("Checking file: %.8s.%.3s\n", disk_info->current_dir_ptr[dirEntryIndex].name, disk_info->current_dir_ptr[dirEntryIndex].ext);
            printf("Attributes: %s\n", (disk_info->current_dir_ptr[dirEntryIndex].attr & FILE_DIRECTORY) ? "Directory" : "File");
        }
        if (
            strncmp(disk_info->current_dir_ptr[dirEntryIndex].name, filenameTmp, 8) == 0 &&
            (
                strncmp(disk_info->current_dir_ptr[dirEntryIndex].ext, extTmp, 3) == 0 ||
                (disk_info->current_dir_ptr[dirEntryIndex].attr & FILE_DIRECTORY)
            )
        ) {
            if (DEBUG) {
                printf("Found file!\n");
            }
            return &disk_info->current_dir_ptr[dirEntryIndex];
        }
    }
    if (DEBUG) {
        printf("File not found.\n");
    }
    return NULL;
}


uint8_t is_fat12(struct disk_info_t *disk_info)
{
    return strncmp(disk_info->param_block.fs_type, "FAT12", 5) == 0;
}

struct disk_info_t load_disk_info(uint8_t drive_number)
{
    struct disk_info_t disk_info;
    disk_info.drive_number = drive_number;
    load_bios_param_block(&disk_info);
    init_disk_params(&disk_info);
    disk_info.fat12_ptr = NULL;
    disk_info.root_dir_ptr = NULL;
    if(!is_fat12(&disk_info)) {
        perror("Not a FAT12 filesystem.");
        exit(EXIT_FAILURE);
    }
    load_fat12(&disk_info);
    load_root_dir(&disk_info);

    return disk_info;
}

void unload_disk_info(struct disk_info_t *disk_info)
{
    free(disk_info->fat12_ptr);
    free(disk_info->root_dir_ptr);
    disk_info->fat12_ptr = NULL;
    disk_info->root_dir_ptr = NULL;
    disk_info->current_dir_ptr = NULL;
    disk_info->current_dir_entries_max = 0;
}

void unload_file(struct file_info_t *file)
{
    uint8_t far_data_index;
    if (file->data.data != NULL) {
        free(file->data.data);
        file->data.far_data_list[0].far_data = NULL;
        file->data.far_data_list[0].data_size = 0;
    }
    for(far_data_index=0; far_data_index<10; far_data_index++) {
        if (file->data.far_data_list[far_data_index].far_data != NULL) {
            _ffree(file->data.far_data_list[far_data_index].far_data);
            file->data.far_data_list[far_data_index].far_data = NULL;
        }
        file->data.far_data_list[far_data_index].data_size = 0;
    }
    file->data.data = NULL;
}

uint8_t is_dir(struct dir_entry_t *entry)
{
    return (entry->attr & FILE_DIRECTORY) != 0;
}

void set_current_dir(struct disk_info_t *disk_info, struct file_info_t *file)
{
    if(file->data.data == NULL) {
        perror("Directory loaded to far memory, not implemented");
        exit(EXIT_FAILURE);
    }
    disk_info->current_dir_ptr = (struct dir_entry_t *) file->data.data; // we just hope its not in far memory :D
    disk_info->current_dir_entries_max = file->malloc_size / sizeof(struct dir_entry_t);
}

void handle_file(struct disk_info_t *disk_info, int argc, char *argv[])
{
    struct file_info_t file;
    struct dir_entry_t *selectedFile;
    if(argc>1) {
        selectedFile = select_file(disk_info, argv[1]);
        if (selectedFile != NULL){
            file = load_file(disk_info, selectedFile);
            if(is_dir(selectedFile)){
                set_current_dir(disk_info, &file);
                handle_file(disk_info, argc - 1, argv + 1);
            } else {
                print_file(&file);
            }
            unload_file(&file);
        } else {
            printf("File not found.\n");
        }
    } else {
        print_dir(disk_info);
    }

}
