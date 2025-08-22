/**
 *  (mostly) same as disk.c but half the file size when compiled
 */

#include <i86.h>
#include <malloc.h>

typedef unsigned char uint8_t;
typedef unsigned int uint16_t;
typedef unsigned long uint32_t;

const uint32_t MAX_FAR_MALLOC_SIZE = 0xFFFF - 512;
const uint8_t DEFAULT_EXT[4] = "TXT";

const uint8_t DRIVE_A = 0;
const uint8_t DRIVE_B = 1;

const uint8_t DRIVE_ATTR_RESET = 1;
const uint8_t DRIVE_ATTR_NONE = 0;

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

void copy_mem(void* dest, void* src, size_t size)
{
    uint8_t *src_ptr = (uint8_t *)src;
    uint8_t *dest_ptr = (uint8_t *)dest;
    uint32_t i;
    for (i = 0; i < size; i++) {
        dest_ptr[i] = src_ptr[i];
    }
}

uint8_t str_n_compare(uint8_t *str1, uint8_t *str2, uint8_t strLim)
{
    uint8_t strIndex;
    for (strIndex = 0; strIndex < strLim; strIndex++) {
        if (str1[strIndex] != str2[strIndex]) {
            return 1;
        }
    }
    return 0;
}

uint8_t char2upper(uint8_t c)
{
    return c-" "[c<97|c>122];
}

void print_char(uint8_t c) {
    union REGS inregs,outregs;
    inregs.h.ah = 0x0e; // BIOS teletype
    inregs.h.bh = 0; // Page (0 default)
    inregs.h.al = c;
    int86(0x10, &inregs, &outregs);
}

void print_strn(char* message, uint32_t lim)
{
    uint32_t charIndex;

    for (charIndex = 0; message[charIndex] != '\0' && charIndex < lim; charIndex++) {
        if (message[charIndex] == '\n') {
            print_char('\r');
        }
        print_char(message[charIndex]);
    }
}
void print_str(char* message) {
    print_strn(message, 0xFFFF);
}
void reset_drive(uint8_t drive)
{
    union REGS inregs,outregs;
    inregs.h.ah = 0x00; // reset 
    inregs.h.dl = drive;
    int86(0x13, &inregs, &outregs);
}

void lba_chs(uint32_t lba, uint8_t SECTORS_PER_TRACK, uint8_t HEADS, uint16_t* cyl, uint16_t* head, uint16_t* sector)
{
    *cyl    = lba / (HEADS * SECTORS_PER_TRACK);
    *head   = ((lba % (HEADS * SECTORS_PER_TRACK)) / SECTORS_PER_TRACK);
    *sector = ((lba % (HEADS * SECTORS_PER_TRACK)) % SECTORS_PER_TRACK + 1);
}

void get_drive_params(uint8_t drive, uint8_t* sectors, uint8_t* heads)
{
    union REGS inregs,outregs;
    inregs.h.ah = 0x08; // Get drive parameters
    inregs.h.dl = drive;
    int86(0x13, &inregs, &outregs);
    *sectors = outregs.h.cl & 0x3f;
    *heads = outregs.h.dh + 1;
}

uint16_t adjust_segment_min_offset(struct SREGS *segregs, uint16_t data_address)
{
    segregs->es += data_address >> 4;
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

    inregs.h.ah = 0x02; // Read sectors
    inregs.h.al = size; // num of sectors
    inregs.h.ch = cyl;
    inregs.h.cl = sector;
    inregs.h.dh = head;
    inregs.h.dl = drive_number;
    inregs.x.bx = offset;

    int86x(0x13, &inregs, &outregs, &segregs);
}

// no padding for load purposes
_Packed struct param_block_t
{
    uint8_t jmp[3];
    uint8_t oem[8];
    uint16_t bytes_per_sector;
    uint8_t sectors_per_cluster;
    uint16_t reserved_sectors;
    uint8_t fat_count;
    uint16_t root_dir_entries;
    uint16_t total_sectors;
    uint8_t media_type;
    uint16_t fat_size;
    uint16_t sectors_per_track;
    uint16_t head_count;
    uint32_t hidden_sectors;
    uint32_t total_sectors_large;
    uint8_t drive_num;
    uint8_t flags_nt;
    uint8_t signature;
    uint32_t serial;
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
    return *(uint16_t *)(fat12_ptr + (cluster + (cluster / 2))) >> (cluster & 1) * 4 & 0xFFF;
}

char* int_to_dec_str(uint32_t value){
    static uint8_t buf[12];
    char *ptr = buf + sizeof(buf) - 1;

    *ptr = '\0';
    do {
        *(--ptr) = '0' + (value % 10);
        value /= 10;
    } while (value > 0);

    return ptr;
}

void print_dir(struct disk_info_t *disk_info)
{

    uint16_t dir_print_index, dirEntries = disk_info->current_dir_entries_max;
    struct dir_entry_t *dirToLookAt = disk_info->current_dir_ptr;
    uint16_t total_files = 0, total_dirs = 0;
    uint32_t total_bytes = 0;
    print_str("Serial:");
    print_str(int_to_dec_str(disk_info->param_block.serial));
    print_str(" Label: ");
    print_strn(disk_info->param_block.label, 11);
    print_str("\n\n");

    print_str("Name\tExt\tSize\tCreated\t\tAttr\n");
    for(dir_print_index = 0; dir_print_index < dirEntries; dir_print_index++)
    {
        if(dirToLookAt[dir_print_index].name[0] == 0 || dirToLookAt[dir_print_index].start_cluster == 0) continue; // skip empty entries
        print_strn(dirToLookAt[dir_print_index].name, 11);
        print_str("\t");
        print_str(int_to_dec_str(dirToLookAt[dir_print_index].file_size));
        print_str("\t");
        print_str(int_to_dec_str(1980 + ((dirToLookAt[dir_print_index].create_date >> 9) & 0x7F)));
        print_str("-");
        print_str(int_to_dec_str((dirToLookAt[dir_print_index].create_date >> 5) & 0xF));
        print_str("-");
        print_str(int_to_dec_str(dirToLookAt[dir_print_index].create_date & 0xF));
        print_str(" ");
        print_str(int_to_dec_str((dirToLookAt[dir_print_index].create_time>>11) & 0x1F));
        print_str(":");
        print_str(int_to_dec_str((dirToLookAt[dir_print_index].create_time>>5) & 0x3F));
        print_str("\t");
        print_str(dirToLookAt[dir_print_index].attr & FILE_DIRECTORY ? "DIR " : "");
        print_str(dirToLookAt[dir_print_index].attr & FILE_ARCHIVE ? "ARCHIVE " : "");
        print_str(dirToLookAt[dir_print_index].attr & FILE_HIDDEN ? "HIDDEN " : "");
        print_str(dirToLookAt[dir_print_index].attr & FILE_SYSTEM ? "SYSTEM " : "");
        print_str(dirToLookAt[dir_print_index].attr & FILE_VOLUME_ID ? "VOLUME_ID " : "");
        print_str(dirToLookAt[dir_print_index].attr & FILE_READ_ONLY ? "READ_ONLY " : "");
        print_str("\n");
        if (dirToLookAt[dir_print_index].attr & FILE_DIRECTORY) {
            total_dirs++;
        } else {
            total_files++;
        }
        total_bytes += dirToLookAt[dir_print_index].file_size;
    }

    print_str("\nFiles: ");
    print_str(int_to_dec_str(total_files));
    print_str(", size: ");
    print_str(int_to_dec_str(total_bytes));
    print_str(" bytes\n");
    print_str("Dirs: ");
    print_str(int_to_dec_str(total_dirs));
    print_str("\n");
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
    copy_mem(&file_info.root_entry, selectedFile, sizeof(struct dir_entry_t));


    // get size from fat
    currentCluster = selectedFile->start_cluster;
    while (currentCluster != 0xFFF && currentCluster != 0x000)
    {
        lbaTmp = disk_info->disk_params.start_of_data_sector + (currentCluster-disk_info->disk_params.FAT_CLUSTER_OFFSET) * disk_info->param_block.sectors_per_cluster;
        currentCluster = parse_fat12(disk_info->fat12_ptr, currentCluster);
        file_offset++;
    }

    file_info.malloc_size = file_offset * disk_info->param_block.sectors_per_cluster * disk_info->param_block.bytes_per_sector;
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
                print_str("Failed malloc");
                return file_info;
            }
        }

        file_info.data.far_data_list[segmentCount].far_data = _fmalloc(file_info.malloc_size % MAX_FAR_MALLOC_SIZE);
        file_info.data.far_data_list[segmentCount].data_size = file_info.malloc_size % MAX_FAR_MALLOC_SIZE;

        if (!file_info.data.far_data_list[segmentCount].far_data) {
            print_str("Failed malloc");
            return file_info;
        }
    }

    // Actually read the data
    file_offset = 0;
    currentCluster = selectedFile->start_cluster;
    while (currentCluster != 0xFFF && currentCluster != 0x000)
    {
        lbaTmp = disk_info->disk_params.start_of_data_sector + (currentCluster-disk_info->disk_params.FAT_CLUSTER_OFFSET) * disk_info->param_block.sectors_per_cluster;
        
        dataTmp = (file_offset * disk_info->param_block.bytes_per_sector * disk_info->param_block.sectors_per_cluster);
        dataStruct.far_data_list[dataTmp / MAX_FAR_MALLOC_SIZE].far_data = (uint8_t __far *)file_info.data.far_data_list[dataTmp / MAX_FAR_MALLOC_SIZE].far_data+ dataTmp % MAX_FAR_MALLOC_SIZE;
        dataStruct.far_data_list[dataTmp / MAX_FAR_MALLOC_SIZE].data_size = file_info.data.far_data_list[dataTmp / MAX_FAR_MALLOC_SIZE].data_size;
        get_data_from_disk(lbaTmp, disk_info->param_block.sectors_per_cluster, dataStruct.far_data_list[dataTmp / MAX_FAR_MALLOC_SIZE].far_data, DRIVE_ATTR_NONE, disk_info->drive_number);
        currentCluster = parse_fat12(disk_info->fat12_ptr, currentCluster);
        file_offset++;
    }
    return file_info;
}

void print_file(struct file_info_t *file)
{
    uint32_t printIter = 0;
    print_str("\nFilename: ");
    print_strn(file->root_entry.name, 11);
    print_str("\nContent: \n");
    
    for (printIter = 0; printIter < file->root_entry.file_size; printIter++)
    {
        print_char(((uint8_t __far *)file->data.far_data_list[printIter / MAX_FAR_MALLOC_SIZE].far_data)[printIter % MAX_FAR_MALLOC_SIZE]);
    }
    print_str("\n");
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

    get_data_from_disk(disk_info->param_block.reserved_sectors, disk_info->disk_params.fat12_size_sectors/2, (uint8_t __far *)disk_info->fat12_ptr, DRIVE_ATTR_NONE, disk_info->drive_number);
}

struct dir_entry_t *select_file(struct disk_info_t *disk_info, uint8_t *filename)
{
    uint16_t dirEntryIndex, filenameCharIndex, extCharIndex;
    uint8_t filenameTmp[8] = "        ";
    uint8_t extTmp[3];
    copy_mem(extTmp, (char *)DEFAULT_EXT, 3);

    for (filenameCharIndex = 0; filenameCharIndex < 8; filenameCharIndex++)
    {
        if (filename[filenameCharIndex] == ' ' || filename[filenameCharIndex] == '\0') {
            break;
        }
        if(filename[filenameCharIndex] == '.') {
            filenameCharIndex++;
            for (extCharIndex=0; extCharIndex < 3; extCharIndex++)
            {
                if (filename[extCharIndex + filenameCharIndex] == ' ' || filename[extCharIndex + filenameCharIndex] == '\0') break;
                extTmp[extCharIndex] = char2upper(filename[extCharIndex + filenameCharIndex]);
            }
            break; 
        }
        filenameTmp[filenameCharIndex] = char2upper(filename[filenameCharIndex]);
    }


    for (dirEntryIndex = 0; dirEntryIndex < disk_info->current_dir_entries_max; dirEntryIndex++)
    {
        if (disk_info->current_dir_ptr[dirEntryIndex].name[0] == 0 || disk_info->current_dir_ptr[dirEntryIndex].start_cluster == 0) continue;

        if (
            str_n_compare(disk_info->current_dir_ptr[dirEntryIndex].name, filenameTmp, 8) == 0 &&
            (
                str_n_compare(disk_info->current_dir_ptr[dirEntryIndex].ext, extTmp, 3) == 0 ||
                (disk_info->current_dir_ptr[dirEntryIndex].attr & FILE_DIRECTORY)
            )
        ) {
            return &disk_info->current_dir_ptr[dirEntryIndex];
        }
    }
    return NULL;
}

uint8_t is_fat12(struct disk_info_t *disk_info)
{
    return str_n_compare(disk_info->param_block.fs_type, "FAT12", 5) == 0;
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
        print_str("Not FAT12");
        return disk_info;
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

uint8_t set_current_dir(struct disk_info_t *disk_info, struct file_info_t *file)
{
    if(file->data.data == NULL) {
        print_str("Dir in __FAR err");
        return 0;
    }
    disk_info->current_dir_ptr = (struct dir_entry_t *) file->data.data; // we just hope its not in far memory :D
    disk_info->current_dir_entries_max = file->malloc_size / sizeof(struct dir_entry_t);
    return 1;
}

void handle_file(struct disk_info_t *disk_info, int argc, char *argv[])
{
    struct file_info_t file;
    struct dir_entry_t *selectedFile;
    if(argc>1) {
        selectedFile = select_file(disk_info, argv[1]);
        if (selectedFile != NULL){
            file = load_file(disk_info, selectedFile);
            if(file.data.far_data_list[file.malloc_size/MAX_FAR_MALLOC_SIZE].far_data == NULL) {
                print_str("FLoad ERR\n");
                return;
            }
            if(is_dir(selectedFile)){
                if (!set_current_dir(disk_info, &file)){
                    return;
                }
                handle_file(disk_info, argc - 1, argv + 1);
            } else {
                print_file(&file);
            }
            unload_file(&file);
        } else {
            print_str("File not found.\n");
        }
    } else {
        print_dir(disk_info);
    }
}
