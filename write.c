//#include "disk_min.c"
#include "disk.c"

void main(int argc, char *argv[])
{
    struct file_info_t *file;
    struct disk_info_t disk_info = load_disk_info(DRIVE_A);
    uint8_t* buffer = malloc(1024);
    if (disk_info.fat12_ptr == NULL) {
        return;
    }
    memset(buffer, 65, 1024);
    buffer[1023] = '\0';
    strcpy(buffer, "Hello, FAT12!aaa");
    strcpy(buffer+1000, "end of file test");
    buffer[16] = 'A';

    create_file(&disk_info, "FT13    TXT", buffer);
    unload_disk_info(&disk_info);
    free(buffer);

    return;
}

