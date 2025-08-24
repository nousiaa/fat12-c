#include "disk.c"

void main(int argc, char *argv[])
{
    struct file_info_t fileDir;
    struct disk_info_t disk_info = load_disk_info(DRIVE_A);
    struct dir_entry_t *selectedFile = NULL;
    uint8_t* buffer = malloc(1024);

    // TO write in a directory
    //selectedFile = select_file(&disk_info, "DIRNAME");
    //fileDir = load_file(&disk_info, selectedFile);
    //set_current_dir(&disk_info, &fileDir);

    memset(buffer, 65, 1024);
    buffer[1023] = '\0';
    strcpy(buffer, "Hello, FAT12!aaa");
    strcpy(buffer+1000, "end of file test");
    buffer[16] = 'A';

    create_file(&disk_info, "FT13    TXT", buffer);
    //unload_file(&fileDir);
    unload_disk_info(&disk_info);
    free(buffer);

    return;
}

