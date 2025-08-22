#include "disk_min.c"
//#include "disk.c"

void main(int argc, char *argv[])
{
    struct disk_info_t disk_info = load_disk_info(DRIVE_A);
    if (disk_info.fat12_ptr == NULL) {
        return;
    }
    handleFile(&disk_info, argc, argv);
    unload_disk_info(&disk_info);

    return;
}

