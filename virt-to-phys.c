// XXX: Taken from https://stackoverflow.com/a/45128487

#define _XOPEN_SOURCE 700
#include <fcntl.h> /* open */
#include <stdint.h> /* uint64_t  */
#include <stdio.h> /* printf */
#include <stdlib.h> /* size_t */
#include <unistd.h> /* pread, sysconf */

typedef struct {
    uint64_t pfn : 55;
    unsigned int soft_dirty : 1;
    unsigned int file_page : 1;
    unsigned int swapped : 1;
    unsigned int present : 1;
} PagemapEntry;

/* Parse the pagemap entry for the given virtual address.
 *
 * @param[out] entry      the parsed entry
 * @param[in]  pagemap_fd file descriptor to an open /proc/pid/pagemap file
 * @param[in]  vaddr      virtual address to get entry for
 * @return 0 for success, 1 for failure
 */
int pagemap_get_entry(PagemapEntry *entry, int pagemap_fd, uintptr_t vaddr)
{
    size_t nread;
    ssize_t ret;
    uint64_t data;
    uintptr_t vpn;

    vpn = vaddr / sysconf(_SC_PAGE_SIZE);
    nread = 0;
    while (nread < sizeof(data)) {
        ret = pread(pagemap_fd, ((uint8_t*)&data) + nread, sizeof(data) - nread,
                vpn * sizeof(data) + nread);
        nread += ret;
        if (ret <= 0) {
            return 1;
        }
    }
    entry->pfn = data & (((uint64_t)1 << 55) - 1);
    entry->soft_dirty = (data >> 55) & 1;
    entry->file_page = (data >> 61) & 1;
    entry->swapped = (data >> 62) & 1;
    entry->present = (data >> 63) & 1;
    return 0;
}

/* Convert the given virtual address to physical using /proc/PID/pagemap.
 *
 * @param[name] name of variable
 * @param[in] vaddr virtual address to get entry for
 * @return paddr (physical address) on success, exit on failure
 */
int virt_to_phys_user(char* name, uintptr_t vaddr)
{
    char pagemap_file[BUFSIZ];
    int pagemap_fd;

    snprintf(pagemap_file, sizeof(pagemap_file), "/proc/%ju/pagemap", (uintmax_t)getpid());
    pagemap_fd = open(pagemap_file, O_RDONLY);
    if (pagemap_fd < 0) {
        printf("Failed to open pagemap for process!");
        exit(-1);
    }
    PagemapEntry entry;
    if (pagemap_get_entry(&entry, pagemap_fd, vaddr)) {
        printf("Failed to get entry for pagemap!");
        exit(-1);
    }
    close(pagemap_fd);
    
    uintptr_t paddr = (entry.pfn * sysconf(_SC_PAGE_SIZE)) + (vaddr % sysconf(_SC_PAGE_SIZE));
    printf("%s: virt @ %p, phys @ %p\n", name, (void *)vaddr, (void*)paddr);
    return paddr;
}
