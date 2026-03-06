// probe_proc.c — test what's readable for D-state processes
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <string.h>

int test_readable(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        printf("  ❌ %s: %s\n", path, strerror(errno));
        return 0;
    }
    
    char buf[256];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    
    if (n < 0) {
        printf("  ❌ %s: open OK but read failed: %s\n", 
               path, strerror(errno));
        return 0;
    }
    
    buf[n] = '\0';
    printf("  ✅ %s: readable (%zd bytes)\n", path, n);
    return 1;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pid>\n", argv[0]);
        return 1;
    }
    
    char path[512];
    int pid = atoi(argv[1]);
    
    printf("Probing /proc/%d/ for D-state process:\n\n", pid);
    
    // Test each standard proc file
    sprintf(path, "/proc/%d/status", pid);    test_readable(path);
    sprintf(path, "/proc/%d/maps", pid);      test_readable(path);
    sprintf(path, "/proc/%d/stack", pid);      test_readable(path);
    sprintf(path, "/proc/%d/wchan", pid);      test_readable(path);
    sprintf(path, "/proc/%d/syscall", pid);    test_readable(path);
    sprintf(path, "/proc/%d/stat", pid);       test_readable(path);
    sprintf(path, "/proc/%d/cmdline", pid);    test_readable(path);
    sprintf(path, "/proc/%d/environ", pid);    test_readable(path);
    
    // Test /proc/pid/mem — THE CRITICAL ONE
    printf("\n  Testing /proc/%d/mem:\n", pid);
    sprintf(path, "/proc/%d/mem", pid);
    int mem_fd = open(path, O_RDONLY);
    if (mem_fd < 0) {
        printf("  ❌ Can't open mem: %s\n", strerror(errno));
        printf("     TRY RUNNING AS ROOT\n");
    } else {
        // Try reading from the stack area
        // First get stack address from maps
        sprintf(path, "/proc/%d/maps", pid);
        FILE *maps = fopen(path, "r");
        char line[512];
        unsigned long stack_start = 0;
        
        if (maps) {
            while (fgets(line, sizeof(line), maps)) {
                if (strstr(line, "[stack]")) {
                    sscanf(line, "%lx-", &stack_start);
                    break;
                }
            }
            fclose(maps);
        }
        
        if (stack_start) {
            char buf[64];
            if (lseek(mem_fd, stack_start, SEEK_SET) != -1) {
                ssize_t n = read(mem_fd, buf, sizeof(buf));
                if (n > 0) {
                    printf("  ✅ /proc/%d/mem: READABLE! "
                           "Read %zd bytes from stack\n", pid, n);
                    printf("     THIS MEANS WE CAN BUILD "
                           "A CORE DUMP!\n");
                } else {
                    printf("  ❌ /proc/%d/mem: open OK but "
                           "read failed: %s\n", 
                           strerror(errno));
                }
            }
        } else {
            printf("  ❌ Could not find [stack] in maps\n");
        }
        close(mem_fd);
    }
    
    // Enumerate threads
    printf("\n  Threads (/proc/%d/task/):\n", pid);
    sprintf(path, "/proc/%d/task", pid);
    DIR *dir = opendir(path);
    if (dir) {
        struct dirent *entry;
        while ((entry = readdir(dir))) {
            if (entry->d_name[0] == '.') continue;
            
            printf("    Thread %s:\n", entry->d_name);
            
            sprintf(path, "/proc/%d/task/%s/stack", 
                    pid, entry->d_name);
            test_readable(path);
            
            sprintf(path, "/proc/%d/task/%s/syscall", 
                    pid, entry->d_name);
            test_readable(path);
        }
        closedir(dir);
    }
    
    return 0;
}