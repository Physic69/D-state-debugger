// cvmfs_debug_rescue.c
// 
// Constructs an ELF core dump from a D-state process
// by reading /proc/<pid>/ interfaces directly.
// Does not require ptrace, signals, or process cooperation.
//
// Usage: cvmfs_debug_rescue <pid> <output.core>
// Then:  gdb /path/to/binary <output.core>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <elf.h>
#include <errno.h>
#include <stdint.h>

#define MAX_REGIONS 1024
#define MAX_THREADS 256
#define NOTE_ALIGN(sz) (((sz) + 3) & ~3)

// ============================================
// Data structures
// ============================================

typedef struct {
    unsigned long start;
    unsigned long end;
    unsigned long offset;
    int readable;
    int writable;
    int executable;
    char name[256];
} mem_region_t;

typedef struct {
    int tid;
    unsigned long regs[21]; // x86_64 user_regs_struct has 27 entries
                            // but we only populate what we can get
} thread_info_t;

// ============================================
// /proc parsers
// ============================================

int parse_maps(int pid, mem_region_t *regions) {
    char path[64];
    sprintf(path, "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f) { perror("Cannot read maps"); return -1; }

    int count = 0;
    char line[512];

    while (fgets(line, sizeof(line), f) && count < MAX_REGIONS) {
        unsigned long start, end, offset;
        char perms[5];
        int major, minor, inode;
        char name[256] = "";

        int n = sscanf(line, "%lx-%lx %4s %lx %x:%x %d %255[^\n]",
                       &start, &end, perms, &offset,
                       &major, &minor, &inode, name);

        regions[count].start = start;
        regions[count].end = end;
        regions[count].offset = offset;
        regions[count].readable = (perms[0] == 'r');
        regions[count].writable = (perms[1] == 'w');
        regions[count].executable = (perms[2] == 'x');

        // Trim leading whitespace from name
        char *p = name;
        while (*p == ' ') p++;
        strncpy(regions[count].name, p, 255);
        regions[count].name[255] = '\0';

        (void)n;
        count++;
    }

    fclose(f);
    return count;
}

int read_thread_registers(int pid, int tid, 
                          unsigned long *regs) {
    char path[128];
    sprintf(path, "/proc/%d/task/%d/syscall", pid, tid);
    FILE *f = fopen(path, "r");
    if (!f) return -1;

    char line[512];
    if (!fgets(line, sizeof(line), f)) { 
        fclose(f); 
        return -1; 
    }
    fclose(f);

    // Format: syscall_nr arg0 arg1 arg2 arg3 arg4 arg5 RSP RIP
    // arg0=RDI, arg1=RSI, arg2=RDX, arg3=R10, arg4=R8, arg5=R9
    unsigned long syscall_nr, a0, a1, a2, a3, a4, a5, rsp, rip;

    int n = sscanf(line, 
        "%ld 0x%lx 0x%lx 0x%lx 0x%lx 0x%lx 0x%lx 0x%lx 0x%lx",
        &syscall_nr, &a0, &a1, &a2, &a3, &a4, &a5, &rsp, &rip);

    if (n < 9) {
        // Fallback: try without 0x prefix
        char *tokens[10];
        int tn = 0;
        char linecopy[512];
        strncpy(linecopy, line, sizeof(linecopy));
        char *tok = strtok(linecopy, " \n");
        while (tok && tn < 10) { tokens[tn++] = tok; tok = strtok(NULL, " \n"); }

        if (tn >= 9) {
            syscall_nr = strtoul(tokens[0], NULL, 0);
            a0 = strtoul(tokens[1], NULL, 16);
            a1 = strtoul(tokens[2], NULL, 16);
            a2 = strtoul(tokens[3], NULL, 16);
            a3 = strtoul(tokens[4], NULL, 16);
            a4 = strtoul(tokens[5], NULL, 16);
            a5 = strtoul(tokens[6], NULL, 16);
            rsp = strtoul(tokens[7], NULL, 16);
            rip = strtoul(tokens[8], NULL, 16);
        } else {
            return -1;
        }
    }

    memset(regs, 0, 21 * sizeof(unsigned long));

    // x86_64 user_regs_struct layout:
    // [0]=R15 [1]=R14 [2]=R13 [3]=R12 [4]=RBP [5]=RBX
    // [6]=R11 [7]=R10 [8]=R9  [9]=R8  [10]=RAX [11]=RCX
    // [12]=RDX [13]=RSI [14]=RDI [15]=ORIG_RAX
    // [16]=RIP [17]=CS [18]=EFLAGS [19]=RSP [20]=SS

    regs[7]  = a3;          // R10
    regs[8]  = a5;          // R9
    regs[9]  = a4;          // R8
    regs[10] = syscall_nr;  // RAX
    regs[12] = a2;          // RDX
    regs[13] = a1;          // RSI
    regs[14] = a0;          // RDI
    regs[15] = syscall_nr;  // ORIG_RAX
    regs[16] = rip;         // RIP
    regs[17] = 0x33;        // CS (user mode)
    regs[19] = rsp;         // RSP
    regs[20] = 0x2b;        // SS (user mode)

    return 0;
}

int enumerate_threads(int pid, thread_info_t *threads) {
    char path[64];
    sprintf(path, "/proc/%d/task", pid);
    DIR *dir = opendir(path);
    if (!dir) return -1;

    int count = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) && count < MAX_THREADS) {
        if (entry->d_name[0] == '.') continue;

        threads[count].tid = atoi(entry->d_name);
        if (read_thread_registers(pid, threads[count].tid,
                                  threads[count].regs) == 0) {
            count++;
        }
    }
    closedir(dir);
    return count;
}

int read_auxv(int pid, char **data, size_t *sz) {
    char path[64];
    sprintf(path, "/proc/%d/auxv", pid);
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;

    *data = malloc(4096);
    *sz = 0;
    ssize_t n;
    while ((n = read(fd, (*data) + *sz, 4096 - *sz)) > 0) {
        *sz += n;
    }
    close(fd);
    return 0;
}

// ============================================
// Note writer
// ============================================

size_t write_note(FILE *out, uint32_t type,
                  const void *desc, size_t desc_sz) {
    Elf64_Nhdr nhdr;
    nhdr.n_namesz = 5;    // "CORE\0"
    nhdr.n_descsz = desc_sz;
    nhdr.n_type = type;

    char name_padded[8] = "CORE\0\0\0\0";
    // namesz=5, padded to 8 bytes (4-byte aligned)

    fwrite(&nhdr, sizeof(nhdr), 1, out);
    fwrite(name_padded, 8, 1, out);
    fwrite(desc, desc_sz, 1, out);

    size_t pad = NOTE_ALIGN(desc_sz) - desc_sz;
    if (pad > 0) {
        char zeros[4] = {0};
        fwrite(zeros, pad, 1, out);
    }

    return sizeof(nhdr) + 8 + NOTE_ALIGN(desc_sz);
}

// ============================================
// Core dump builder
// ============================================

int build_core(int pid, const char *output_path) {
    printf("=== cvmfs-debug-rescue ===\n");
    printf("Building core dump for PID %d\n\n", pid);

    // Parse memory regions
    mem_region_t regions[MAX_REGIONS];
    int num_regions = parse_maps(pid, regions);
    if (num_regions < 0) return -1;
    printf("Memory regions: %d\n", num_regions);

    // Enumerate threads and read registers
    thread_info_t threads[MAX_THREADS];
    int num_threads = enumerate_threads(pid, threads);
    if (num_threads <= 0) {
        fprintf(stderr, "No threads found\n");
        return -1;
    }
    printf("Threads: %d\n", num_threads);

    for (int i = 0; i < num_threads; i++) {
        printf("  Thread %d: RIP=0x%lx RSP=0x%lx\n",
               threads[i].tid,
               threads[i].regs[16],
               threads[i].regs[19]);
    }

    // Read auxiliary vector
    char *auxv_data = NULL;
    size_t auxv_sz = 0;
    read_auxv(pid, &auxv_data, &auxv_sz);

    // Open process memory
    char mem_path[64];
    sprintf(mem_path, "/proc/%d/mem", pid);
    int mem_fd = open(mem_path, O_RDONLY);
    if (mem_fd < 0) {
        perror("Cannot open process memory (try root)");
        return -1;
    }

    // Count loadable regions
    int loadable = 0;
    for (int i = 0; i < num_regions; i++) {
        if (regions[i].readable) loadable++;
    }

    // ---- Calculate note sizes ----

    // NT_PRSTATUS: one per thread (336 bytes = sizeof(elf_prstatus))
    size_t per_prstatus = sizeof(Elf64_Nhdr) + 8 + NOTE_ALIGN(336);
    size_t total_prstatus = per_prstatus * num_threads;

    // NT_PRPSINFO (136 bytes)
    size_t prpsinfo_note_sz = sizeof(Elf64_Nhdr) + 8 + NOTE_ALIGN(136);

    // NT_FILE
    uint64_t file_count = 0;
    size_t strings_len = 0;
    for (int i = 0; i < num_regions; i++) {
        if (regions[i].name[0] == '/') {
            file_count++;
            strings_len += strlen(regions[i].name) + 1;
        }
    }
    size_t file_desc_sz = 16 + (file_count * 24) + strings_len;
    size_t file_note_sz = sizeof(Elf64_Nhdr) + 8 + NOTE_ALIGN(file_desc_sz);

    // NT_AUXV
    size_t auxv_note_sz = 0;
    if (auxv_data) {
        auxv_note_sz = sizeof(Elf64_Nhdr) + 8 + NOTE_ALIGN(auxv_sz);
    }

    size_t all_notes_sz = total_prstatus + prpsinfo_note_sz
                        + file_note_sz + auxv_note_sz;

    // ---- Write core file ----

    FILE *core = fopen(output_path, "wb");
    if (!core) { perror("Cannot create output"); close(mem_fd); return -1; }

    // ELF header
    Elf64_Ehdr ehdr;
    memset(&ehdr, 0, sizeof(ehdr));
    memcpy(ehdr.e_ident, ELFMAG, SELFMAG);
    ehdr.e_ident[EI_CLASS] = ELFCLASS64;
    ehdr.e_ident[EI_DATA] = ELFDATA2LSB;
    ehdr.e_ident[EI_VERSION] = EV_CURRENT;
    ehdr.e_ident[EI_OSABI] = ELFOSABI_LINUX;
    ehdr.e_type = ET_CORE;
    ehdr.e_machine = EM_X86_64;
    ehdr.e_version = EV_CURRENT;
    ehdr.e_phoff = sizeof(Elf64_Ehdr);
    ehdr.e_ehsize = sizeof(Elf64_Ehdr);
    ehdr.e_phentsize = sizeof(Elf64_Phdr);
    ehdr.e_phnum = 1 + loadable;

    fwrite(&ehdr, sizeof(ehdr), 1, core);

    size_t phdr_total = ehdr.e_phnum * sizeof(Elf64_Phdr);
    size_t note_offset = sizeof(Elf64_Ehdr) + phdr_total;
    size_t data_offset = note_offset + all_notes_sz;

    // PT_NOTE program header
    Elf64_Phdr note_phdr = {0};
    note_phdr.p_type = PT_NOTE;
    note_phdr.p_offset = note_offset;
    note_phdr.p_filesz = all_notes_sz;
    fwrite(&note_phdr, sizeof(note_phdr), 1, core);

    // PT_LOAD program headers
    size_t current_offset = data_offset;
    for (int i = 0; i < num_regions; i++) {
        if (!regions[i].readable) continue;

        size_t seg_size = regions[i].end - regions[i].start;
        Elf64_Phdr phdr = {0};
        phdr.p_type = PT_LOAD;
        phdr.p_offset = current_offset;
        phdr.p_vaddr = regions[i].start;
        phdr.p_filesz = seg_size;
        phdr.p_memsz = seg_size;
        phdr.p_flags = PF_R;
        if (regions[i].writable) phdr.p_flags |= PF_W;
        if (regions[i].executable) phdr.p_flags |= PF_X;
        phdr.p_align = 4096;

        fwrite(&phdr, sizeof(phdr), 1, core);
        current_offset += seg_size;
    }

    // ---- Write notes ----

    // NT_PRSTATUS (one per thread)
    for (int i = 0; i < num_threads; i++) {
        unsigned char prstatus[336] = {0};

        // pr_pid at offset 32
        *(int *)(prstatus + 32) = threads[i].tid;

        // pr_reg at offset 112 (27 * 8 = 216 bytes of registers)
        memcpy(prstatus + 112, threads[i].regs, 
               21 * sizeof(unsigned long));

        write_note(core, 1 /* NT_PRSTATUS */, prstatus, 336);
    }

    // NT_PRPSINFO
    {
        unsigned char prpsinfo[136] = {0};
        prpsinfo[0] = 2;    // pr_state = TASK_UNINTERRUPTIBLE
        prpsinfo[1] = 'D';  // pr_sname

        // pr_pid at offset 24
        *(int *)(prpsinfo + 24) = pid;

        // pr_fname at offset 40 (16 bytes)
        char cmdline[80] = {0};
        char cmd_path[64];
        sprintf(cmd_path, "/proc/%d/cmdline", pid);
        int cmd_fd = open(cmd_path, O_RDONLY);
        if (cmd_fd >= 0) {
            ssize_t n = read(cmd_fd, cmdline, sizeof(cmdline) - 1);
            close(cmd_fd);
            if (n > 0) {
                // Replace null separators with spaces
                for (int j = 0; j < n - 1; j++) {
                    if (cmdline[j] == '\0') cmdline[j] = ' ';
                }
            }
        }

        // Extract just the binary name for pr_fname
        char *basename = strrchr(cmdline, '/');
        basename = basename ? basename + 1 : cmdline;
        char *space = strchr(basename, ' ');
        size_t namelen = space ? (size_t)(space - basename) : strlen(basename);
        if (namelen > 15) namelen = 15;
        memcpy(prpsinfo + 40, basename, namelen);

        // pr_psargs at offset 56 (80 bytes)
        strncpy((char *)(prpsinfo + 56), cmdline, 79);

        write_note(core, 3 /* NT_PRPSINFO */, prpsinfo, 136);
    }

    // NT_FILE
    {
        char *file_desc = calloc(1, file_desc_sz);
        uint64_t *hdr = (uint64_t *)file_desc;
        hdr[0] = file_count;
        hdr[1] = 4096;

        uint64_t *entries = &hdr[2];
        char *strings = (char *)&entries[file_count * 3];
        int idx = 0;
        char *sp = strings;

        for (int i = 0; i < num_regions; i++) {
            if (regions[i].name[0] != '/') continue;
            entries[idx * 3 + 0] = regions[i].start;
            entries[idx * 3 + 1] = regions[i].end;
            entries[idx * 3 + 2] = regions[i].offset / 4096;
            strcpy(sp, regions[i].name);
            sp += strlen(regions[i].name) + 1;
            idx++;
        }

        write_note(core, 0x46494c45 /* NT_FILE */, 
                   file_desc, file_desc_sz);
        free(file_desc);
    }

    // NT_AUXV
    if (auxv_data) {
        write_note(core, 6 /* NT_AUXV */, auxv_data, auxv_sz);
        free(auxv_data);
    }

    // ---- Write memory contents ----

    printf("\nDumping memory:\n");
    size_t total_dumped = 0;
    size_t total_zeroed = 0;

    for (int i = 0; i < num_regions; i++) {
        if (!regions[i].readable) continue;

        size_t seg_size = regions[i].end - regions[i].start;
        printf("  0x%lx-0x%lx %s ... ",
               regions[i].start, regions[i].end,
               regions[i].name[0] ? regions[i].name : "(anon)");

        char          buf[4096];
        unsigned long addr         = regions[i].start;
        size_t        rem          = seg_size;
        size_t        region_read  = 0;
        size_t        region_zero  = 0;

        while (rem > 0) {
            size_t chunk = rem > sizeof(buf) ? sizeof(buf) : rem;

            ssize_t n = pread(mem_fd, buf, chunk, (off_t)addr);

            if (n <= 0) {
                // Guard page or unmapped — zero this chunk only
                memset(buf, 0, chunk);
                fwrite(buf, chunk, 1, core);
                region_zero += chunk;
            } else {
                fwrite(buf, n, 1, core);
                if ((size_t)n < chunk) {
                    // Short read — pad remainder with zeros
                    size_t shortfall = chunk - n;
                    memset(buf, 0, shortfall);
                    fwrite(buf, shortfall, 1, core);
                    region_zero += shortfall;
                }
                region_read += n;
            }

            addr += chunk;
            rem  -= chunk;
        }

        total_dumped += region_read;
        total_zeroed += region_zero;

        if (region_zero > 0) {
            printf("partial (%zu read, %zu zeroed)\n",
                   region_read, region_zero);
        } else {
            printf("OK (%zu bytes)\n", region_read);
        }
    }

    fclose(core);
    close(mem_fd);

    printf("\n=== Summary ===\n");
    printf("Core dump: %s\n", output_path);
    printf("Threads:   %d\n", num_threads);
    printf("Regions:   %d (%d readable)\n", num_regions, loadable);
    printf("Memory:    %zu bytes dumped, %zu bytes zeroed\n",
           total_dumped, total_zeroed);
    printf("\nLoad with: gdb /path/to/binary %s\n", output_path);

    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, 
            "Usage: %s <pid> <output.core>\n\n"
            "Constructs an ELF core dump from a D-state process\n"
            "by reading /proc interfaces directly. No ptrace needed.\n",
            argv[0]);
        return 1;
    }

    return build_core(atoi(argv[1]), argv[2]);
}