// cvmfs_debug_rescue.c
//
// Constructs an ELF core dump from a D-state process
// by reading /proc/<pid>/ interfaces directly.
// Does not require ptrace, signals, or process cooperation.
//
// Tested: Linux 6.13, x86_64, kernel 6.x /proc security model
// Requires: root (kernel 6.x tightened /proc/pid/syscall access)
//
// Usage:
//   cvmfs_debug_rescue [OPTIONS] <pid> <output.core>
//   gdb /path/to/binary <output.core>
//
// Options:
//   --minimal    dump only writable/anonymous regions (smallest)
//   --standard   skip read-only file-backed regions (default)
//   --full       dump everything readable


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <elf.h>
#include <errno.h>
#include <stdint.h>
#include <sys/types.h>

#define NOTE_ALIGN(sz) (((sz) + 3) & ~3)
#define PAGE_SIZE 4096UL

// ============================================================
// Hardcoded Architecture: x86_64
// ============================================================

#define X86_64_NGREG          27
#define X86_64_REG_RIP        16
#define X86_64_REG_RSP        19
#define X86_64_REG_RBP        4
#define X86_64_PRSTATUS_SIZE  336
#define X86_64_PRSTATUS_PID   32
#define X86_64_PRSTATUS_REG   112
#define X86_64_PRPSINFO_SIZE  136
#define X86_64_PRPSINFO_PID   24
#define X86_64_PRPSINFO_FNAME 40
#define X86_64_PRPSINFO_ARGS  56


// ============================================================
// Data structures
// ============================================================

typedef struct {
    unsigned long start;
    unsigned long end;
    unsigned long offset;   // file offset (from maps)
    int readable;
    int writable;
    int executable;
    char name[256];
} mem_region_t;

typedef struct {
    int tid;
    // 27 slots for x86_64 user_regs_struct
    // zero-initialized, unknown regs stay 0
    unsigned long regs[X86_64_NGREG];
} thread_info_t;

// ============================================================
// Region filter
// ============================================================

// The main executable path — set during parse_maps from the
// first file-backed region (which is the executable itself).
static char g_exe_path[256] = "";

static int should_dump_region(const mem_region_t *r) {
    if (!r->readable) return 0;

    // vvar and vvar_vclock are kernel-mapped, never readable
    // from userspace via /proc/pid/mem — always skip
    if (strstr(r->name, "[vvar]"))        return 0;
    if (strstr(r->name, "[vvar_vclock]")) return 0;
    if (strstr(r->name, "[vsyscall]"))    return 0;

    // DUMP_FULL: Dump everything readable
    return 1;
}

// ============================================================
// /proc parsers
// ============================================================

int parse_maps(int pid, mem_region_t **regions_out) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f) { perror("Cannot open maps"); return -1; }

    int cap = 256;
    int count = 0;
    mem_region_t *regions = malloc(cap * sizeof(mem_region_t));
    if (!regions) { fclose(f); return -1; }

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        if (count == cap) {
            cap *= 2;
            mem_region_t *tmp = realloc(regions,
                                        cap * sizeof(mem_region_t));
            if (!tmp) { free(regions); fclose(f); return -1; }
            regions = tmp;
        }

        unsigned long start, end, offset;
        char perms[5];
        unsigned int major, minor;
        unsigned long inode;
        char name[256] = "";

        // /proc/pid/maps format:
        // addr-addr perms offset major:minor inode [name]
        // major:minor are HEX (use %x not %d)
        sscanf(line, "%lx-%lx %4s %lx %x:%x %lu %255[^\n]",
               &start, &end, perms, &offset,
               &major, &minor, &inode, name);

        regions[count].start      = start;
        regions[count].end        = end;
        regions[count].offset     = offset;
        regions[count].readable   = (perms[0] == 'r');
        regions[count].writable   = (perms[1] == 'w');
        regions[count].executable = (perms[2] == 'x');

        // Trim leading whitespace from name field
        char *p = name;
        while (*p == ' ') p++;
        strncpy(regions[count].name, p, 255);
        regions[count].name[255] = '\0';

        // First file-backed region in maps is the main executable.
        // Save its path so should_dump_region() can always keep it.
        if (g_exe_path[0] == '\0' && p[0] == '/') {
            strncpy(g_exe_path, p, sizeof(g_exe_path) - 1);
            g_exe_path[sizeof(g_exe_path) - 1] = '\0';
        }

        count++;
    }

    fclose(f);
    *regions_out = regions;
    return count;
}

int read_thread_registers(int pid, int tid, unsigned long *regs) {
    char path[128];
    snprintf(path, sizeof(path),
             "/proc/%d/task/%d/syscall", pid, tid);

    FILE *f = fopen(path, "r");
    if (!f) return -1;

    char line[512];
    if (!fgets(line, sizeof(line), f)) {
        fclose(f);
        return -1;
    }
    fclose(f);

    // Detect non-blocked threads: kernel writes "running"
    // when the thread is executing in userspace, not in a syscall
    if (strncmp(line, "running", 7) == 0)
        return -2;  // distinct from -1 (permission/read error)

    // Format: syscall_nr a0 a1 a2 a3 a4 a5 RSP RIP
    // All values in hex with 0x prefix
    unsigned long nr, a0, a1, a2, a3, a4, a5, rsp, rip;

    int n = sscanf(line,
        "%lu 0x%lx 0x%lx 0x%lx 0x%lx 0x%lx 0x%lx 0x%lx 0x%lx",
        &nr, &a0, &a1, &a2, &a3, &a4, &a5, &rsp, &rip);

    if (n < 9) {
        // Fallback: parse as space-separated hex tokens
        // handles kernels that omit 0x prefix
        unsigned long *vals[] = {
            &nr, &a0, &a1, &a2, &a3, &a4, &a5, &rsp, &rip
        };
        char copy[512];
        strncpy(copy, line, sizeof(copy));
        char *tok = strtok(copy, " \t\n");
        int i = 0;
        while (tok && i < 9) {
            *vals[i++] = strtoul(tok, NULL, 0);
            tok = strtok(NULL, " \t\n");
        }
        if (i < 9) return -1;
    }

    // Zero all registers — unknown ones stay 0
    memset(regs, 0, X86_64_NGREG * sizeof(unsigned long));

    // Map syscall args to x86_64 register slots
    regs[15] = nr;   // ORIG_RAX
    regs[10] = nr;   // RAX
    regs[14] = a0;   // RDI
    regs[13] = a1;   // RSI
    regs[12] = a2;   // RDX
    regs[7]  = a3;   // R10
    regs[9]  = a4;   // R8
    regs[8]  = a5;   // R9
    regs[X86_64_REG_RSP] = rsp;
    regs[X86_64_REG_RIP] = rip;

    // Set segment registers for user mode
    regs[17] = 0x33; // CS
    regs[20] = 0x2b; // SS

    return 0;
}

int enumerate_threads(int pid, thread_info_t **threads_out) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/task", pid);

    DIR *dir = opendir(path);
    if (!dir) { perror("Cannot open task dir"); return -1; }

    int cap = 64;
    int count = 0;
    thread_info_t *threads = malloc(cap * sizeof(thread_info_t));
    if (!threads) { closedir(dir); return -1; }

    struct dirent *entry;
    while ((entry = readdir(dir))) {
        if (entry->d_name[0] == '.') continue;

        if (count == cap) {
            cap *= 2;
            thread_info_t *tmp = realloc(threads,
                                         cap * sizeof(thread_info_t));
            if (!tmp) { free(threads); closedir(dir); return -1; }
            threads = tmp;
        }

        int tid = atoi(entry->d_name);
        memset(&threads[count], 0, sizeof(thread_info_t));
        threads[count].tid = tid;

        int ret = read_thread_registers(pid, tid,
                                        threads[count].regs);
        if (ret == 0) {
            count++;
        } else if (ret == -2) {
            // Thread is running in userspace, not blocked
            fprintf(stderr,
                "  note: TID %d running (not in syscall),"
                " registers unavailable\n", tid);
            count++;
        } else {
            fprintf(stderr,
                "  warning: TID %d: cannot read registers"
                " (permission denied? try root)\n", tid);
            count++;
        }
    }

    // Ensure main thread (TID == PID) is first in the array.
    // GDB treats the first NT_PRSTATUS as the "current" thread.
    for (int i = 1; i < count; i++) {
        if (threads[i].tid == pid) {
            thread_info_t tmp = threads[0];
            threads[0] = threads[i];
            threads[i] = tmp;
            break;
        }
    }

    closedir(dir);
    *threads_out = threads;
    return count;
}

int read_auxv(int pid, char **data_out, size_t *sz_out) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/auxv", pid);

    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;

    size_t cap = 4096;
    char *data = malloc(cap);
    size_t sz = 0;
    ssize_t n;

    while ((n = read(fd, data + sz, cap - sz)) > 0) {
        sz += n;
        if (sz == cap) {
            cap *= 2;
            char *tmp = realloc(data, cap);
            if (!tmp) { free(data); close(fd); return -1; }
            data = tmp;
        }
    }

    close(fd);
    *data_out = data;
    *sz_out = sz;
    return 0;
}

// ============================================================
// RBP heuristic recovery
//
// /proc/pid/syscall gives us RSP and RIP but NOT RBP.
// On binaries compiled with frame pointers (gcc -fno-omit-
// frame-pointer, default on Arch/Fedora), GDB's DWARF CFI
// rules use RBP to compute the Canonical Frame Address (CFA).
// Without RBP, backtraces stop at frame 1.
//
// Algorithm:
//   1. Read the stack memory from RSP upward (already dumped)
//   2. For each 8-byte value V that looks like a stack address:
//      a. Check if *(V+8) falls in an executable mapping
//         (i.e. it's a return address in .text)
//      b. Check if *V is either 0 (chain end) or another
//         stack address (chain continues)
//   3. The candidate with the longest valid chain wins
//
// Tested: recovers full backtraces (statx → do_stat → main)
// on Arch Linux x86_64 with coreutils 9.x.
// ============================================================

static int is_executable_addr(unsigned long addr,
                              const mem_region_t *regions,
                              int num_regions) {
    for (int i = 0; i < num_regions; i++) {
        if (regions[i].executable &&
            addr >= regions[i].start &&
            addr < regions[i].end)
            return 1;
    }
    return 0;
}

static int is_stack_addr(unsigned long addr,
                         unsigned long stack_lo,
                         unsigned long stack_hi) {
    return addr > stack_lo && addr < stack_hi;
}

// Walk a frame pointer chain starting from candidate RBP.
// Returns the chain length (number of valid frames).
static int walk_fp_chain(unsigned long rbp_candidate,
                         int mem_fd,
                         unsigned long stack_lo,
                         unsigned long stack_hi,
                         const mem_region_t *regions,
                         int num_regions,
                         int max_depth) {
    unsigned long fp = rbp_candidate;
    int depth = 0;

    while (depth < max_depth) {
        // Read [fp] = saved RBP, [fp+8] = return address
        unsigned long frame[2];
        ssize_t n = pread(mem_fd, frame, 16, (off_t)fp);
        if (n < 16) break;

        unsigned long saved_rbp = frame[0];
        unsigned long ret_addr  = frame[1];

        // Return address must be in an executable mapping
        if (!is_executable_addr(ret_addr, regions, num_regions))
            break;

        depth++;

        // Chain end: saved RBP is 0 or outside stack
        if (saved_rbp == 0)
            break;
        if (!is_stack_addr(saved_rbp, stack_lo, stack_hi))
            break;
        // Frame pointer must move UP the stack (higher address)
        if (saved_rbp <= fp)
            break;

        fp = saved_rbp;
    }

    return depth;
}

// Scan the stack for the best RBP candidate.
// Returns the recovered RBP value, or 0 if no chain found.
static unsigned long recover_rbp(int mem_fd,
                                 unsigned long rsp,
                                 const mem_region_t *regions,
                                 int num_regions) {
    // Find the stack region that contains RSP
    unsigned long stack_lo = 0, stack_hi = 0;
    for (int i = 0; i < num_regions; i++) {
        if (rsp >= regions[i].start && rsp < regions[i].end) {
            stack_lo = regions[i].start;
            stack_hi = regions[i].end;
            break;
        }
    }
    if (stack_hi == 0) return 0;

    // Read up to 4KB of stack above RSP
    size_t scan_size = stack_hi - rsp;
    if (scan_size > 4096) scan_size = 4096;

    unsigned char *stack_buf = malloc(scan_size);
    if (!stack_buf) return 0;

    ssize_t nr = pread(mem_fd, stack_buf, scan_size, (off_t)rsp);
    if (nr < 16) { free(stack_buf); return 0; }

    unsigned long best_rbp = 0;
    int           best_depth = 0;

    // Scan every 8-byte aligned position on the stack
    for (size_t off = 0; off + 8 <= (size_t)nr; off += 8) {
        unsigned long val;
        memcpy(&val, stack_buf + off, 8);

        // Only consider values that look like stack addresses
        // above RSP (frame pointers point to higher frames)
        if (!is_stack_addr(val, rsp, stack_hi))
            continue;

        // Walk the frame pointer chain from this candidate
        int depth = walk_fp_chain(val, mem_fd,
                                  stack_lo, stack_hi,
                                  regions, num_regions, 64);

        if (depth > best_depth) {
            best_depth = depth;
            best_rbp   = val;
        }
    }

    free(stack_buf);

    if (best_rbp) {
        printf("  RBP recovered: 0x%016lx (chain depth: %d)\n",
               best_rbp, best_depth);
    }

    return best_rbp;
}

// ============================================================
// ELF note writer
//
// ELF note format:
//   Elf64_Nhdr  (12 bytes: namesz, descsz, type)
//   name        (namesz bytes, padded to 4-byte boundary)
//   desc        (descsz bytes, padded to 4-byte boundary)
//
// For core files: name is always "CORE\0" (5 bytes, pad to 8)
// ============================================================

size_t write_note(FILE *out, uint32_t type,
                  const void *desc, size_t desc_sz) {
    Elf64_Nhdr nhdr;
    nhdr.n_namesz = 5;       // "CORE\0" = 5 bytes
    nhdr.n_descsz = desc_sz;
    nhdr.n_type   = type;

    // "CORE\0" padded to 8 bytes (4-byte alignment of namesz=5)
    char name_padded[8] = {'C','O','R','E','\0','\0','\0','\0'};

    fwrite(&nhdr,       sizeof(nhdr), 1, out);
    fwrite(name_padded, 8,            1, out);
    fwrite(desc,        desc_sz,      1, out);

    // Pad desc to 4-byte boundary
    size_t pad = NOTE_ALIGN(desc_sz) - desc_sz;
    if (pad > 0) {
        char zeros[4] = {0};
        fwrite(zeros, pad, 1, out);
    }

    return sizeof(nhdr) + 8 + NOTE_ALIGN(desc_sz);
}

// ============================================================
// Core dump builder
// ============================================================

int build_core(int pid, const char *output_path) {
    printf("=== cvmfs-debug-rescue ===\n");
    printf("Target PID:   %d\n", pid);
    printf("Output:       %s\n", output_path);
    printf("Architecture: x86_64\n");
    printf("Dump level:   full\n");
    printf("\n");

    // ---- Parse memory map ----
    mem_region_t *regions = NULL;
    int num_regions = parse_maps(pid, &regions);
    if (num_regions < 0) return -1;
    printf("Memory regions: %d\n", num_regions);

    // ---- Open /proc/pid/mem early ----
    // Needed for RBP heuristic recovery (reads stack memory)
    char mem_path[64];
    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);
    int mem_fd = open(mem_path, O_RDONLY);
    if (mem_fd < 0) {
        perror("Cannot open /proc/pid/mem (run as root)");
        free(regions);
        return -1;
    }

    // ---- Enumerate threads ----
    thread_info_t *threads = NULL;
    int num_threads = enumerate_threads(pid, &threads);
    if (num_threads <= 0) {
        fprintf(stderr, "No threads found — is PID %d alive?\n", pid);
        free(regions); close(mem_fd);
        return -1;
    }
    printf("Threads:        %d\n\n", num_threads);

    for (int i = 0; i < num_threads; i++) {
        printf("  TID %-6d  RIP=0x%016lx  RSP=0x%016lx",
               threads[i].tid,
               threads[i].regs[X86_64_REG_RIP],
               threads[i].regs[X86_64_REG_RSP]);

        // Attempt heuristic RBP recovery for each thread
        unsigned long rsp = threads[i].regs[X86_64_REG_RSP];
        if (rsp != 0 && threads[i].regs[X86_64_REG_RBP] == 0) {
            unsigned long rbp = recover_rbp(mem_fd, rsp,
                                            regions, num_regions);
            if (rbp != 0) {
                threads[i].regs[X86_64_REG_RBP] = rbp;
            } else {
                printf("  (RBP=0, no chain found)");
            }
        }
        printf("\n");
    }
    printf("\n");

    // ---- Read auxiliary vector ----
    char  *auxv_data = NULL;
    size_t auxv_sz   = 0;
    if (read_auxv(pid, &auxv_data, &auxv_sz) < 0) {
        fprintf(stderr, "warning: could not read auxv\n");
    }


    // ---- Count dumpable regions ----
    int loadable = 0;
    for (int i = 0; i < num_regions; i++) {
        if (should_dump_region(&regions[i])) loadable++;
    }

    // ---- Calculate note section size ----

    // NT_PRSTATUS: one per thread
    size_t per_prstatus  = sizeof(Elf64_Nhdr) + 8
                         + NOTE_ALIGN(X86_64_PRSTATUS_SIZE);
    size_t total_prstatus = per_prstatus * num_threads;

    // NT_PRPSINFO: one total
    size_t prpsinfo_sz = sizeof(Elf64_Nhdr) + 8
                       + NOTE_ALIGN(X86_64_PRPSINFO_SIZE);

    // NT_FILE: covers ALL file-backed regions regardless of
    // dump level — GDB needs this to reload .text from disk
    uint64_t file_count  = 0;
    size_t   strings_len = 0;
    for (int i = 0; i < num_regions; i++) {
        if (regions[i].name[0] == '/') {
            file_count++;
            strings_len += strlen(regions[i].name) + 1;
        }
    }
    // NT_FILE desc format:
    //   uint64 count
    //   uint64 page_size
    //   count × [uint64 start, uint64 end, uint64 file_ofs]
    //   null-terminated filenames concatenated
    size_t file_desc_sz = 16
                        + (file_count * 24)
                        + strings_len;
    size_t file_note_sz = sizeof(Elf64_Nhdr) + 8
                        + NOTE_ALIGN(file_desc_sz);

    // NT_AUXV
    size_t auxv_note_sz = 0;
    if (auxv_data) {
        auxv_note_sz = sizeof(Elf64_Nhdr) + 8
                     + NOTE_ALIGN(auxv_sz);
    }

    size_t all_notes_sz = total_prstatus + prpsinfo_sz
                        + file_note_sz   + auxv_note_sz;

    // ---- Open output file ----
    FILE *core = fopen(output_path, "wb");
    if (!core) {
        perror("Cannot create output file");
        close(mem_fd); free(regions); free(threads);
        free(auxv_data);
        return -1;
    }

    // ---- ELF header ----
    Elf64_Ehdr ehdr;
    memset(&ehdr, 0, sizeof(ehdr));
    memcpy(ehdr.e_ident, ELFMAG, SELFMAG);
    ehdr.e_ident[EI_CLASS]   = ELFCLASS64;
    ehdr.e_ident[EI_DATA]    = ELFDATA2LSB;
    ehdr.e_ident[EI_VERSION] = EV_CURRENT;
    ehdr.e_ident[EI_OSABI]   = ELFOSABI_LINUX;
    ehdr.e_type              = ET_CORE;
    ehdr.e_machine           = EM_X86_64;
    ehdr.e_version           = EV_CURRENT;
    ehdr.e_phoff             = sizeof(Elf64_Ehdr);
    ehdr.e_ehsize            = sizeof(Elf64_Ehdr);
    ehdr.e_phentsize         = sizeof(Elf64_Phdr);
    ehdr.e_phnum             = 1 + loadable; // PT_NOTE + PT_LOADs
    fwrite(&ehdr, sizeof(ehdr), 1, core);

    // ---- Calculate offsets ----
    size_t phdr_total  = ehdr.e_phnum * sizeof(Elf64_Phdr);
    size_t note_offset = sizeof(Elf64_Ehdr) + phdr_total;
    size_t data_offset = note_offset + all_notes_sz;

    // ---- PT_NOTE program header ----
    Elf64_Phdr note_phdr = {0};
    note_phdr.p_type   = PT_NOTE;
    note_phdr.p_offset = note_offset;
    note_phdr.p_filesz = all_notes_sz;
    fwrite(&note_phdr, sizeof(note_phdr), 1, core);

    // ---- PT_LOAD program headers (one per dumpable region) ----
    size_t cur_offset = data_offset;
    for (int i = 0; i < num_regions; i++) {
        if (!should_dump_region(&regions[i])) continue;

        size_t seg_size = regions[i].end - regions[i].start;

        Elf64_Phdr phdr = {0};
        phdr.p_type   = PT_LOAD;
        phdr.p_offset = cur_offset;
        phdr.p_vaddr  = regions[i].start;
        phdr.p_filesz = seg_size;
        phdr.p_memsz  = seg_size;
        phdr.p_flags  = PF_R;
        if (regions[i].writable)   phdr.p_flags |= PF_W;
        if (regions[i].executable) phdr.p_flags |= PF_X;
        phdr.p_align  = PAGE_SIZE;

        fwrite(&phdr, sizeof(phdr), 1, core);
        cur_offset += seg_size;
    }

    // ---- NT_PRSTATUS notes (one per thread) ----
    for (int i = 0; i < num_threads; i++) {
        unsigned char *prstatus = calloc(1, X86_64_PRSTATUS_SIZE);
        if (!prstatus) { fclose(core); return -1; }

        // pr_pid at x86_64 offset
        *(pid_t *)(prstatus + X86_64_PRSTATUS_PID)
            = (pid_t)threads[i].tid;

        // pr_reg: copy full gregset (unknown regs are 0)
        memcpy(prstatus + X86_64_PRSTATUS_REG,
               threads[i].regs,
               X86_64_NGREG * sizeof(unsigned long));

        write_note(core, 1 /* NT_PRSTATUS */,
                   prstatus, X86_64_PRSTATUS_SIZE);
        free(prstatus);
    }

    // ---- NT_PRPSINFO ----
    {
        unsigned char *prpsinfo = calloc(1, X86_64_PRPSINFO_SIZE);
        if (!prpsinfo) { fclose(core); return -1; }

        prpsinfo[0] = 2;    // pr_state = TASK_UNINTERRUPTIBLE
        prpsinfo[1] = 'D';  // pr_sname

        // pr_pid
        *(pid_t *)(prpsinfo + X86_64_PRPSINFO_PID)
            = (pid_t)pid;

        // Read cmdline for pr_fname and pr_psargs
        char cmdline[80] = {0};
        char cmd_path[64];
        snprintf(cmd_path, sizeof(cmd_path),
                 "/proc/%d/cmdline", pid);
        int cmd_fd = open(cmd_path, O_RDONLY);
        if (cmd_fd >= 0) {
            ssize_t n = read(cmd_fd, cmdline, sizeof(cmdline) - 1);
            close(cmd_fd);
            // cmdline uses null bytes as arg separators → spaces
            if (n > 0) {
                for (int j = 0; j < n - 1; j++) {
                    if (cmdline[j] == '\0') cmdline[j] = ' ';
                }
            }
        }

        // pr_fname: binary name only (up to 15 chars)
        char *bn = strrchr(cmdline, '/');
        bn = bn ? bn + 1 : cmdline;
        char *sp = strchr(bn, ' ');
        size_t nlen = sp ? (size_t)(sp - bn) : strlen(bn);
        if (nlen > 15) nlen = 15;
        memcpy(prpsinfo + X86_64_PRPSINFO_FNAME, bn, nlen);

        // pr_psargs: full command line (up to 79 chars)
        strncpy((char *)(prpsinfo + X86_64_PRPSINFO_ARGS),
                cmdline, 79);

        write_note(core, 3 /* NT_PRPSINFO */,
                   prpsinfo, X86_64_PRPSINFO_SIZE);
        free(prpsinfo);
    }

    // ---- NT_FILE ----
    // Tells GDB the exact file→address mapping for every
    // file-backed region. This is what allows GDB to reload
    // .text and .rodata from disk even if we didn't dump them.
    {
        char *file_desc = calloc(1, file_desc_sz);
        if (!file_desc) { fclose(core); return -1; }

        uint64_t *hdr = (uint64_t *)file_desc;
        hdr[0] = file_count;
        hdr[1] = PAGE_SIZE;

        uint64_t *entries = &hdr[2];
        char     *strtab  = (char *)&entries[file_count * 3];
        int       idx     = 0;
        char     *sp2     = strtab;

        for (int i = 0; i < num_regions; i++) {
            if (regions[i].name[0] != '/') continue;
            entries[idx * 3 + 0] = regions[i].start;
            entries[idx * 3 + 1] = regions[i].end;
            // file_ofs is in pages, not bytes
            entries[idx * 3 + 2] = regions[i].offset / PAGE_SIZE;
            strcpy(sp2, regions[i].name);
            sp2 += strlen(regions[i].name) + 1;
            idx++;
        }

        write_note(core, 0x46494c45 /* NT_FILE */,
                   file_desc, file_desc_sz);
        free(file_desc);
    }

    // ---- NT_AUXV ----
    if (auxv_data) {
        write_note(core, 6 /* NT_AUXV */, auxv_data, auxv_sz);
    }

    // ---- Memory contents ----
    // Uses pread() per PAGE_SIZE chunk so guard page failures
    // are isolated — one failed chunk doesn't corrupt the rest
    // of the region's file position.

    printf("Dumping memory:\n");
    size_t total_read   = 0;
    size_t total_zeroed = 0;

    for (int i = 0; i < num_regions; i++) {
        if (!should_dump_region(&regions[i])) continue;

        size_t seg_size = regions[i].end - regions[i].start;
        printf("  0x%lx-0x%lx %-40s ... ",
               regions[i].start, regions[i].end,
               regions[i].name[0] ? regions[i].name : "(anon)");
        fflush(stdout);

        char          buf[PAGE_SIZE];
        unsigned long addr         = regions[i].start;
        size_t        rem          = seg_size;
        size_t        region_read  = 0;
        size_t        region_zero  = 0;

        while (rem > 0) {
            size_t chunk = rem > PAGE_SIZE ? PAGE_SIZE : rem;

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

        total_read   += region_read;
        total_zeroed += region_zero;

        if (region_zero > 0) {
            printf("partial (%zu read, %zu zeroed)\n",
                   region_read, region_zero);
        } else {
            printf("OK (%zu bytes)\n", region_read);
        }
    }

    // ---- Cleanup ----
    fclose(core);
    close(mem_fd);
    free(regions);
    free(threads);
    free(auxv_data);

    printf("\n=== Summary ===\n");
    printf("Threads:  %d\n", num_threads);
    printf("Regions:  %d total, %d dumped\n", num_regions, loadable);
    printf("Memory:   %zu bytes read, %zu bytes zeroed\n",
           total_read, total_zeroed);
    printf("Output:   %s\n\n", output_path);
    printf("Load with:\n");
    printf("  gdb /path/to/binary %s\n", output_path);
    printf("  (gdb) thread apply all bt\n\n");
    printf("RBP recovery: heuristic frame-pointer chain scan\n");
    printf("If backtraces are short, the binary may lack frame\n");
    printf("pointers. Recompile with -fno-omit-frame-pointer.\n");

    return 0;
}

// ============================================================
// main — argument parsing
// ============================================================

int main(int argc, char *argv[]) {
    int argi = 1;

    // Parse flags
    while (argi < argc && argv[argi][0] == '-') {
        if (!strcmp(argv[argi], "--help") ||
                   !strcmp(argv[argi], "-h")) {
            printf(
"Usage: cvmfs_debug_rescue [OPTIONS] <pid> <output.core>\n"
"\n"
"Constructs an ELF core dump from a D-state process\n"
"without ptrace. Reads /proc/<pid>/ interfaces directly.\n"
"\n"
"Options:\n"

"  --help       this message\n"
"\n"
"Requires root on kernel 6.x (for /proc/pid/syscall access).\n"
"\n"
"Example:\n"
"  sudo cvmfs_debug_rescue 1234 /tmp/hung.core\n"
"  gdb /usr/bin/cvmfs2 /tmp/hung.core\n"
"  (gdb) thread apply all bt\n"
            );
            return 0;
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[argi]);
            fprintf(stderr, "Try --help\n");
            return 1;
        }
        argi++;
    }

    if (argc - argi != 2) {
        fprintf(stderr,
            "Usage: %s [OPTIONS] <pid> <output.core>\n"
            "Try --help for details.\n", argv[0]);
        return 1;
    }
    int pid = atoi(argv[argi]);
    if (pid <= 0) {
        fprintf(stderr, "Invalid PID: %s\n", argv[argi]);
        return 1;
    }

    return build_core(pid, argv[argi + 1]);
}