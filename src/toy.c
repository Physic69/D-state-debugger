
#define FUSE_USE_VERSION 31
#include <fuse3/fuse.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>

// Global mutex that we'll use to create deadlocks
pthread_mutex_t evil_lock = PTHREAD_MUTEX_INITIALIZER;

static int toy_getattr(const char *path, struct stat *stbuf,
                       struct fuse_file_info *fi) {
    (void) fi;
    memset(stbuf, 0, sizeof(struct stat));
    
    if (strcmp(path, "/") == 0) {
        stbuf->st_mode = S_IFDIR | 0755;
        stbuf->st_nlink = 2;
        return 0;
    }
    
    // Normal file
    if (strcmp(path, "/hello") == 0) {
        stbuf->st_mode = S_IFREG | 0444;
        stbuf->st_nlink = 1;
        stbuf->st_size = 13;
        return 0;
    }
    
    // THIS FILE HANGS FOREVER — simulates deadlock
    if (strcmp(path, "/hang") == 0) {
        // Simulate: daemon stuck in network call
        while(1) { sleep(99999); }
        return 0;  // never reached
    }
    
    // THIS FILE CAUSES DEADLOCK — more realistic
    if (strcmp(path, "/deadlock") == 0) {
        // Lock is already held by another thread
        // and will never be released
        pthread_mutex_lock(&evil_lock);
        // ... stuck forever
        stbuf->st_mode = S_IFREG | 0444;
        return 0;
    }
    
    // THIS FILE HANGS IN KERNEL — stuck in syscall
    if (strcmp(path, "/kernel_stuck") == 0) {
        // Simulate daemon stuck in a kernel call
        // e.g., reading from a socket that never responds
        int fds[2];
        pipe(fds);
        char buf[1];
        read(fds[0], buf, 1);  // blocks forever, 
                                // nothing writes to pipe
        return 0;
    }
    
    return -ENOENT;
}

static int toy_readdir(const char *path, void *buf, 
                       fuse_fill_dir_t filler,
                       off_t offset, struct fuse_file_info *fi,
                       enum fuse_readdir_flags flags) {
    (void) offset; (void) fi; (void) flags;
    
    if (strcmp(path, "/") != 0)
        return -ENOENT;
    
    filler(buf, ".", NULL, 0, 0);
    filler(buf, "..", NULL, 0, 0);
    filler(buf, "hello", NULL, 0, 0);
    filler(buf, "hang", NULL, 0, 0);
    filler(buf, "deadlock", NULL, 0, 0);
    filler(buf, "kernel_stuck", NULL, 0, 0);
    return 0;
}

static int toy_read(const char *path, char *buf, size_t size,
                    off_t offset, struct fuse_file_info *fi) {
    (void) fi;
    
    if (strcmp(path, "/hello") == 0) {
        const char *content = "hello world\n";
        size_t len = strlen(content);
        if (offset >= (off_t)len) return 0;
        if (offset + size > len) size = len - offset;
        memcpy(buf, content + offset, size);
        return size;
    }
    
    return -ENOENT;
}

// Pre-lock the evil_lock so /deadlock path gets stuck
static void *lock_holder(void *arg) {
    (void) arg;
    pthread_mutex_lock(&evil_lock);
    // Hold it forever
    while(1) sleep(99999);
    return NULL;
}

static const struct fuse_operations toy_ops = {
    .getattr = toy_getattr,
    .readdir = toy_readdir,
    .read    = toy_read,
};

int main(int argc, char *argv[]) {
    // Start the lock holder thread
    pthread_t t;
    pthread_create(&t, NULL, lock_holder, NULL);
    sleep(1);  // ensure lock is held
    
    return fuse_main(argc, argv, &toy_ops, NULL);
}