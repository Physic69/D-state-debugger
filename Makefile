CC = gcc
CFLAGS = -Wall -Wextra -O2
FUSE_CFLAGS = $(shell pkg-config --cflags fuse3)
FUSE_LIBS = $(shell pkg-config --libs fuse3)

all: cvmfs_debug_rescue probe_proc toy_fuse

cvmfs_debug_rescue: src/cvmfs_debug_rescue.c
	$(CC) $(CFLAGS) -o $@ $<

probe_proc: src/probe_proc.c
	$(CC) $(CFLAGS) -o $@ $<

toy_fuse: src/toy_fuse.c
	$(CC) $(CFLAGS) -g $(FUSE_CFLAGS) -o $@ $< $(FUSE_LIBS) -lpthread

clean:
	rm -f cvmfs_debug_rescue probe_proc toy_fuse

.PHONY: all clean