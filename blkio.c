#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "blkio.h"

#define panic()                                                 \
  __extension__({                                               \
    fprintf(stderr, "%s: %s\n", __func__, strerror(errno));     \
    exit(EXIT_FAILURE);                                         \
  })

static size_t blksize = 1 << 10;
static int fd = -1;

void blk_open(const char *path) {
  fd = open(path, O_RDWR);

  if (fd < 0)
    panic();
}

void blk_close(void) {
  if (close(fd) < 0)
    panic();
}

void blk_read_n(void *buf, size_t addr, size_t count) {
  size_t offset = addr * blksize;
  size_t size = count * blksize;

  ssize_t actual = pread(fd, buf, size, offset);

  if (actual < 0)
    panic();

  assert((size_t)actual == size);
}

void blk_setsize(size_t size) {
  blksize = size;
}
