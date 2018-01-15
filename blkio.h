#ifndef _BLKIO_H_
#define _BLKIO_H_

#include <sys/types.h>

void blk_open(const char *path);
void blk_close(void);
void blk_read_n(void *buf, size_t addr, size_t count);
#define blk_read(buf, addr) blk_read_n(buf, addr, 1)
void blk_setsize(size_t size);

#endif
