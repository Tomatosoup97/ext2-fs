#include <stdbool.h>
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "blkio.h"
#include "ext2.h"

#define min(a,b) \
   ({ __typeof__ (a) _a = (a); \
      __typeof__ (b) _b = (b); \
      _a < _b ? _a : _b; })

typedef struct ext2fs_dinode dinode_t;
typedef struct ext2fs sb_t;
typedef struct ext2_gd bgd_t;
typedef struct ext2fs_direct_2 dirent_t;

void hexdump(void *addr, size_t size) {
  uint8_t *data = addr;
  bool was_empty = false;
  bool is_empty;

  for (unsigned i = 0; i < size; i += 16, was_empty = is_empty) {
    is_empty = true;

    for (unsigned j = i; j < min(size, i + 16); j++) {
      if (data[j]) {
        is_empty = false;
        break;
      }
    }

    if (is_empty) {
      if (!was_empty)
        puts("*");
      continue;
    }

    printf("%04x:", i);
    for (unsigned j = i; j < min(size, i + 16); j++) {
      if (j % 8 == 0)
        putchar(' ');
      printf(" %02x", data[j]);
    }
    printf(" |");
    for (unsigned j = i; j < min(size, i + 16); j++) {
      uint8_t c = data[j];
      putchar(isprint(c) ? c : '.');
    }
    printf("|\n");
  }
}

static const char *ditype_name[] = {
  [EXT2_FT_UNKNOWN] = "???",
  [EXT2_FT_REG_FILE]	= "reg",
  [EXT2_FT_DIR] = "dir",
  [EXT2_FT_CHRDEV] = "cdev",
  [EXT2_FT_BLKDEV] = "bdev",
  [EXT2_FT_FIFO] = "fifo",
  [EXT2_FT_SOCK] = "sock",
  [EXT2_FT_SYMLINK] = "slnk",
};

int main(void) {
  blk_open("debian9-ext2.img");

  puts(">>> super block");

  sb_t sb;
  blk_setsize(1024);
  blk_read(&sb, 1);
  size_t blk_size = 1024 * (1 << sb.e2fs_log_bsize);
  size_t inode_size = sb.e2fs_inode_size;
  blk_setsize(blk_size);
  printf("# of inodes      : %d\n"
         "# of blocks      : %d\n"
         "block size       : %ld\n"
         "blocks per group : %d\n"
         "frags per group  : %d\n"
         "inodes per group : %d\n"
         "inode size       : %ld\n",
         sb.e2fs_icount, sb.e2fs_bcount, blk_size, sb.e2fs_bpg, sb.e2fs_fpg,
         sb.e2fs_ipg, inode_size);

  void *blk = malloc(blk_size * 2);

  puts("\n>>> block group descriptor table");

  bgd_t bgd;
  blk_read(blk, 2);
  memcpy(&bgd, blk, sizeof(bgd_t));
  printf("blocks bitmap block : %d\n"
         "inodes bitmap block : %d\n"
         "inodes table block  : %d\n",
         bgd.ext2bgd_b_bitmap, bgd.ext2bgd_i_bitmap, bgd.ext2bgd_i_tables);

  puts("\n>>> root i-node");

  dinode_t di;
  blk_read(blk, bgd.ext2bgd_i_tables);
  memcpy(&di, blk + (EXT2_ROOTINO - 1) * inode_size, inode_size);
  printf("# of links  : %d\n"
         "# of blocks : %d\n"
         "first block : %d\n",
         di.e2di_nlink, di.e2di_nblock, di.e2di_blocks[0]);

  puts("\n>>> root directory");

  blk_read(blk, di.e2di_blocks[0]);
  blk_read(blk + blk_size, di.e2di_blocks[1]);

  dirent_t *dir = blk;

  while (dir->e2d_ino) {
    printf("name: '%.*s', ino: %d, type: %s\n",
           dir->e2d_namlen, dir->e2d_name, 
           dir->e2d_ino, ditype_name[dir->e2d_type]);
    dir = (void *)dir + dir->e2d_reclen;
  }

  free(blk);
  blk_close();
  return 0;
}
