/*
 * This file is based on example source code 'hello_ll.c'
 *
 * FUSE: Filesystem in Userspace
 * Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>
 *
 * This program can be distributed under the terms of the GNU GPL.
 */

#define FUSE_USE_VERSION 30

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <fuse_lowlevel.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ext2.h"
#include "blkio.h"

#define UNUSED __attribute__((unused))

typedef struct fuse_file_info fuse_file_info_t;

static const char *ext2_str = "Hello World!\n";
static const char *ext2_name = "hello";

static int ext2_stat(fuse_ino_t ino, struct stat *stbuf) {
  stbuf->st_ino = ino;

  switch (ino) {
    case 1:
      stbuf->st_mode = S_IFDIR | 0755;
      stbuf->st_nlink = 2;
      break;

    case 2:
      stbuf->st_mode = S_IFREG | 0444;
      stbuf->st_nlink = 1;
      stbuf->st_size = strlen(ext2_str);
      break;

    default:
      return -1;
  }
  return 0;
}

static void ext2_getattr(fuse_req_t req, fuse_ino_t ino,
                         fuse_file_info_t *fi UNUSED) {
  struct stat stbuf;

  memset(&stbuf, 0, sizeof(stbuf));
  if (ext2_stat(ino, &stbuf) == -1) {
    fuse_reply_err(req, ENOENT);
  } else {
    fuse_reply_attr(req, &stbuf, 1.0);
  }
}

static void ext2_lookup(fuse_req_t req, fuse_ino_t parent, const char *name) {
  struct fuse_entry_param e;

  if (parent != 1 || strcmp(name, ext2_name) != 0) {
    fuse_reply_err(req, ENOENT);
  } else {
    memset(&e, 0, sizeof(e));
    e.ino = 2;
    e.attr_timeout = 1.0;
    e.entry_timeout = 1.0;
    ext2_stat(e.ino, &e.attr);

    fuse_reply_entry(req, &e);
  }
}

typedef struct {
  char *p;
  size_t size;
} dirbuf_t;

static void dirbuf_add(fuse_req_t req, dirbuf_t *b, const char *name,
                       fuse_ino_t ino) {
  struct stat stbuf;
  size_t oldsize = b->size;
  b->size += fuse_add_direntry(req, NULL, 0, name, NULL, 0);
  b->p = (char *)realloc(b->p, b->size);
  memset(&stbuf, 0, sizeof(stbuf));
  stbuf.st_ino = ino;
  fuse_add_direntry(req, b->p + oldsize, b->size - oldsize, name, &stbuf,
                    b->size);
}

#define min(x, y) ((x) < (y) ? (x) : (y))

static int reply_buf_limited(fuse_req_t req, const char *buf, size_t bufsize,
                             off_t off, size_t maxsize) {
  if (off < (ssize_t)bufsize) {
    return fuse_reply_buf(req, buf + off, min(bufsize - off, maxsize));
  } else {
    return fuse_reply_buf(req, NULL, 0);
  }
}

static void ext2_opendir(fuse_req_t req, fuse_ino_t ino UNUSED,
                         fuse_file_info_t *fi) {
  fuse_reply_open(req, fi);
}

static void ext2_readdir(fuse_req_t req, fuse_ino_t ino, size_t size,
                         off_t off, fuse_file_info_t *fi UNUSED) {
  if (ino != 1) {
    fuse_reply_err(req, ENOTDIR);
  } else {
    dirbuf_t b;

    memset(&b, 0, sizeof(b));
    dirbuf_add(req, &b, ".", 1);
    dirbuf_add(req, &b, "..", 1);
    dirbuf_add(req, &b, ext2_name, 2);
    reply_buf_limited(req, b.p, b.size, off, size);
    free(b.p);
  }
}

static void ext2_releasedir(fuse_req_t req, fuse_ino_t ino UNUSED,
                            fuse_file_info_t *fi UNUSED) {
  fuse_reply_err(req, ENOENT);
}

static void ext2_open(fuse_req_t req, fuse_ino_t ino, fuse_file_info_t *fi) {
  if (ino != 2)
    fuse_reply_err(req, EISDIR);
  else if ((fi->flags & 3) != O_RDONLY)
    fuse_reply_err(req, EACCES);
  else
    fuse_reply_open(req, fi);
}

static void ext2_read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
                      fuse_file_info_t *fi UNUSED) {
  assert(ino == 2);
  reply_buf_limited(req, ext2_str, strlen(ext2_str), off, size);
}

static void ext2_release(fuse_req_t req, fuse_ino_t ino UNUSED,
                         fuse_file_info_t *fi UNUSED) {
  fuse_reply_err(req, ENOENT);
}

static void ext2_statfs(fuse_req_t req, fuse_ino_t ino UNUSED) {
  struct statvfs statfs;
  memset(&statfs, 0, sizeof(statfs));
  fuse_reply_statfs(req, &statfs);
}

static struct fuse_lowlevel_ops ext2_oper = {
  .lookup = ext2_lookup,
  .getattr = ext2_getattr,
  .opendir = ext2_opendir,
  .readdir = ext2_readdir,
  .releasedir = ext2_releasedir,
  .open = ext2_open,
  .read = ext2_read,
  .release = ext2_release,
  .statfs = ext2_statfs
};

int main(int argc, char *argv[]) {
  struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
  struct fuse_chan *ch;
  char *mountpoint;
  int err = -1;

  if (fuse_parse_cmdline(&args, &mountpoint, NULL, NULL) != -1 &&
      (ch = fuse_mount(mountpoint, &args)) != NULL) {
    struct fuse_session *se;

    se = fuse_lowlevel_new(&args, &ext2_oper, sizeof(ext2_oper), NULL);
    if (se != NULL) {
      if (fuse_set_signal_handlers(se) != -1) {
        fuse_session_add_chan(se, ch);
        err = fuse_session_loop(se);
        fuse_remove_signal_handlers(se);
        fuse_session_remove_chan(ch);
      }
      fuse_session_destroy(se);
    }
    fuse_unmount(mountpoint, ch);
  }
  fuse_opt_free_args(&args);

  return err ? 1 : 0;
}
