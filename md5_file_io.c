#define _FILE_OFFSET_BITS 64
#include "md5_file_io.h"
#include "md5.h"
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

off_t getfilesize(const char *path) {

  int fd = open(path, O_RDONLY);

  if (fd < 0) {
    return -1;
  }

  off_t size = lseek(fd, 0, SEEK_END);

  close(fd);

  return size;
}

void md5_stream_init(MD5_CTX *ctx) {

  md5_init_dgst(&(ctx->state));
  memset(ctx->fbuffer, 0, sizeof(ctx->fbuffer));
  memset(ctx->blk_buffer, 0, sizeof(ctx->blk_buffer));
  ctx->byte_index = 0;
  ctx->byte_count = 0;
}

void read_stream(int *fd, MD5_CTX *ctx) {

  while (1) {

    ssize_t bytes_read = read(*fd, ctx->fbuffer, sizeof(ctx->fbuffer));
    if (bytes_read < 0) {
      close(*fd);
      return;
    }

    if (bytes_read == 0) {

      break;
    }

    for (ssize_t i = 0; i < bytes_read; i++) {
      ctx->blk_buffer[ctx->byte_index] = ctx->fbuffer[i];
      ctx->byte_index++;
      ctx->byte_count++;

      if (ctx->byte_index == BLK_SIZE) {
        calc_dgst(ctx->blk_buffer, &ctx->state);
        ctx->byte_index = 0;
      }
    }
  }
  ctx->blk_buffer[ctx->byte_index++] = 0x80;

  if (ctx->byte_index <= 57) {
    memset(&(ctx->blk_buffer[ctx->byte_index]), 0, 56 - (ctx->byte_index));

  } else {
    memset(&(ctx->blk_buffer[ctx->byte_index]), 0, 64 - (ctx->byte_index));
    calc_dgst(ctx->blk_buffer, &ctx->state);
    memset(&(ctx->blk_buffer[ctx->byte_index]), 0, 56);
  }
  uint64_t end_bits = (uint64_t)ctx->byte_count * 8LL;

  for (int j = 0; j < 8; j++) {
    /** 8 bits = 1 B so right shift by 1B and capture last byte with 0xff
     */
    ctx->blk_buffer[56 + j] = ((end_bits >> (8 * j)) & 0xff);
  }
  calc_dgst(ctx->blk_buffer, &ctx->state);
}

void calc_file_md5(int *fd, FILE_METADATA *fm) {
  MD5_CTX ctx;
  md5_stream_init(&ctx);

  read_stream(fd, &ctx);

  calc_md5fromstate(&(fm->hash), &(ctx.state));
}

void update_md5(MD5_CTX *ctx) {
  memcpy(ctx->blk_buffer, &(ctx->fbuffer[ctx->byte_count]),
         sizeof(ctx->blk_buffer));
  calc_dgst(ctx->blk_buffer, &(ctx->state));
}
