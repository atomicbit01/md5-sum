#ifndef MD5_FILE_IO
#define MD5_FILE_IO

#include "md5.h"
#include <stdint.h>
#include <sys/types.h>

#define FILE_BUFFER_SIZE 4194304

typedef long long int lli;

typedef struct FILE_METADATA {
  char path[4096];
  MD5 hash;
  off_t sizeinbytes;

} FILE_METADATA;

typedef struct {
  MD5_DGST state;
  uchar fbuffer[FILE_BUFFER_SIZE];
  uchar blk_buffer[BLK_SIZE];
  uint32_t byte_index;
  uint32_t byte_count;
} MD5_CTX;

FILE_METADATA get_file_metadata(const char *path);

off_t getfilesize(const char *path);

void md5_stream_init(MD5_CTX *ctx);

void read_stream(int *fd, MD5_CTX *ctx);

void calc_file_md5(int *fd, FILE_METADATA *fm);

void update_md5(MD5_CTX *ctx);

#endif // MD5_FILE_IO
