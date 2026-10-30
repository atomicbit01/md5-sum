#ifndef MD5_H
#define MD5_H

#include <limits.h>
#include <math.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned char uchar;

typedef struct MD5_DGST {
  uint32_t a0;
  uint32_t b0;
  uint32_t c0;
  uint32_t d0;
} MD5_DGST;

typedef struct MD5 {
  uchar digest[16];
  char hexstring[33];
} MD5;

#define BLK_SIZE 64 // 512 bits


#define LEFT_ROTATE(x, y) ((((x) << (y)) | ((x) >> ((32 - (y)) & 31))))


#define F(x, y, z) ((((x) & (y)) | (~(x) & (z))))
#define G(x, y, z) ((((x) & (z)) | ((y) & ~(z))))
#define H(x, y, z) (((x) ^ (y) ^ (z)))
#define I(x, y, z) (((y) ^ ((x) | ~(z))))

extern uint32_t K[BLK_SIZE];

// shifts per round
extern const uint32_t s[BLK_SIZE];

void *md5(const uchar *msg, uint32_t len, MD5_DGST *state);
void md5_init(void);
void md5_init_dgst(MD5_DGST *state);
void *pad_message(const char *msg, uint32_t *new_len);
void md5_close(void *ptr);

void calc_dgst(const uchar *block, MD5_DGST *state);
void message_digest(const char *msg, MD5_DGST *state);

void calc_md5fromstate(MD5 *md5, MD5_DGST *state);

void calc_md5(const char *msg, MD5 *res);

#endif // MD5_H
