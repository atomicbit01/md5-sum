#include "md5.h"
#include <string.h>

uint32_t K[BLK_SIZE] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a,
    0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340,
    0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8,
    0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
    0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92,
    0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};
const uint32_t s[BLK_SIZE] = {
    7,  12, 17, 22, 7,  12, 17, 22, 7,  12, 17, 22, 7,  12, 17, 22, 5,
    9,  14, 20, 5,  9,  14, 20, 5,  9,  14, 20, 5,  9,  14, 20, 4,  11,
    16, 23, 4,  11, 16, 23, 4,  11, 16, 23, 4,  11, 16, 23, 6,  10, 15,
    21, 6,  10, 15, 21, 6,  10, 15, 21, 6,  10, 15, 21

};

void *md5(const uchar *message, uint32_t len, struct MD5_DGST *md5_dgst) {

  for (int i = 0; i < (len / 64); i++) {


    uint32_t M[16];

    // memcpy n is number of bytes
    memcpy(M, &message[i * 64], 16 * (32 / 8));

    // initalize hash values for this block

    uint32_t A = md5_dgst->a0;
    uint32_t B = md5_dgst->b0;
    uint32_t C = md5_dgst->c0;
    uint32_t D = md5_dgst->d0;

    for (int l = 0; l < 64; l++) {
      uint32_t f, g;
      if (l >= 0 && l <= 15) {
        f = F(B, C, D);
        g = l;
      } else if (l >= 16 && l <= 31) {
        f = G(B, C, D);
        g = (5 * l + 1) % 16;

      } else if (l >= 32 && l <= 47) {
        f = H(B, C, D);
        g = (3 * l + 5) % 16;

      } else if (l >= 48 && l <= 63) {
        f = I(B, C, D);
        g = (7 * l) % 16;
      }

      f = f + A + K[l] + M[g];
      A = D;
      D = C;
      C = B;
      B = B + LEFT_ROTATE(f, s[l]);
    }
    md5_dgst->a0 += A;
    md5_dgst->b0 += B;
    md5_dgst->c0 += C;
    md5_dgst->d0 += D;
  }

  // combining hashes in little endian format
  uint32_t hashes[4] = {md5_dgst->a0, md5_dgst->b0, md5_dgst->c0, md5_dgst->d0};
  uchar digest[16];

  for (int i = 0; i < 4; i++) {
    int k = 4 * i;
    digest[k] = ((uchar)hashes[i] & 0xff);
    digest[k + 1] = ((uchar)(hashes[i] >> 8) & 0xff);
    digest[k + 2] = ((uchar)(hashes[i] >> 16) & 0xff);
    digest[k + 3] = ((uchar)(hashes[i] >> 24) & 0xff);
  }

  char *hex_string = calloc(sizeof(uchar), 33);
  hex_string[32] = '\0';

  for (int i = 0; i < 16; i++) {
    sprintf(&hex_string[i * 2], "%02x", digest[i]);
  }

  return hex_string;
}

void md5_init() {
  // some constants
  for (uint32_t i = 0; i < BLK_SIZE; i++) {
    K[i] = floor(1.0 * (1LL << 32) * fabs(sin(i + 1.0)));
  }
}

void md5_init_dgst(MD5_DGST *s) {
  s->a0 = 0x67452301;
  s->b0 = 0xefcdab89;
  s->c0 = 0x98badcfe;
  s->d0 = 0x10325476;
}

void md5_close(void *memptr) { free(memptr); }

void *pad_message(const char message[], uint32_t *padded_len) {

  // calculate size of mesage str as char = 1B len give size
  uint32_t message_len = strlen(message);
  // minimum size to accomadate the message end padding for md5
  uint32_t total_len = message_len + 1 + 8;

  if (total_len % 64 != 0) {
    total_len += (64 - (total_len % 64));
  }

  uchar *padded_message = calloc(sizeof(uchar), total_len);
  if (!padded_message)
    return NULL;

  // start index
  int i = 0;

  // copy message to padded_message
  for (i = 0; i < message_len; i++) {
    padded_message[i] = message[i];
  }

  /**
   * md5 padding rules append 1 bit then 0's till 448%512 which is append 0x80
   * then 0x00 till before last 8 bytes
   */
  padded_message[message_len] = 0x80;
  for (i = message_len + 1; i < (total_len - 8); i++) {

    padded_message[i] = 0x00;
  }

  /**
   * end padding last 8 bytes with size of message in bits in little endian
   * format
   */
  uint64_t end_bits = (uint64_t)message_len * 8u;

  for (int j = 0; j < 8; j++) {
    /** 8 bits = 1 B so right shift by 1B and capture last byte with 0xff
     */
    padded_message[i + j] = ((end_bits >> (8 * j)) & 0xff);
  }

  // return new padded length
  *padded_len = total_len;

  return padded_message;
}

void calc_dgst(const uchar *buffer, MD5_DGST *d) {
  // calculate digest for 64 B buffer and update
  uint32_t M[16];

  // memcpy n is number of bytes
  memcpy(M, buffer, 16 * (32 / 8));

  // initalize hash values for this block

  uint32_t A = d->a0;
  uint32_t B = d->b0;
  uint32_t C = d->c0;
  uint32_t D = d->d0;

  for (int l = 0; l < 64; l++) {
    uint32_t f, g;
    if (l >= 0 && l <= 15) {
      f = F(B, C, D);
      g = l;
    } else if (l >= 16 && l <= 31) {
      f = G(B, C, D);
      g = (5 * l + 1) % 16;

    } else if (l >= 32 && l <= 47) {
      f = H(B, C, D);
      g = (3 * l + 5) % 16;

    } else if (l >= 48 && l <= 63) {
      f = I(B, C, D);
      g = (7 * l) % 16;
    }

    f = f + A + K[l] + M[g];
    A = D;
    D = C;
    C = B;
    B = B + LEFT_ROTATE(f, s[l]);
  }
  d->a0 += A;
  d->b0 += B;
  d->c0 += C;
  d->d0 += D;
}

void message_digest(const char message[], MD5_DGST *d) {

  md5_init_dgst(d);

  // calculate md5 for message
  uint32_t padded_message_len = 0;
  uchar *padded_message = pad_message(message, &padded_message_len);

  if (!padded_message)
    return;

  uchar buffer[64];

  for (uint32_t i = 0; i < (padded_message_len / 64); i++) {

    memcpy(buffer, &padded_message[i * 64], 64);

    calc_dgst(buffer, d);
  }

  free(padded_message);
}

void calc_md5(const char message[], MD5 *md5) {

  MD5_DGST state;

  message_digest(message, &state);

  uint32_t hashes[4] = {state.a0, state.b0, state.c0, state.d0};

  for (int i = 0; i < 4; i++) {
    int k = 4 * i;
    md5->digest[k] = (hashes[i] & 0xff);
    md5->digest[k + 1] = ((hashes[i] >> 8) & 0xff);
    md5->digest[k + 2] = ((hashes[i] >> 16) & 0xff);
    md5->digest[k + 3] = ((hashes[i] >> 24) & 0xff);
  }

  for (int i = 0; i < 16; i++) {
    sprintf(&md5->hexstring[i * 2], "%02x", md5->digest[i]);
  }
  md5->hexstring[32] = '\0';
}

void calc_md5fromstate(MD5 *md5, MD5_DGST *state) {

  uint32_t hashes[4] = {state->a0, state->b0, state->c0, state->d0};

  for (int i = 0; i < 4; i++) {
    int k = 4 * i;
    md5->digest[k] = (hashes[i] & 0xff);
    md5->digest[k + 1] = ((hashes[i] >> 8) & 0xff);
    md5->digest[k + 2] = ((hashes[i] >> 16) & 0xff);
    md5->digest[k + 3] = ((hashes[i] >> 24) & 0xff);
  }

  for (int i = 0; i < 16; i++) {
    sprintf(&md5->hexstring[i * 2], "%02x", md5->digest[i]);
  }
  md5->hexstring[32] = '\0';
}
