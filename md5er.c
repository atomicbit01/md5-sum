

/**
 * Author: Emmanuel J
 * Date : 30-10-2026
 * Description: calculate md5 digest for message string
 */

#include "md5.h"

int main(int argc, char *argv[]) {

  if (argc == 1) {
    printf("Usage: %s \"string\"\n", argv[0]);
    return 1;
  }

  // initalize md5 algo constants

  for (int i = 1; i < argc; i++) {

    MD5 hash;

    calc_md5(argv[i], &hash);

    printf("[MD5] \'%s\': %s\n", argv[i], hash.hexstring);
  }

  return 0;
}
