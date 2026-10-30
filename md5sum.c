
/**
 * Author: Emmanuel J
 * Date : 30-10-2026
 * Description: calculate md5 digest for file
 */

#define _FILE_OFFSET_BITS 64

#include "md5.h"
#include "md5_file_io.h"
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, char *argv[]) {

  if (argc == 1) {
    printf("Usage: %s [FILES]...\n", argv[0]);
    return 1;
  }

  // md5_init();

  for (int i = 1; i < argc; i++) {

    FILE_METADATA file;
    snprintf(file.path, sizeof(file.path), "%s", argv[i]);

    file.sizeinbytes = getfilesize(file.path);
    if (file.sizeinbytes < 0) {
      fprintf(stderr, "%s: No such fire or directory\n", file.path);
      continue;
    }

    int fd = open(file.path, O_RDONLY);
    if (fd < 0) {
      fprintf(stderr, "%s: Permission denied\n", file.path);
      continue;
    }

    calc_file_md5(&fd, &file);

    printf("%s\n", file.hash.hexstring);

    close(fd);
  }

  return 0;
}
