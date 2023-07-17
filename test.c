#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "csfio.h"

#include <errno.h>

#define BLOCK_SIZE 512


/* read in an unencrypted file, encrypt it with a key */
int do_encrypt(int fdin, int fdout, unsigned char *key, int keylen){
  CSF_CTX *csf_ctx;

  //int read_size = 65536;
  int read_size = 1;
  char buffer[1024];
  int actual_read_size = 0;
  int total_read = 0;

  printf("sizeof header=%d\n", sizeof(CSF_PAGE_HEADER));
  printf("sizeof file header=%d\n", sizeof(CSF_FILE_HEADER));

  //csf_ctx_init(&csf_ctx, fdout, key, keylen, BLOCK_SIZE, "csfio.log");
  csf_ctx_init(&csf_ctx, fdout, key, keylen, BLOCK_SIZE, O_CREAT|O_RDWR);
  while( (actual_read_size=read(fdin, buffer, read_size)) >0 ) {
      //printf("we have read %d \n", actual_read_size);
      csf_write(csf_ctx, buffer, actual_read_size);
      total_read += actual_read_size;
  }
  csf_ctx_destroy(csf_ctx);
  return total_read;
}

// we need size of the original file to truncate it back to
/* read in an encrypted file, decrypt it with a key */
int do_decrypt(int fdin, int fdout, unsigned char *key, int keylen){
  CSF_CTX *csf_ctx;

  // must test with different read sizes for different edge cases
  //int read_size = BLOCK_SIZE/2;
  int read_size = 65536;
  //int read_size = BLOCK_SIZE;
  // this buffer needs to be larger as read can return more data than requested.
  //char buffer[70000];
  char buffer[100000];
  int actual_read_size = 0;
  int total_read;

  //csf_ctx_init(&csf_ctx, fdin, key, keylen, BLOCK_SIZE, "csfio.log");
  csf_ctx_init(&csf_ctx, fdin, key, keylen, BLOCK_SIZE, O_RDWR);
  while( (actual_read_size=csf_read(csf_ctx, buffer, read_size)) >0 ) {
      printf("we have read %d %d\n\n\n", actual_read_size, read_size);
      write(fdout, buffer, actual_read_size);
      /*if(actual_read_size > BLOCK_SIZE)
          write(fdout, buffer, BLOCK_SIZE);
      else
          write(fdout, buffer, actual_read_size);*/
      total_read +=actual_read_size;
  }
  csf_ctx_destroy(csf_ctx);
  return total_read;
}

// encrypt a file
int test_enc( char *inpath, char *outpath) {
   char *key="012345678901234567890123456789012";
   int keylen = 32;

   int fdin = open(inpath, O_RDWR);
   if(errno)
       printf("could not open file: %s %d %s\n", inpath,  errno, strerror(errno));
   int fdout = open(outpath, O_CREAT|O_RDWR);
   if(errno)
       printf("could not open file: %s %d %s\n", outpath, errno, strerror(errno));

   if(fdin<0 || fdout <0) {
    printf("could not open files\n");
    exit(0);
   }
   do_encrypt(fdin, fdout, key, keylen);

   close(fdin);
   close(fdout);
   chmod(outpath, S_IRWXU);
}

// decrypt a file
int test_dec( char *inpath, char *outpath) {
   char *key="012345678901234567890123456789012";
   int keylen = 32;

   int fdin = open(inpath, O_RDWR);
   if(errno)
       printf("could not open file: %s %d %s\n", inpath,  errno, strerror(errno));
   int fdout = open(outpath, O_CREAT|O_RDWR);
   if(errno)
       printf("could not open file: %s %d %s\n", outpath, errno, strerror(errno));

   if(fdin<0 || fdout <0) {
    printf("could not open files %s %d %s %d\n", inpath, fdin, outpath, fdout);
    exit(0);
   }
   do_decrypt(fdin, fdout, key, keylen);

   close(fdin);
   close(fdout);
   chmod(outpath, S_IRWXU);
}


int main(int argc, char **argv) {
   if(argc<2) {
     printf("test [-u] filename\n");
     return -1;
   }
   if(argc==2) { // encrypt the input file and save with .Z extension
       char *infile = argv[1];
       char *out = malloc(strlen(infile)+3);
       strcpy(out, infile);
       strcat(out, ".Z");
       printf("new file: %s\n", out);
       test_enc(infile, out);
   } else if(argc==3) { // decrypt the input file and save with .U extension
       char *infile = argv[2];
       char *out = malloc(strlen(infile)+3);
       strcpy(out, infile);
       strcat(out, ".U");
       printf("new file: %s\n", out);
       test_dec(infile, out);
   }
}
