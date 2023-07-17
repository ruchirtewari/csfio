/*
 ** CSFIO - Cryptographically Secure File I/O
 ** csfio.c developed by Stephen Lombardo (Zetetic LLC)
 ** sjlombardo at zetetic dot net
 ** http://zetetic.net
 **
 ** Copyright (c) 2008, ZETETIC LLC
 ** All rights reserved.
 **
 ** Redistribution and use in source and binary forms, with or without
 ** modification, are permitted provided that the following conditions are met:
 **     * Redistributions of source code must retain the above copyright
 **       notice, this list of conditions and the following disclaimer.
 **     * Redistributions in binary form must reproduce the above copyright
 **       notice, this list of conditions and the following disclaimer in the
 **       documentation and/or other materials provided with the distribution.
 **     * Neither the name of the ZETETIC LLC nor the
 **       names of its contributors may be used to endorse or promote products
 **       derived from this software without specific prior written permission.
 **
 ** THIS SOFTWARE IS PROVIDED BY ZETETIC LLC ''AS IS'' AND ANY
 ** EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 ** WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 ** DISCLAIMED. IN NO EVENT SHALL ZETETIC LLC BE LIABLE FOR ANY
 ** DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 ** (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 ** LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 ** ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 ** (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 ** SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 **
 */

//#pragma GCC diagnostic ignored

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include "csfio.h"
#include <arpa/inet.h>

/*
 defining CSF_DEBUG will produce copious trace output
 for debugging purposes
 */
#define CSF_DEBUG 0
#if CSF_DEBUG
#define TRACE1(X)       (printf(X) && fflush(stdout))
#define TRACE2(X,Y)       (printf(X,Y) && fflush(stdout))
#define TRACE3(X,Y,Z)       (printf(X,Y,Z) && fflush(stdout))
#define TRACE4(X,Y,Z,W)       (printf(X,Y,Z,W) && fflush(stdout))
#define TRACE5(X,Y,Z,W,V)       (printf(X,Y,Z,W,V) && fflush(stdout))
#define TRACE6(X,Y,Z,W,V,U)       (printf(X,Y,Z,W,V,U) && fflush(stdout))
#define TRACE7(X,Y,Z,W,V,U,T)       (printf(X,Y,Z,W,V,U,T) && fflush(stdout))
#else
#define TRACE1(X)
#define TRACE2(X,Y)
#define TRACE3(X,Y,Z)
#define TRACE4(X,Y,Z,W)
#define TRACE5(X,Y,Z,W,V)
#define TRACE6(X,Y,Z,W,V,U)
#define TRACE7(X,Y,Z,W,V,U,T)
#endif

#define RETRYCOUNT 3

static void *csf_malloc(int sz);
static void csf_free(void * buf, int sz);
static size_t csf_read_page(CSF_CTX *ctx, int pgno, void *data);
static size_t csf_write_page(CSF_CTX *ctx, int pgno, void *data, size_t data_sz);
static off_t csf_pageno_for_offset(CSF_CTX *ctx, int offset);
static int csf_page_count_for_length(CSF_CTX *ctx, int length);
static int csf_page_count_for_file(CSF_CTX *ctx);

static void print_iv(unsigned char *iv, int pgno);
static void print_header(unsigned char *header, int pgno);
static size_t lower_cutoff(size_t req_end, size_t page_end, size_t file_end);

static size_t csf_write_header(CSF_CTX *ctx);
static int csf_read_header(CSF_CTX *ctx, CSF_FILE_HEADER *cfh);

static void print_iv(unsigned char *iv, int pgno) {
    int i = 0;
//    printf("iv for pg%d is: ", pgno);
    for(i = 0 ; i < 64 ; i++ ) {
        unsigned char c1, c2, curr = *(iv+i);
        c1 = curr & 0xF0;
        c2 = curr & 0x0F;
//        printf("%x%x ", c1>>4, c2);
    }
//    printf("\n");
}

static void print_header(unsigned char *hdr, int pgno) {
    int i = 0;
//    printf("header for pg%d is: ", pgno);
    for(i = 0 ; i < 16 ; i++ ) {
        unsigned char c1, c2, curr = *(hdr+i);
        c1 = curr & 0xF0;
        c2 = curr & 0x0F;
//        printf("%x%x", c1>>4, c2);
//        printf("%s", ( (i+1)%4) ? "-":" ");
    }
//    printf("\n");
}


/*
 * create a CSF context - initialize enc state and bounds for page, data, header sizes
 * given:
 *  file handle
 *  key data
 *  key size
 *  page size
 */
int csf_ctx_init(CSF_CTX **ctx_out, int fh, unsigned char *keydata, int key_sz, int page_sz, int flags) {
    EVP_CIPHER_CTX ectx;
    CSF_CTX *ctx;

    TRACE2("in csf_ctx_init fh=%d\n", fh);
    ctx = csf_malloc(sizeof(CSF_CTX));
    ctx->seek_ptr = ctx->file_sz = 0;
    ctx->fh = fh;

    ctx->key_sz = key_sz;
    ctx->key_data = csf_malloc(ctx->key_sz);
    memcpy(ctx->key_data, keydata, ctx->key_sz);

    EVP_EncryptInit(&ectx, CIPHER, ctx->key_data, NULL);
    ctx->block_sz = EVP_CIPHER_CTX_block_size(&ectx);
    ctx->iv_sz = EVP_CIPHER_CTX_iv_length(&ectx);

    /* the combined page size includes the size of the initialization
     vector, an integer for the count of bytes on page, and the data block */
    ctx->page_sz = page_sz;

    /* ensure the page header allocation ends on an even block alignment */
    ctx->page_header_sz = (sizeof(CSF_PAGE_HEADER) % ctx->block_sz == 0) ?
    (sizeof(CSF_PAGE_HEADER) / ctx->block_sz) :
    (sizeof(CSF_PAGE_HEADER) / ctx->block_sz) + ctx->block_sz;

    /* determine unused space avaliable for data */
    ctx->data_sz = ctx->page_sz - ctx->iv_sz - ctx->page_header_sz;

    assert(ctx->iv_sz %  ctx->block_sz == 0);
    assert(ctx->page_header_sz %  ctx->block_sz == 0);
    assert(ctx->data_sz %  ctx->block_sz == 0);
    assert(ctx->page_sz %  ctx->block_sz == 0);

    ctx->page_buffer = csf_malloc(ctx->page_sz);
    ctx->csf_buffer = csf_malloc(ctx->page_sz);
    ctx->scratch_buffer = csf_malloc(ctx->page_sz);

    EVP_CIPHER_CTX_cleanup(&ectx);

    ctx->encrypted=1;
    ctx->file_header_check=0;

    ctx->fileFlag = flags;
    ctx->seekPastEndOfFile = 0;

    TRACE7("csf_init() ctx->page_header_sz=%d ctx->data_sz=%d, ctx->page_sz=%d, ctx->block_sz=%d, ctx->iv_sz=%d, ctx->key_sz=%d\n", ctx->page_header_sz, ctx->data_sz, ctx->page_sz, ctx->block_sz, ctx->iv_sz, ctx->key_sz);

    *ctx_out = ctx;
    return 0;
}

int csf_ctx_destroy(CSF_CTX *ctx) {
    if (ctx) {
        csf_free(ctx->page_buffer, ctx->page_sz);
        csf_free(ctx->csf_buffer, ctx->page_sz);
        csf_free(ctx->scratch_buffer, ctx->page_sz);
        csf_free(ctx->key_data, ctx->key_sz);
        csf_free(ctx, sizeof(CSF_CTX));
    }
    return 0;
}

/* initialize a file header */
static int csf_create_file_header(CSF_CTX *ctx, CSF_FILE_HEADER *header) {
    header->version  = htonl(VERSION_1001);
    header->magic    = htonl(FILE_MAGIC_NUM);
    header->cipher   = htonl(CIPHER_HEX_STRING);
    header->pagesize = htonl(ctx->page_sz);
    return 0;
}

/*
 * determine the original file size given an encrypted file
 * the last page needs to be decrypted to determine its size
 * returns -1 on failure to read file (header mismatch or I/O error)
 */
off_t csf_file_size(CSF_CTX *ctx) {
    TRACE1("in csf_file_size\n");
    int page_count = csf_page_count_for_file(ctx);
    int data_sz = csf_read_page(ctx, page_count-1, ctx->page_buffer);
    if(data_sz<0)
        return -1;

    if (page_count ==0) {
        return data_sz;
    }
    return ((page_count - 1) * ctx->data_sz) + data_sz;
}

/*
 * total number of csf pages in the encrypted file
 * save current seek pointer, seek to end of file to find length
 * reset the seek pointer to saved. what if someone else does read/write ?
 */
static int csf_page_count_for_file(CSF_CTX *ctx) {
    TRACE1("in csf_page_count_for_file\n");
    size_t cur_offset = lseek(ctx->fh, 0, SEEK_CUR);
    size_t count = (lseek(ctx->fh, 0, SEEK_END) - HDR_SZ) / ctx->page_sz;
    lseek(ctx->fh, cur_offset, SEEK_SET);
    return count;
}

/*
 * file offset -> csfio pageno in which it falls
 */
static off_t csf_pageno_for_offset(CSF_CTX *ctx, int offset) {
    TRACE1("in csf_pageno_for_offset\n");
    return (offset / ctx->data_sz);
}

/*
 * count of csfio pages for amount of data = length
 * extra page if not page aligned.
 * independant of initial offset.
 */
static int csf_page_count_for_length(CSF_CTX *ctx, int length) {
    int count = (length / ctx->data_sz);
    TRACE1("in csf_page_count_for_length\n");
    if ( (length % ctx->data_sz) != 0 ) {
        count++;
    }
    return count;
}

/*
 * is this correct ? it truncates the page numbers to the last page
 * but does it update the page size in the header ?
 */
int csf_truncate(CSF_CTX *ctx, int offset) {
    int true_offset = HDR_SZ + (csf_pageno_for_offset(ctx, offset) * ctx->page_sz);
    TRACE4("csf_truncate(%d,%d), retval = %d\n", ctx->fh, offset, true_offset);
    return ftruncate(ctx->fh, true_offset);
}

/* FIXME - what happens when you seek past end of file? */
/* returns new seek pointer */
/* seek offset does not change in case of read error */
off_t csf_seek(CSF_CTX *ctx, off_t offset, int whence) {
    off_t target_offset = 0;
    int size=0;

    TRACE3("in csf_seek %ld %d\n", offset, whence);
    switch(whence) {
        case SEEK_SET:
            target_offset = offset;
            break;
        case SEEK_CUR:
            target_offset = ctx->seek_ptr + offset;
            break;
        case SEEK_END:
            size = csf_file_size(ctx);
            if(size <0) { // seek offset does not change in case of lseek error
                target_offset = ctx->seek_ptr;
//                printf("csf_seek error: %d\n", size);
            } else {
                target_offset = size + offset;
            }
            break;
        default:
            return -1;
    }
//    off_t fileSize = csf_file_size(ctx);
//    if (fileSize >= target_offset) {
        ctx->seek_ptr = target_offset;

        TRACE5("csf_seek(%d,%lld,%d), ctx->seek_ptr = %lld\n", ctx->fh, offset, whence, ctx->seek_ptr);
        return ctx->seek_ptr;
//    }
//    else {
//        ctx->seek_ptr = target_offset;
//        errno = EFBIG;
//        ctx->seek_ptr = fileSize;
//        return 0;
//    }
//    return -1;
}

/* reads single page (data of size data_sz, header of size page_header_sz) from an encrypted file which is in csf format.
 * returns only the data portion (max is data_sz = page_size - iv_size -header_size ) in data buffer
 * returns actual number of bytes read, in retval
 * pgno is the offset in csf pages
 * first 16 bytes in the csf page is the IV
 * after that we have encrypted data, which includes both the page header and page data
 * page header is in the beginning of the decrypted buffer
 */
static size_t csf_read_page(CSF_CTX *ctx, int pgno, void *data) {

    if (pgno < 0) {
        //If page number is negative that means file is empty.
        return 0;
    }

    off_t start_offset = HDR_SZ + (pgno * ctx->page_sz);
    off_t cur_offset =  lseek(ctx->fh, 0L, SEEK_CUR);
    int to_read = ctx->page_sz;
    size_t read_sz = 0;
    CSF_PAGE_HEADER header;

    TRACE1("in csf_read_page\n");
    // go to right offset to read the page, if not already there
    if(cur_offset != start_offset) {
        cur_offset = lseek(ctx->fh, start_offset, SEEK_SET);
    }
    int read_any_data = 0;
    // read page in csf format
    // error handling :
    // try three times. if we fail all three times, print error and return -1.
    for(;read_sz < to_read;) {
        ssize_t bytes_read;
        int trycount = RETRYCOUNT;
        errno = 0;
        while( (bytes_read = read(ctx->fh, ctx->page_buffer + read_sz, to_read - read_sz)) <0 && trycount-- >0  ) {// try again
            errno = 0;
        }
        if(bytes_read < 0) {
            // we have a read error after 3 tries.
            // if we have read partial data. there will be corruption on decryption.
            // if we have not read any data, we have a shot at decrypting data still in memory.
            // this is to handle a common case of files opened write-only. bmax-4229
            if (read_any_data) {
//                printf("csf_read_page received an error after read: %d\n", errno);
                return 0;
            } else {
//                printf("csf_read_page received an error: %d\n", errno);
                break;
            }
        }
        read_any_data = 1;

        read_sz += bytes_read;
        if(bytes_read < 1) {
            return 0;
        }
    }

    //printf("ruchir==>\n");
    // show the IV
    //print_iv(ctx->page_buffer, pgno);

    if(ctx->encrypted) {

        EVP_CIPHER_CTX ectx;
        void *out_ptr =  ctx->scratch_buffer;
        int out_sz, cipher_sz = 0;

        // pass in the cipher
        EVP_CipherInit(&ectx, CIPHER, NULL, NULL, 0);
        EVP_CIPHER_CTX_set_padding(&ectx, 0);

        // pass in the key and IV, ask to decrypt
        EVP_CipherInit(&ectx, NULL, ctx->key_data, ctx->page_buffer, 0);

        // output is in out_ptr, which is scratch_buffer; input is page_buffer+iv_sz of size (header_sz+data)
        // printf("input is : %d ", ctx->page_header_sz + ctx->data_sz); print_iv(ctx->page_buffer + ctx->iv_sz, pgno);
        EVP_CipherUpdate(&ectx, out_ptr + cipher_sz, &out_sz, ctx->page_buffer + ctx->iv_sz, ctx->page_header_sz + ctx->data_sz);
        cipher_sz += out_sz;
        EVP_CipherFinal(&ectx, out_ptr + cipher_sz, &out_sz);
        cipher_sz += out_sz;
        EVP_CIPHER_CTX_cleanup(&ectx);
        assert(cipher_sz == (ctx->page_header_sz + ctx->data_sz));
    } else {
        memcpy(ctx->scratch_buffer, ctx->page_buffer + ctx->iv_sz, ctx->page_header_sz + ctx->data_sz);
    }
    //printf("csf_read_page(%d,%d,x), cur_offset=%lld, read_sz=%ld, return_ds=%ld, sizeof(header)=%d s1=%d s2=%d\n", ctx->fh, pgno, cur_offset, read_sz, header.data_sz, sizeof(header), sizeof(header.data_sz), sizeof(header.magic));

    //print_header(ctx->scratch_buffer, pgno);

    memcpy(&header, ctx->scratch_buffer, sizeof(header));

    // handle incorrect headers (due to empty file or incorrect decryption - say invalid key)
    if(header.data_sz>ctx->data_sz) {
//        printf("header size invalid: %ld %d %d\n", header.data_sz, ctx->data_sz, pgno);
        header.data_sz = ctx->data_sz;
        header.data_sz = 0;
    }
    if (header.magic != PAGE_MAGIC_NUM) {
//        printf("magic number mismatch: %ld %d %ld %x\n", header.magic, PAGE_MAGIC_NUM, header.magic, PAGE_MAGIC_NUM);
        header.data_sz = 0;
        //header.data_sz = ctx->data_sz;
    }
    memcpy(data, ctx->scratch_buffer + ctx->page_header_sz, header.data_sz);

    TRACE6("csf_read_page(%d,%d,x), cur_offset=%lld, read_sz=%ld, return=%ld\n", ctx->fh, pgno, cur_offset, read_sz, header.data_sz);

    return header.data_sz;
}

/* writes single page (data of size data_sz, header of size page_header_sz)
 * to an encrypted file which in csf format, after the bitz header
 * pgno is the offset in csf pages
 * first 16 bytes in the csf page is the IV
 * after that we have encrypted data, consisting of both the page header and page data
 * seeks to the right csf page offset before writing
 *
 * encrypted write is all or none - if the write fails, the entire page write fails.
 * return -1 on failure
 */
static size_t csf_write_page(CSF_CTX *ctx, int pgno, void *data, size_t data_sz) {
    off_t start_offset = HDR_SZ + (pgno * ctx->page_sz);
    off_t cur_offset =  lseek(ctx->fh, 0L, SEEK_CUR);
    int to_write = ctx->page_sz;
    size_t write_sz = 0;
    CSF_PAGE_HEADER header;

    TRACE1("in csf_write_page\n");
    assert(data_sz <= ctx->data_sz);

    // create the header with data size
    header.data_sz = data_sz;
    header.magic = PAGE_MAGIC_NUM;

    // create the random IV for the page, directly into page_buffer
    int testing = 0;
    if(testing)
        bzero(ctx->page_buffer,  ctx->iv_sz);
    else
        RAND_pseudo_bytes(ctx->page_buffer, ctx->iv_sz);

    //print_iv(ctx->page_buffer, pgno);

    // copy header and data to the scratch buffer
    memcpy(ctx->scratch_buffer, &header, sizeof(header));
    memcpy(ctx->scratch_buffer + ctx->page_header_sz, data, data_sz);
    //print_iv(ctx->scratch_buffer, pgno); // before encryption

    // encrypt the scratch buffer (header+data) in memory only, into page_buffer, right after IV
    if(ctx->encrypted) {
        EVP_CIPHER_CTX ectx;
        void *out_ptr =  ctx->page_buffer + ctx->iv_sz;
        int out_sz, cipher_sz = 0;

        // init the cipher
        EVP_CipherInit(&ectx, CIPHER, NULL, NULL, 1);
        EVP_CIPHER_CTX_set_padding(&ectx, 0);

        // pass in the key and IV and ask to encrypt
        EVP_CipherInit(&ectx, NULL, ctx->key_data, ctx->page_buffer, 1);

        // start output after page_buf+iv_sz
        EVP_CipherUpdate(&ectx, out_ptr + cipher_sz, &out_sz, ctx->scratch_buffer, ctx->page_header_sz + ctx->data_sz);
        cipher_sz += out_sz;
        EVP_CipherFinal(&ectx, out_ptr + cipher_sz, &out_sz);
        cipher_sz += out_sz;
        EVP_CIPHER_CTX_cleanup(&ectx);
        assert(cipher_sz == (ctx->page_header_sz + ctx->data_sz));
        //printf(" encrypted val: "); print_iv(ctx->page_buffer+ctx->iv_sz, pgno);
    } else {
        memcpy(ctx->page_buffer + ctx->iv_sz, ctx->scratch_buffer, ctx->page_header_sz + ctx->data_sz);
    }

    // after encryption
    //print_iv(ctx->page_buffer, pgno);

    // if not already in proper position for page, seek there
    if(cur_offset != start_offset) {
        errno = 0;
        cur_offset = lseek(ctx->fh, start_offset, SEEK_SET);
        // check the above seek is valid.  else output is corrupted.
        if(errno) {
//            printf("error %d seeking to right offset %lld during write to fd=%d\n", errno, start_offset, ctx->fh);
            return -1;
        }
    }

    // write out entire page into the output file handle, on the seek location set at page boundary.
    for(;write_sz < to_write;) { /* FIXME - error handling */
        int trycount = RETRYCOUNT;
        ssize_t bytes_write;

        errno = 0;
        while( ((bytes_write = write(ctx->fh, ctx->page_buffer + write_sz, to_write - write_sz)))<0 && trycount-- >0 ) {
            errno = 0;
        }

        if(bytes_write < 0) { // we have a write error after 3 tries
            if(errno) {
//                printf("csf_write_page write received an error: %d\n", errno);
            }
            return -1;
        }
        write_sz += bytes_write;
    }

    TRACE6("csf_write_page(%d,%d,x,%ld), cur_offset=%lld, write_sz= %ld\n", ctx->fh, pgno, data_sz, cur_offset, write_sz);

    return data_sz;
}

static size_t lower_cutoff(size_t req_end, size_t page_end, size_t file_end) {
    size_t lowest = (req_end < page_end) ? req_end : page_end;
    lowest = (lowest < file_end) ? lowest: file_end;
    return lowest;
}

/* read from an encrypted file nbyte bytes of data into data buffer
 * max size of data returned is not data_sz or page_sz, it can be larger
 * it reads each csf page in which the data resides and copies them into one buffer
 * returns number of bytes read on success
 * returns -1 on failures
 *    - file header mismatch
 *    - page magic mismatch
 */
size_t csf_read(CSF_CTX *ctx, void *databuf, size_t nbyte) {

    TRACE1("csf_read()\n");
    // starting point is the current seek pointer
    // starting csf page
    const int start_page = csf_pageno_for_offset(ctx, ctx->seek_ptr);

    // starting offset translated to offset within the page
    int start_offset = ctx->seek_ptr % ctx->data_sz;
    //int first_start_offset = start_offset; // how much to subtract from last read

    // this is the last byte to read, starting from current page, offset 0
    // used to determine number of pages to iterate over in loop below
    int lastbyte_to_read = nbyte + start_offset;
    const int pages_to_read = csf_page_count_for_length(ctx, lastbyte_to_read);

    // now lastbyte_to_read tracks the number of bytes left to read
    // it is updated after every page read, relative to start of current page.
    lastbyte_to_read = nbyte;

    // total page count for file.
    // used as bounds check over the loop, to avoid read past last page
    // that check should really be for page_count minus start_page
    int total_page_count = csf_page_count_for_file(ctx);
    int page_count_to_EOF = total_page_count - start_page;
    int i, data_offset = 0;
    int total_bytes_read = 0;
    CSF_FILE_HEADER cfh;

    // in case we do this for every read, we need to save the seek ptr to 0, then reset back
    // optimization to do it only for file reads already at start.
    int retval = 0;
    if(ctx->seek_ptr==0 && total_page_count>0) {
        retval = csf_read_header(ctx, &cfh);
        if(retval<0) {
//            printf("error reading header: %d\n",retval);
            return retval;
        }
    }

    // loop over csf pages to read, reading them in entirety using csf_read_page
    // modifies ctx->fh->seek pointer to beginning of each page at the beginning of each read (prob with multiple reads ? no)
    // modifies ctx->fh->seek pointer to last valid byte within each page after each iteration
    // modifies ctx->seek_ptr to bytes moved forward
    // printf("in csf_read (seek=%ld, size=%d)=>([startpage=%d startoff=%d], [pages_to_read=%d, lastbyteoff=%d])\n" ,
    //    (unsigned int)(ctx->seek_ptr), nbyte,   start_page, start_offset,  pages_to_read, lastbyte_to_read);

    for(i = 0; i < pages_to_read && i < total_page_count; i++) { /* dont read past end of file */

        if(i > page_count_to_EOF) {
//            printf("=========> reading page past EOF\n");
            ctx->seekPastEndOfFile = 1;
        }
        //printf("=========>pgno=%d seekptr=%ld\n", start_page+i, (ctx->seek_ptr));

        // read in the full page in csf_buffer, startng from page offset 0 to ctx->data_sz (not fh->seek)
        // retval which indicates bytes available comes from the header value
        // if it is less than data_sz, then that's the max amount of data we can read.
        int data_bytes_in_page = csf_read_page(ctx, start_page + i, ctx->csf_buffer);

        if(data_bytes_in_page <0) // error in read of current page
            break;

        // we want to find how much data to read within each page
        // startpoint is determined by
        //  1. current seek pointer
        // endpoint is determined by min of
        //  1. user request (lastbyte_to_read)
        //  2. end of page  (ctx->data_sz)
        //  3. end of file  (data_bytes_in_page)
        // after read we know 3, so now we know all parameters

        // if last byte is less than max data size, then use that lower value, otherwise read max data size
        // this isn't actually passed to csf_read_page, which reads the entire page
        // it is used by us to determine the relevant data. that may be modified by the actual size available within page
        // lastbyte_within_page needs to relative to the start_offset if it is smaller than pgsz
        size_t lastbyte_within_page = (lastbyte_to_read < ctx->data_sz) ? lastbyte_to_read+start_offset: lastbyte_to_read;

        size_t endcutoff = lower_cutoff(lastbyte_within_page, ctx->data_sz, data_bytes_in_page);
        //printf("===== endcutoff is %d start_offset is %d\n", endcutoff, start_offset);

        if(endcutoff > start_offset) {
            size_t bytes_to_copy = endcutoff - start_offset;
            //printf("===== bytes to copy ares %d %d %d %d\n", bytes_to_copy, lastbyte_to_read, ctx->data_sz, data_bytes_in_page);
            memcpy(databuf + data_offset, ctx->csf_buffer + start_offset, bytes_to_copy);

            lastbyte_to_read -=  bytes_to_copy;
            total_bytes_read +=  bytes_to_copy;
            data_offset += bytes_to_copy;
            ctx->seek_ptr += bytes_to_copy;
            start_offset = 0; /* after the first iteration the start offset will always be at the beginning of the page */
            memset(ctx->csf_buffer, 0, ctx->page_sz);
        } else {
            // printf("breaking at EOF\n");
            // we hit a page where the available data is less than our start offset for read
            // this would indicate EOF so we break.
            // doing this we should be able to avoid the earlier file size check
            break;
        }
    }

    TRACE6("csf_read(%d,x,%ld), pages_to_read = %d, ctx->seek_ptr = %lld, return=%d\n", ctx->fh, nbyte, pages_to_read, ctx->seek_ptr, data_offset);
    return total_bytes_read;
}

/* write out the file header. must be all or nothing */
/* first check if it exists. seeks to beginning of files, restores seek at end */
/* returns number of bytes written */
/* in case of a error returns -1 */
static size_t csf_write_header(CSF_CTX *ctx) {
    int write_sz=0;
    CSF_FILE_HEADER cfh;
    unsigned char header[HDR_SZ];

    if(HDR_SZ==0)
        return 0;

    int existing_bytes = csf_read_header(ctx, &cfh);
    if(existing_bytes >0) {
        //printf("successfully read header\n");
        return existing_bytes;
    }
    else {
//        printf("error reading header, creating new one\n");
    }

    off_t cur_offset = lseek(ctx->fh, 0, SEEK_CUR);
    if(cur_offset != 0) {
        lseek(ctx->fh, 0, SEEK_SET);
    }

    memset(header, 0, HDR_SZ);
    csf_create_file_header(ctx, &cfh);
    memcpy(header, (void *)&cfh, HDR_SZ);
    for(;write_sz < HDR_SZ;) { /* FIXME - error handling */
        int trycount = RETRYCOUNT;
        ssize_t bytes_write;
        errno = 0;
        while( (bytes_write = write(ctx->fh, header, HDR_SZ-write_sz)) <0 && trycount-- >0) {
            // try again
            errno = 0;
        }
        if(bytes_write < 0) {
            if(errno) {
//                printf("csf_write_header write received an error: %d\n", errno);
            }
            return -1;
        }
        write_sz += bytes_write;
        //printf("wrote n bytes of header: %d\n", write_sz);
    }
    ctx->file_header_check = 1;

    // reset it back
    lseek(ctx->fh, cur_offset, SEEK_SET);
    return write_sz;
}

/* read in the file header
 * should be possible to do it before creating ctx, to check file type and read page size.
 * returns number of bytes read in case of success
 * returns -1 if there is an error
 */
static int csf_read_header(CSF_CTX *ctx, CSF_FILE_HEADER *cfh) {
    ssize_t bytes_read=0, read_sz=0;
    unsigned char header[HDR_SZ];

    if(HDR_SZ==0)
        return 0;

    //printf("csf_read_header fh=%d seek=%d\n", ctx->fh, ctx->seek_ptr);

    // error handling : try 3 times and return error if it still fails.
    for(;read_sz < HDR_SZ;) {
        int trycount = RETRYCOUNT;
        errno = 0;
        while( (bytes_read = read(ctx->fh, header, HDR_SZ-read_sz)) <0 && trycount-- >0  ) {
            // try again
            // printf("error on read header: %d %d\n", errno, trycount);
            errno = 0;
        }
        //printf("tried: %d %d %d %d\n", trycount, bytes_read, errno, ctx->fh);
        if(bytes_read < 0) { // we have a read error after 3 tries.
            // we cannot continue else read buffer will be corrupted.
            if(errno) {
            //  printf("csf_read_header read received an error: %d\n", errno);
            }
            return -1;
        }
        if(bytes_read == 0) { // no error but we are at EOF. new file
            return 0;
        }
        read_sz += bytes_read;
        //printf("read n bytes of header: %d\n", read_sz);
    }

    memcpy((void*)cfh, header, HDR_SZ);
    //printf("header values1 vers=%x magic=%x cipher=%x pgsize=%d cmpmagic=%x\n", cfh->version, cfh->magic, cfh->cipher, cfh->pagesize, FILE_MAGIC_NUM);
    cfh->version = ntohl(cfh->version);
    cfh->magic = ntohl(cfh->magic);
    cfh->cipher = ntohl(cfh->cipher);
    cfh->pagesize = ntohl(cfh->pagesize);
    if(cfh->magic != FILE_MAGIC_NUM) {
        //printf("header values vers=%x magic=%x cipher=%x pgsize=%d cmpmagic=%x\n", cfh->version, cfh->magic, cfh->cipher, cfh->pagesize, FILE_MAGIC_NUM);
        // printf("not a bitzer file\n");
        return -1;
    }
    ctx->file_header_check = 1;
    return 0;
}

/*
 * write out set of encrypted pages to file
 */
size_t csf_write(CSF_CTX *ctx, const void *data, size_t nbyte) {
    int start_page = csf_pageno_for_offset(ctx, ctx->seek_ptr);
    int start_offset = ctx->seek_ptr % ctx->data_sz;
    int to_write = nbyte + start_offset;
    int pages_to_write = csf_page_count_for_length(ctx, to_write);
    int i, data_offset = 0;
    int page_count = csf_page_count_for_file(ctx);

    TRACE2("in csf_write %d\n", ctx->file_header_check);

    // write out the header.
    // if there is an error, caller must try again.
    if(ctx->file_header_check == 0) {
        //printf("writing file header\n");
        int hdrbytes_written = 0;
        hdrbytes_written = csf_write_header(ctx);
        if(hdrbytes_written < 0 || hdrbytes_written < HDR_SZ)
            return -1;
    }

    // TBD: Error handling for writes of empty pages.
    if(start_page > page_count) {
        /* this is a seek past end of file. we need to fill in the gap. sorry no sparse files */
        int i;

        /* start by rewriting the current end page */
        if(page_count > 0) {
            size_t data_sz = csf_read_page(ctx, page_count-1, ctx->csf_buffer);
            memset(ctx->csf_buffer + data_sz, 0, ctx->data_sz - data_sz); /* back fill an unused data on page with zeros */
            data_sz = csf_write_page(ctx, page_count-1, ctx->csf_buffer, ctx->data_sz);
            assert(data_sz == ctx->data_sz);
        }

        /* loop through the next page on through the n-1 page, fill up with zero data */
        memset(ctx->csf_buffer, 0, ctx->page_sz); // zero out the data!
        for(i = page_count; i < start_page - 1; i++) {
            csf_write_page(ctx, i, ctx->csf_buffer, ctx->data_sz);
        }

        /* take the last page, and write out the proper number of bytes to reach the target offset */
        csf_write_page(ctx, start_page-1, ctx->csf_buffer, ctx->seek_ptr % ctx->data_sz);
    }

    for(i = 0; i < pages_to_write; i++) {
        int data_sz = (to_write < ctx->data_sz ? to_write : ctx->data_sz);
        int l_data_sz = data_sz - start_offset;
        int bytes_write = 0;
        int cur_page_bytes = 0;

        if(page_count > (start_page + i)) {
            cur_page_bytes = csf_read_page(ctx, start_page + i, ctx->csf_buffer); /* FIXME error hndling */
            if(cur_page_bytes < 0) { // error reading in the page
            //  printf("csf_write_page: error reading page no=%d: errno=%d\n", start_page+i, errno);
            }
        } else {
            cur_page_bytes = 0;
        }

        memcpy(ctx->csf_buffer + start_offset, data + data_offset, l_data_sz);

        bytes_write = csf_write_page(ctx, start_page + i, ctx->csf_buffer, (data_sz < cur_page_bytes) ? cur_page_bytes : data_sz);

        if(bytes_write <0) { // write failure. stop writing further pages.
            // printf("csf_write_page received an error");
            break;
        }

        to_write -= bytes_write; /* to_write is already adjusted for start_offset */
        data_offset += l_data_sz;
        ctx->seek_ptr += l_data_sz;
        start_offset = 0; /* after the first iteration the start offset will always be at the beginning of the page */
        memset(ctx->csf_buffer, 0, ctx->page_sz);
    }

    TRACE6("csf_write(%d,x,%ld), pages_to_write = %d, ctx->seek_ptr = %lld, return=%d\n", ctx->fh, nbyte, pages_to_write, ctx->seek_ptr, data_offset);
    return data_offset;
}

/*
 input: size of the buffer to allocate
 */
static void *csf_malloc(int sz) {
    void *buf;
    buf = calloc(sz, 1);
    if(buf == NULL) {
        TRACE2("allocating %d bytes via malloc() in csf_malloc()\n", sz);
    }
    return buf;
}

/*
 input: the pointer to the malloc'd memory, and
 the lenght of the buffer to zero out
 */
static void csf_free(void * buf, int sz) {
    memset(buf, 0, sz);
    free(buf);
}


