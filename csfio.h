/*
 ** CSFIO - Cryptographically Secure File I/O
 ** csfio.h developed by Stephen Lombardo (Zetetic LLC)
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

#ifndef CSFIO_H
#define CSFIO_H

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "csfio.h"
#include <inttypes.h>

#define CIPHER EVP_aes_256_cbc()

#define FILE_MAGIC_NUM     0x4249545A
#define VERSION_1001       0x00001001
#define CIPHER_HEX_STRING  0x00AE5256

#define PAGE_MAGIC_NUM     0xCAFEBABE

#define HDR_SZ 0               // magic (4) + version (4) + cipher (4) + pagesize (4)

typedef struct {
    unsigned int magic;        // magic number
    unsigned int version;      // version number of encryption
    unsigned int cipher;       // cipher type
    unsigned int pagesize;     // page size
} CSF_FILE_HEADER;

typedef struct {
    int fh;
    off_t seek_ptr;    // current location in encrypted file
    off_t file_sz;     // not used, set to 0. could be set and saved in file header
    int encrypted;     // is true. set to 0 to test paging+headers, without encryption
    int key_sz;        // size of the encryption key. 256bits=32bytes for CIPHER=AES_256
    int data_sz;       // size of data within a page
    int block_sz;      // cipher block size. property of cipher
    int iv_sz;         // size of initialization vector. 16 bytes. created for each csf page.
    int page_header_sz;// 8 bytes below. 16 with alignment to 16 bytes.
    int page_sz;       // passed in as a user paramerter in ctx_init
    int file_header_check;        // 0 if file header is not yet written or checked. 1 if it is.
    unsigned char *key_data;      // file encryption/decryption key.
    unsigned char *page_buffer;   // raw csf page read from disk, of ctx->page_sz
    unsigned char *scratch_buffer;// used to encrypt/decrypt header+data portion
    unsigned char *csf_buffer;
    int fileFlag;      //Holds the file flag originally set by caller. If file is opened write only, we open file read/write for csfio seek purpose. To simulate correct file mode, we keep mode here and use it to simulate read/write protection.
    int seekPastEndOfFile;        //This flag will be set if seek/read is done past end of file;
} CSF_CTX;

/* total size is 8 bytes, which is less than 16 byte block sz, so another 8 bytes will be padded */
typedef struct {
    int32_t magic;       // unsigned int of 4 bytes
    int32_t data_sz;     // index of last byte of data on page
} CSF_PAGE_HEADER;

/* context init for file open and interceptors for other file i/o functions */
int csf_ctx_init(CSF_CTX **ctx_out, int fh, unsigned char *keydata, int key_sz, int page_sz, int flags);
int csf_truncate(CSF_CTX *ctx, int nByte);
off_t csf_seek(CSF_CTX *ctx, off_t offset, int whence);
size_t csf_read(CSF_CTX *ctx, void *buf, size_t nbyte);
size_t csf_write(CSF_CTX *ctx, const void *buf, size_t nbyte);
int csf_ctx_destroy(CSF_CTX *ctx);
off_t csf_file_size(CSF_CTX *ctx);

#endif
