/*
 * openssl_compat.h - OpenSSL 1.1 Compatibility Layer
 * Copyright 2019 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */
#ifndef SRC_OPENSSL_COMPAT_H_
#define SRC_OPENSSL_COMPAT_H_

#include <openssl/opensslv.h> /* For OPENSSL_VERSION_NUMBER */

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#include <openssl/bio.h>
#include <openssl/ssl.h>

static inline void BIO_set_data(BIO *a, void *ptr)
{
  a->ptr = ptr;
}

static inline void *BIO_get_data(BIO *a)
{
  return a->ptr;
}

static inline void BIO_set_init(BIO *a, int init)
{
  a->init = init;
}

static inline size_t SSL_get_server_random(const SSL *ssl, unsigned char *out,
                                           size_t outlen)
{
  size_t server_random_len = sizeof(ssl->s3->server_random);
  // Per https://www.openssl.org/docs/man1.1.0/ssl/SSL_get_server_random.html
  // If outlen is 0, return the maximum number of bytes that would be copied.
  if (!outlen)
    return server_random_len;
  if (outlen > server_random_len)
    outlen = server_random_len;
  memcpy(out, ssl->s3->server_random, outlen);
  return outlen;
}

#endif /* OPENSSL_VERSION_NUMBER < 0x10100000L */

#endif /* SRC_OPENSSL_COMPAT_H_ */
