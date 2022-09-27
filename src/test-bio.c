/*
 * test-bio.c - BIO layer for testing
 *
 * Copyright (c) 2012 The Chromium Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * This is a 'source/sink' BIO which supports synthetic inputs and outputs, and
 * can be used to drive filter BIOs through a state machine. It buffers all
 * output sent to it, which can be retrieved with BIO_test_get_output(), and
 * input sent to it, which is handed back in response to BIO_read() by the
 * filter BIO.
 */

#include <assert.h>
#include <string.h>

#include "src/openssl_compat.h"
#include "src/test-bio.h"
#include "src/util.h"

static const unsigned int kMagic = 0x5f8d3f15;

struct test_ctx
{
  unsigned int magic;
  unsigned char *out;
  size_t outsz;
  unsigned char *in;
  size_t insz;
};

static struct test_ctx *bio_ctx (BIO *b)
{
  struct test_ctx *ctx = BIO_get_data(b);
  assert (ctx->magic == kMagic);
  return ctx;
}

static size_t buf_drain (unsigned char **buf, size_t *bufsz,
                         unsigned char *out, size_t outsz)
{
  if (*bufsz < outsz)
    outsz = *bufsz;
  memcpy (out, *buf, outsz);
  if (*bufsz > outsz)
    memmove (*buf, *buf + outsz, *bufsz - outsz);
  *bufsz -= outsz;
  *buf = realloc (*buf, *bufsz);
  return outsz;
}

static void buf_fill (unsigned char **buf, size_t *bufsz,
                      const unsigned char *in, size_t insz)
{
  *buf = realloc (*buf, *bufsz + insz);
  memcpy (*buf + *bufsz, in, insz);
  *bufsz += insz;
}

int test_new (BIO *b)
{
  struct test_ctx *ctx = malloc (sizeof *ctx);
  if (!ctx)
    return 0;
  ctx->magic = kMagic;
  ctx->in = NULL;
  ctx->insz = 0;
  ctx->out = NULL;
  ctx->outsz = 0;
  BIO_set_init(b, 1);
  BIO_clear_flags(b, ~0);
  BIO_set_data(b, ctx);
  return 1;
}

int test_free (BIO *b)
{
  struct test_ctx *ctx;
  if (!b || !BIO_get_data(b))
    return 1;
  ctx = bio_ctx (b);
  free (ctx->in);
  free (ctx->out);
  return 1;
}

int test_write (BIO *b, const char *buf, int sz)
{
  struct test_ctx *ctx = bio_ctx (b);
  if (sz <= 0)
    return 0;
  buf_fill (&ctx->out, &ctx->outsz, (unsigned char *) buf, sz);
  return sz;
}

int test_read (BIO *b, char *buf, int sz)
{
  struct test_ctx *ctx = bio_ctx (b);
  if (sz <= 0)
    return 0;
  return buf_drain (&ctx->in, &ctx->insz, (unsigned char *) buf, sz);
}

long test_ctrl (BIO *b, int cmd, long num, void *ptr)
{
  return 0;
}

long test_callback_ctrl (BIO *b, int cmd, bio_info_cb *fp)
{
  return 0;
}

#if OPENSSL_VERSION_NUMBER < 0x10100000L

BIO_METHOD test_methods =
{
  BIO_TYPE_SOCKET,
  "test",
  test_write,
  test_read,
  NULL,
  NULL,
  test_ctrl,
  test_new,
  test_free,
  test_callback_ctrl,
};

BIO_METHOD *BIO_s_test()
{
  return &test_methods;
}

#else

BIO_METHOD *BIO_s_test()
{
  /* We leak a singleton BIO_METHOD here. */
  static BIO_METHOD *test_method;

  if (!test_method) {
    int index;

    index = BIO_get_new_index() | BIO_TYPE_SOURCE_SINK | BIO_TYPE_DESCRIPTOR;
    test_method = BIO_meth_new (index, "test");
    BIO_meth_set_write (test_method, test_write);
    BIO_meth_set_read (test_method, test_read);
    BIO_meth_set_puts (test_method, NULL);
    BIO_meth_set_gets (test_method, NULL);
    BIO_meth_set_ctrl (test_method, test_ctrl);
    BIO_meth_set_create (test_method, test_new);
    BIO_meth_set_destroy (test_method, test_free);
    BIO_meth_set_callback_ctrl (test_method, test_callback_ctrl);
  }

  return test_method;
}

#endif

BIO API *BIO_new_test()
{
  return BIO_new (BIO_s_test());
}

size_t API BIO_test_output_left (BIO *b)
{
  return bio_ctx (b)->outsz;
}

size_t API BIO_test_get_output (BIO *b, unsigned char *buf, size_t bufsz)
{
  struct test_ctx *c = bio_ctx (b);
  return buf_drain (&c->out, &c->outsz, buf, bufsz);
}

void API BIO_test_add_input (BIO *b, const unsigned char *buf, size_t bufsz)
{
  struct test_ctx *c = bio_ctx (b);
  return buf_fill (&c->in, &c->insz, buf, bufsz);
}
