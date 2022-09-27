/*
 * platform-cros-unittest.c - CrOS platform unit tests
 * Copyright 2017 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "config.h"

#include <stdbool.h>
#include <string.h>

#include "src/platform-cros-util.h"
#include "src/test_harness.h"

#define ARRAYSIZE(a) (sizeof(a) / sizeof(a[0]))

/* Sigh, expected by util.c. */
int verbose = 0;

struct TestCase {
  /* Input PAC string. */
  const char *input_pac;
  /* Expected output. */
  const char *expected;
};

/* Runs the test case in |tc| using buffer |buf| of size |len|. */
static bool check_case(const struct TestCase* tc, char* buf, size_t len) {
  memset(buf, '\0', len);
  canonicalize_pac(tc->input_pac, buf, len);
  return strcmp(tc->expected, buf) == 0;
}

TEST(test_canonicalize_pac_parsing) {
  const struct TestCase kCases[] = {
    /* Well-formed PAC strings. */
    { "DIRECT", "" },
    { "PROXY proxy.example.com", "http://proxy.example.com" },
    { "PROXY proxy.example.com:", "http://proxy.example.com:" },
    { "PROXY proxy.example.com:1234", "http://proxy.example.com:1234" },
    { "PROXY proxy-2.example.com", "http://proxy-2.example.com" },
    { "PROXY 127.0.0.1:8080", "http://127.0.0.1:8080" },
    { "SOCKS proxy.example.com", "socks4://proxy.example.com" },
    { "SOCKS5 proxy.example.com", "socks5://proxy.example.com" },
    { "HTTPS proxy.example.com", "https://proxy.example.com" },
    /* Multiple proxies are separated by semicolons with optional spaces. */
    { "PROXY a.com:8080; PROXY b.com:8080", "http://a.com:8080" },
    { "PROXY a.com:8080 ; PROXY b.com:8080", "http://a.com:8080" },
    { "PROXY a.com; PROXY b.com", "http://a.com" },
    { "PROXY a.com ; PROXY b.com", "http://a.com" },
    { "PROXY a.com; DIRECT", "http://a.com" },
    /* Bad input should always result in an empty string. */
    { "", "" },
    { "BOGUS", "" },
    { "PROXY", "" },
    { "PROXYa", "" },
    { "PROXY ", "" },
    { "PROXY \n", "" },
    { "PROXY $.com", "" },
    { "PROXY proxy.example.com::123", "" },
    { "PROXY proxy.example.com!", "" },
    { "PROXY http://proxy.example.com", "" },
    { "PROXY proxy_2.example.com", "" },
    /* Don't permit empty strings at the beginning of a list. */
    { "; PROXY b.com", "" },
    { " ;PROXY b.com", "" },
  };

  char buf[256];
  size_t i;
  for (i = 0; i < ARRAYSIZE(kCases); ++i) {
    EXPECT_TRUE(check_case(&kCases[i], buf, ARRAYSIZE(buf))) {
      TH_LOG("PAC \"%s\": expected \"%s\", actual \"%s\"",
             kCases[i].input_pac, kCases[i].expected, buf);
    }
  }
}

TEST(test_canonicalize_pac_overflow) {
  const struct TestCase kCases[] = {
    /* Input that needs 15 chars or fewer should be permitted. */
    { "PROXY abcde", "http://abcde" },
    { "PROXY abcde:80", "http://abcde:80" },
    { "PROXY abcdef:8", "http://abcdef:8" },
    { "PROXY abcdefgh", "http://abcdefgh" },
    { "HTTPS abcdefg", "https://abcdefg" },
    /* Input that would take 16 chars (not leaving space for a terminating NUL)
     * should be dropped. */
    { "PROXY abcdefghi", "" },
    { "PROXY abcdefgh:", "" },
    { "HTTPS abcdefgh", "" },
  };

  char buf[16];
  size_t i;
  for (i = 0; i < ARRAYSIZE(kCases); ++i) {
    EXPECT_TRUE(check_case(&kCases[i], buf, ARRAYSIZE(buf))) {
      TH_LOG("PAC \"%s\": expected \"%s\", actual \"%s\"",
             kCases[i].input_pac, kCases[i].expected, buf);
    }
  }
}

TEST_HARNESS_MAIN
