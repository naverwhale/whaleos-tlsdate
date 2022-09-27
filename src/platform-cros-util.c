/*
 * platform-cros-util.c - Utility code for platform-cros.c
 * Copyright 2017 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "config.h"

#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "src/util.h"

static
bool
get_valid_hostport (const char *hostport, char *out, size_t len)
{
  bool host = true;
  const char *end = hostport + strlen (hostport);
  const char *c;
  *out = '\0';
  /* Hosts begin with alphanumeric only. */
  if (!isalnum (*hostport))
    {
      info ("Host does not start with alnum");
      return false;
    }
  *out++ = *hostport;
  /* Break on spaces and semicolons, either of which can indicate the end of the
   * first proxy within a list. */
  for (c = hostport + 1; c < end && len > 0 && *c != ' ' && *c != ';';
       ++c, ++out, --len)
    {
      *out = *c;
      if (host)
        {
          if (isalnum (*c) || *c == '-' || *c == '.')
            {
              continue;
            }
          if (*c == ':')
            {
              host = false;
              continue;
            }
        }
      else
        {
          if (isdigit (*c))
            continue;
        }
      *out = '\0';
      return false;
    }
  *out = '\0';
  return true;
}

/* TODO(wad) support multiple proxies when Chromium does:
 * PROXY x.x.x.x:yyyy; PROXY z.z.z.z:aaaaa
 */
void canonicalize_pac (const char *pac_fmt, char *proxy_url, size_t len)
{
  size_t type_len;
  size_t copied = 0;
  const char *space;
  /* host[255]:port[6]\0 */
  char hostport[6 + 255 + 2];
  proxy_url[0] = '\0';
  if (len < 1)
    return;
  if (!strcmp (pac_fmt, "DIRECT"))
    {
      return;
    }
  /* Find type */
  space = strchr (pac_fmt, ' ');
  if (!space)
    return;
  type_len = space - pac_fmt;
  if (!get_valid_hostport (space + 1, hostport, sizeof (hostport)))
    {
      error ("invalid host:port: %s", space + 1);
      return;
    }
  proxy_url[0] = '\0';
  if (!strncmp (pac_fmt, "PROXY", type_len))
    {
      copied = snprintf (proxy_url, len, "http://%s", hostport);
    }
  else if (!strncmp (pac_fmt, "SOCKS", type_len))
    {
      copied = snprintf (proxy_url, len, "socks4://%s", hostport);
    }
  else if (!strncmp (pac_fmt, "SOCKS5", type_len))
    {
      copied = snprintf (proxy_url, len, "socks5://%s", hostport);
    }
  else if (!strncmp (pac_fmt, "HTTPS", type_len))
    {
      copied = snprintf (proxy_url, len, "https://%s", hostport);
    }
  else
    {
      error ("pac_fmt unmatched: '%s' %zu", pac_fmt, type_len);
    }
  if (copied >= len)
    {
      error ("canonicalize_pac: truncation '%s'", proxy_url);
      proxy_url[0] = '\0';
      return;
    }
}
