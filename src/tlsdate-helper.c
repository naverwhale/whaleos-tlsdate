/* Copyright (c) 2012, Jacob Appelbaum.
 * Copyright (c) 2012, The Tor Project, Inc.
 * Copyright (c) 2012, Christian Grothoff. */
/* See LICENSE for licensing information */
/*
                    This file contains the license for tlsdate,
        a free software project to set your system clock securely.

        It also lists the licenses for other components used by tlsdate.

      For more information about tlsdate, see https://github.com/ioerror/tlsdate

             If you got this file as a part of a larger bundle,
        there may be other license terms that you should be aware of.

===============================================================================
tlsdate is distributed under this license:

Copyright (c) 2011-2012, Jacob Appelbaum <jacob@appelbaum.net>
Copyright (c) 2011-2012, The Tor Project, Inc.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

    * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.

    * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.

    * Neither the names of the copyright owners nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
===============================================================================
If you got tlsdate as a static binary with OpenSSL included, then you should
know:

 "This product includes software developed by the OpenSSL Project for use in
  the OpenSSL Toolkit (http://www.openssl.org/)"

===============================================================================
*/

/**
 * \file tlsdate-helper.c
 * \brief Helper program that does the actual work of setting the system clock.
 **/

/*
 * tlsdate is a tool for setting the system clock by hand or by communication
 * with the network. It does not set the RTC. It is designed to be as secure as
 * TLS (RFC 2246) but of course the security of TLS is often reduced to
 * whichever CA racket you believe is trustworthy. By default, tlsdate trusts
 * your local CA root store - so any of these companies could assist in a MITM
 * attack against you and you'd be screwed.

 * This tool is designed to be run by hand or as a system daemon. It must be
 * run as root or otherwise have the proper caps; it will not be able to set
 * the system time without running as root or another privileged user.
 */

#include "config.h"

#include "src/openssl_compat.h"
#include "src/tlsdate-helper.h"

#include <errno.h>
#include <netdb.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "src/proxy-bio.h"
#include "src/util.h"
#include "src/compat/clock.h"

static int g_ca_racket;

static const char *g_ca_cert_container;

// Target host to connect to.
static const char *g_host;

// Port to connect to on the target host.
static const char *g_port;

// The SSL/TLS protocol used
static const char *g_protocol;

// Proxy with format scheme://proxy_host:proxy_port.
static char *g_proxy;

static void
validate_proxy_scheme (const char *scheme)
{
  if (!strcmp (scheme, "http"))
    return;
  if (!strcmp (scheme, "socks4"))
    return;
  if (!strcmp (scheme, "socks5"))
    return;
  die ("invalid proxy scheme\n");
}

static void
validate_proxy_host (const char *host)
{
  const char *kValid = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                       "abcdefghijklmnopqrstuvwxyz"
                       "0123456789"
                       ".-";
  if (strspn (host, kValid) != strlen (host))
    die ("invalid char in host\n");
}

static void
validate_port (const char *port)
{
  if (!port)
    return;
  char *end;
  const int kBase = 10;
  errno = 0;
  unsigned long value = strtoul(port, &end, kBase);
  if (errno != 0 || value > USHRT_MAX || value == 0 || *end != '\0')
    die("invalid port %s\n", port);
}

static void
parse_proxy_uri (char *proxy, char **scheme, char **host, char **port)
{
  /* Expecting a URI, so: <scheme> '://' <host> ':' <port> */
  *scheme = proxy;
  proxy = strstr (proxy, "://");
  if (!proxy)
    die ("malformed proxy URI\n");
  *proxy = '\0'; /* terminate scheme string */
  proxy += strlen ("://");
  *host = proxy;
  proxy = strchr (proxy, ':');
  if (!proxy)
    die ("malformed proxy URI\n");
  *proxy++ = '\0';
  *port = proxy;
  validate_proxy_scheme (*scheme);
  validate_proxy_host (*host);
  validate_port (*port);
}

/* Returns a BIO that talks through a HTTP proxy using the CONNECT command.
 * The created BIO will ask the proxy to CONNECT to |target_host|:|target_port|
 * using |scheme|.
 */
static BIO *
BIO_create_proxy (const char *scheme, const char *target_host,
                  const char *target_port)
{
  BIO *bio_proxy = BIO_new_proxy ();
  BIO_proxy_set_type (bio_proxy, scheme);
  BIO_proxy_set_target_host (bio_proxy, target_host);
  BIO_proxy_set_target_port (bio_proxy, atoi (target_port));
  return bio_proxy;
}

static void
addr_to_str (const struct sockaddr *addr, char* dest,
                         socklen_t size)
{
  struct sockaddr_in* addr_ipv4 = NULL;
  struct sockaddr_in6* addr_ipv6 = NULL;
  memset (dest, '\0', size);
  if (addr->sa_family == AF_INET) {
    addr_ipv4 = (struct sockaddr_in*)addr;
    inet_ntop (AF_INET, &addr_ipv4->sin_addr, dest, size);
    return;
  }
  if (addr->sa_family == AF_INET6) {
    addr_ipv6 = (struct sockaddr_in6*)addr;
    inet_ntop (AF_INET6, &addr_ipv6->sin6_addr, dest, size);
    return;
  }
  verb ("V: unknown sa_family %hu\n", addr->sa_family);
}

static int
get_addrinfo_length (struct addrinfo *addr_infos) {
  int result = 0;
  for (struct addrinfo *iter = addr_infos; iter; iter = iter->ai_next) {
    ++result;
  }
  return result;
}

static struct addrinfo *
get_addrinfo_element (struct addrinfo *addr_infos, int index) {
  int current_index = 0;
  for (struct addrinfo *iter = addr_infos; iter; iter = iter->ai_next) {
    if (current_index == index) {
      return iter;
    }
    ++current_index;
  }
  return NULL;
}

/* Connects to |host| on port |port|.
 * Returns the socket file descriptor if successful, otherwise exits with
 * failure.
 */
static int
create_connection (const char *host, const char *port)
{
  int sock = -1;
  struct addrinfo hints = {
      .ai_flags = AI_ADDRCONFIG,
      .ai_family = AF_UNSPEC,
      .ai_socktype = SOCK_STREAM,
  };
  // Use INET6_ADDRSTRLEN for the buffer holding IP addresses as it will always
  // be longer than INET_ADDRSTRLEN.
  char addr_str_buf[INET6_ADDRSTRLEN];
  memset (addr_str_buf, '\0', INET6_ADDRSTRLEN);

  struct addrinfo *addr_infos = NULL;
  int err = getaddrinfo (host, port, &hints, &addr_infos);
  if (err != 0 || !addr_infos)
    die ("getaddrinfo (%s): %s\n", host, gai_strerror (err));

  // tlsdate is killed by a supervisor if it takes too long to finish. So it
  // may not have time to try all the addresses. Selecting the start point
  // randomly makes it try different addresses during different attempts, that
  // is useful when some addresses are not accessible (e.g. first ones).
  int list_length = get_addrinfo_length (addr_infos);
  int start_index = random () % list_length;

  for (int i = 0; i < list_length; ++i)
  {
    struct addrinfo *current_addr_info =
        get_addrinfo_element (addr_infos, (start_index + i) % list_length);
    if (!current_addr_info) {
      die ("attempted to use NULL addrinfo");
    }

    addr_to_str (current_addr_info->ai_addr, addr_str_buf, INET6_ADDRSTRLEN);
    verb ("V: attempting to connect to %s\n", addr_str_buf);
    sock = socket (current_addr_info->ai_family, SOCK_STREAM, 0);
    if (sock < 0)
    {
      perror ("socket");
      continue;
    }

    if (connect (sock, current_addr_info->ai_addr,
                 current_addr_info->ai_addrlen) != 0)
    {
      perror ("connect");
      close (sock);
      sock = -1;
      continue;
    }
    break;
  }
  freeaddrinfo (addr_infos);

  if (sock < 0)
    die ("failed to find any remote addresses for %s:%s\n", host, port);

  return sock;
}

/* Creates a BIO wrapper over the socket connection to |host|:|port|.
 * This workaround is needed because BIO_s_connect() doesn't support IPv6.
 */
static BIO *BIO_create_socket (const char *host, const char *port)
{
  BIO *bio_socket = NULL;
  int sockfd = create_connection (host, port);
  if ( !(bio_socket = BIO_new_fd (sockfd, 1 /* close_flag */)))
    die ("BIO_new_fd failed\n");

  return bio_socket;
}

/* Creates an OpenSSL BIO-chain which talks to |target_host|:|target_port|
 * using the SSL protocol. If |proxy| is set it will be used as a HTTP proxy.
 */
static BIO *
make_ssl_bio (SSL_CTX *ctx, const char *target_host, const char *target_port,
              char *proxy)
{
  BIO *bio_socket = NULL;
  BIO *bio_ssl = NULL;
  BIO *bio_proxy = NULL;
  char *scheme = NULL;
  char *proxy_host = NULL;
  char *proxy_port = NULL;

  if ( !(bio_ssl = BIO_new_ssl (ctx, 1)))
    die ("BIO_new_ssl failed\n");

  if (proxy)
  {
    verb ("V: using proxy %s\n", proxy);
    parse_proxy_uri (proxy, &scheme, &proxy_host, &proxy_port);

    if ( !(bio_proxy = BIO_create_proxy (scheme, target_host, target_port)))
        die ("BIO_create_proxy failed\n");

    bio_socket = BIO_create_socket (proxy_host, proxy_port);

    BIO_push (bio_ssl, bio_proxy);
    BIO_push (bio_ssl, bio_socket);
  }
  else
  {
    bio_socket = BIO_create_socket (target_host, target_port);
    BIO_push (bio_ssl, bio_socket);
  }
  return bio_ssl;
}

/** helper function for 'malloc' */
static void *
xmalloc (size_t size)
{
  void *ptr;
  if (0 == size)
    die ("xmalloc: zero size\n");
  ptr = malloc (size);
  if (NULL == ptr)
    die ("xmalloc: out of memory (allocating %zu bytes)\n", size);
  return ptr;
}


/** helper function for 'free' */
static void
xfree (void *ptr)
{
  if (NULL == ptr)
    die ("xfree: NULL pointer given as argument\n");
  free (ptr);
}


static int
verify_with_server_time (X509_STORE_CTX *store_ctx, void *arg)
{
  SSL *ssl = X509_STORE_CTX_get_ex_data (
      store_ctx, SSL_get_ex_data_X509_STORE_CTX_idx());

  // XXX TODO: If we want to trust the remote system for time,
  // can we just read that time out of the remote system and if the
  // cert verifies, decide that the time is reasonable?
  // Such a process seems to indicate that a once valid cert would be
  // forever valid - we stopgap that by ensuring it isn't less than
  // the latest compiled_time and isn't above max_reasonable_time...
  // XXX TODO: Solve eternal question about the Chicken and the Egg...
  uint32_t compiled_time = RECENT_COMPILE_DATE;
  uint32_t max_reasonable_time = MAX_REASONABLE_TIME;
  uint32_t server_time;
  verb ("V: freezing time for x509 verification\n");
  SSL_get_server_random(ssl, (unsigned char *)&server_time,
                        sizeof (uint32_t));
  if (compiled_time < ntohl (server_time)
      &&
      ntohl (server_time) < max_reasonable_time)
    {
      verb ("V: remote peer provided: %d, preferred over compile time: %d\n",
           ntohl (server_time), compiled_time);
      verb ("V: freezing time with X509_VERIFY_PARAM_set_time\n");
      X509_STORE_CTX_set_time (
          store_ctx, 0, (time_t) ntohl (server_time) + 86400);
    }
  else
    {
      die ("V: the remote server is a false ticker! server: %d compile: %d\n",
          ntohl (server_time), compiled_time);
    }

  return X509_verify_cert (store_ctx);
}

uint32_t
get_certificate_keybits (EVP_PKEY *public_key)
{
  /*
    In theory, we could use check_bitlen_dsa() and check_bitlen_rsa()
   */
  uint32_t key_bits;
  switch (EVP_PKEY_id (public_key))
    {
    case EVP_PKEY_RSA:
      verb ("V: key type: EVP_PKEY_RSA\n");
      break;
    case EVP_PKEY_RSA2:
      verb ("V: key type: EVP_PKEY_RSA2\n");
      break;
    case EVP_PKEY_DSA:
      verb ("V: key type: EVP_PKEY_DSA\n");
      break;
    case EVP_PKEY_DSA1:
      verb ("V: key type: EVP_PKEY_DSA1\n");
      break;
    case EVP_PKEY_DSA2:
      verb ("V: key type: EVP_PKEY_DSA2\n");
      break;
    case EVP_PKEY_DSA3:
      verb ("V: key type: EVP_PKEY_DSA3\n");
      break;
    case EVP_PKEY_DSA4:
      verb ("V: key type: EVP_PKEY_DSA4\n");
      break;
    case EVP_PKEY_DH:
      verb ("V: key type: EVP_PKEY_DH\n");
      break;
    case EVP_PKEY_EC:
      verb ("V: key type: EVP_PKEY_EC\n");
      break;
      // Should we also care about EVP_PKEY_HMAC and EVP_PKEY_CMAC?
    default:
      die ("unknown public key type\n");
      break;
    }
  key_bits = EVP_PKEY_bits (public_key);
  verb ("V: keybits: %d\n", key_bits);
  return key_bits;
}

uint32_t
dns_label_count (char *label, char *delim)
{
  char *label_tmp;
  char *saveptr;
  char *saveptr_tmp;
  uint32_t label_count;
  label_tmp = strdup (label);
  label_count = 0;
  saveptr = NULL;
  saveptr_tmp = NULL;
  saveptr = strtok_r (label_tmp, delim, &saveptr);
  if (NULL != saveptr)
    {
      // Did we find our first label?
      if (saveptr[0] != delim[0])
        {
          label_count++;
          verb ("V: label found; total label count: %d\n", label_count);
        }
      do
        {
          // Find all subsequent labels
          label_count++;
          saveptr_tmp = strtok_r (NULL, delim, &saveptr);
          verb ("V: label found; total label count: %d\n", label_count);
        }
      while (NULL != saveptr_tmp);
    }
  free (label_tmp);
  return label_count;
}

// first we split strings on '.'
// then we call each split string a 'label'
// Do not allow '*' for the top level domain label; eg never allow *.*.com
// Do not allow '*' for subsequent subdomains; eg never allow *.foo.example.com
// Do allow *.example.com
uint32_t
check_wildcard_match_rfc2595 (const char *orig_hostname,
                              const char *orig_cert_wild_card)
{
  char *hostname;
  char *hostname_to_free;
  char *cert_wild_card;
  char *cert_wild_card_to_free;
  char *expected_label;
  char *wildcard_label;
  char *delim;
  char *wildchar;
  uint32_t ok;
  uint32_t wildcard_encountered;
  uint32_t label_count;
  // First we copy the original strings
  hostname = strndup (orig_hostname, strlen (orig_hostname));
  cert_wild_card = strndup (orig_cert_wild_card, strlen (orig_cert_wild_card));
  hostname_to_free = hostname;
  cert_wild_card_to_free = cert_wild_card;
  delim = strdup (".");
  wildchar = strdup ("*");
  verb ("V: Inspecting '%s' for possible wildcard match against '%s'\n",
        hostname, cert_wild_card);
  // By default we have not processed any labels
  label_count = dns_label_count (cert_wild_card, delim);
  // By default we have no match
  ok = 0;
  wildcard_encountered = 0;
  // First - do we have labels? If not, we refuse to even try to match
  if ( (NULL != strpbrk (cert_wild_card, delim)) &&
       (NULL != strpbrk (hostname, delim)) &&
       (label_count <= ( (uint32_t) RFC2595_MIN_LABEL_COUNT)))
    {
      if (wildchar[0] == cert_wild_card[0])
        {
          verb ("V: Found wildcard in at start of provided certificate name\n");
          do
            {
              // Skip over the bytes between the first char and until the next label
              wildcard_label = strsep (&cert_wild_card, delim);
              expected_label = strsep (&hostname, delim);
              if (NULL != wildcard_label &&
                  NULL != expected_label &&
                  NULL != hostname &&
                  NULL != cert_wild_card)
                {
                  // Now we only consider this wildcard valid if the rest of the
                  // hostnames match verbatim
                  verb ("V: Attempting match of '%s' against '%s'\n",
                        expected_label, wildcard_label);
                  // This is the case where we have a label that begins with wildcard
                  // Furthermore, we only allow this for the first label
                  if (wildcard_label[0] == wildchar[0] &&
                      0 == wildcard_encountered && 0 == ok)
                    {
                      verb ("V: Forced match of '%s' against '%s'\n", expected_label, wildcard_label);
                      wildcard_encountered = 1;
                    }
                  else
                    {
                      verb ("V: Attempting match of '%s' against '%s'\n",
                            hostname, cert_wild_card);
                      if (0 == strcasecmp (expected_label, wildcard_label) &&
                          label_count >= ( (uint32_t) RFC2595_MIN_LABEL_COUNT))
                        {
                          ok = 1;
                          verb ("V: remaining labels match!\n");
                          break;
                        }
                      else
                        {
                          ok = 0;
                          verb ("V: remaining labels do not match!\n");
                          break;
                        }
                    }
                }
              else
                {
                  // We hit this case when we have a mismatched number of labels
                  verb ("V: NULL label; no wildcard here\n");
                  break;
                }
            }
          while (0 != wildcard_encountered && label_count <= RFC2595_MIN_LABEL_COUNT);
        }
      else
        {
          verb ("V: Not a RFC 2595 wildcard\n");
        }
    }
  else
    {
      verb ("V: Not a valid wildcard certificate\n");
      ok = 0;
    }
  // Free our copies
  free (wildchar);
  free (delim);
  free (hostname_to_free);
  free (cert_wild_card_to_free);
  if (wildcard_encountered & ok && label_count >= RFC2595_MIN_LABEL_COUNT)
    {
      verb ("V: wildcard match of %s against %s\n",
            orig_hostname, orig_cert_wild_card);
      return (wildcard_encountered & ok);
    }
  else
    {
      verb ("V: wildcard match failure of %s against %s\n",
            orig_hostname, orig_cert_wild_card);
      return 0;
    }
}

/**
 This extracts the first commonName and checks it against hostname.
*/
uint32_t
check_cn (SSL *ssl, const char *hostname)
{
  int ok = 0;
  uint32_t ret;
  char *cn_buf;
  X509 *certificate;
  X509_NAME *xname;
  cn_buf = xmalloc (TLSDATE_HOST_NAME_MAX + 1);
  certificate = SSL_get_peer_certificate (ssl);
  if (NULL == certificate)
    {
      die ("Unable to extract certificate\n");
    }
  memset (cn_buf, '\0', (TLSDATE_HOST_NAME_MAX + 1));
  xname = X509_get_subject_name (certificate);
  ret = X509_NAME_get_text_by_NID (xname, NID_commonName,
                                   cn_buf, TLSDATE_HOST_NAME_MAX);
  if (-1 == ret && ret != strlen (hostname))
    {
      die ("Unable to extract commonName\n");
    }
  if (strcasecmp (cn_buf, hostname))
    {
      verb ("V: commonName mismatch! Expected: %s - received: %s\n",
            hostname, cn_buf);
    }
  else
    {
      verb ("V: commonName matched: %s\n", cn_buf);
      ok = 1;
    }
  X509_NAME_free (xname);
  X509_free (certificate);
  xfree (cn_buf);
  return ok;
}

/**
 Search for a hostname match in the SubjectAlternativeNames.
*/
uint32_t
check_san (SSL *ssl, const char *hostname)
{
  X509 *cert;
  int extcount, ok = 0;
  /* What an OpenSSL mess ... */
  if (NULL == (cert = SSL_get_peer_certificate (ssl)))
    {
      die ("Getting certificate failed\n");
    }
  if ( (extcount = X509_get_ext_count (cert)) > 0)
    {
      int i;
      for (i = 0; i < extcount; ++i)
        {
          const char *extstr;
          X509_EXTENSION *ext;
          ext = X509_get_ext (cert, i);
          extstr = OBJ_nid2sn (OBJ_obj2nid (X509_EXTENSION_get_object (ext)));
          if (!strcmp (extstr, "subjectAltName"))
            {
              int j;
              void *extvalstr;
              STACK_OF (CONF_VALUE) *val;
              CONF_VALUE *nval;
#if OPENSSL_VERSION_NUMBER >= 0x10000000L
              const
#endif
              X509V3_EXT_METHOD *method;
              if (! (method = X509V3_EXT_get (ext)))
                {
                  break;
                }
              extvalstr = X509V3_EXT_d2i(ext);
              if (!extvalstr)
                {
                  break;
                }
              if (method->i2v)
                {
                  val = method->i2v (method, extvalstr, NULL);
                  for (j = 0; j < sk_CONF_VALUE_num (val); ++j)
                    {
                      nval = sk_CONF_VALUE_value (val, j);
                      if ( (!strcasecmp (nval->name, "DNS") &&
                            !strcasecmp (nval->value, hostname)) ||
                           (!strcasecmp (nval->name, "iPAddress") &&
                            !strcasecmp (nval->value, hostname)))
                        {
                          verb ("V: subjectAltName matched: %s, type: %s\n", nval->value, nval->name); // We matched this; so it's safe to print
                          ok = 1;
                          break;
                        }
                      // Attempt to match subjectAltName DNS names
                      if (!strcasecmp (nval->name, "DNS"))
                        {
                          ok = check_wildcard_match_rfc2595 (hostname, nval->value);
                          if (ok)
                            {
                              break;
                            }
                        }
                      verb ("V: subjectAltName found but not matched: %s, type: %s\n", nval->value, nval->name); // XXX: Clean this string!
                    }
                }
            }
          else
            {
              verb ("V: found non subjectAltName extension\n");
            }
          if (ok)
            {
              break;
            }
        }
    }
  else
    {
      verb ("V: no X509_EXTENSION field(s) found\n");
    }
  X509_free (cert);
  return ok;
}

uint32_t
check_name (SSL *ssl, const char *hostname)
{
  uint32_t ret;
  ret = 0;
  ret = check_cn (ssl, hostname);
  ret += check_san (ssl, hostname);
  if (0 != ret && 0 < ret)
    {
      verb ("V: hostname verification passed\n");
    }
  else
    {
      die ("hostname verification failed for host %s!\n", g_host);
    }
  return ret;
}

uint32_t
verify_signature (SSL *ssl, const char *hostname)
{
  long ssl_verify_result;
  X509 *certificate;
  certificate = SSL_get_peer_certificate (ssl);
  if (NULL == certificate)
    {
      die ("Getting certificate failed\n");
    }
  // In theory, we verify that the cert is valid
  ssl_verify_result = SSL_get_verify_result (ssl);
  switch (ssl_verify_result)
    {
    case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
    case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
      die ("certificate is self signed\n");
    case X509_V_OK:
      verb ("V: certificate verification passed\n");
      break;
    default:
      die ("certification verification error: %ld\n",
           ssl_verify_result);
    }
  return 0;
}

void
check_key_length (SSL *ssl)
{
  uint32_t key_bits;
  X509 *certificate;
  EVP_PKEY *public_key;
  certificate = SSL_get_peer_certificate (ssl);
  if (NULL == certificate)
    {
      die ("Getting certificate failed\n");
    }
  public_key = X509_get_pubkey (certificate);
  if (NULL == public_key)
    {
      die ("public key extraction failure\n");
    }
  else
    {
      verb ("V: public key is ready for inspection\n");
    }
  key_bits = get_certificate_keybits (public_key);
  if (MIN_PUB_KEY_LEN >= key_bits && EVP_PKEY_id(public_key) != EVP_PKEY_EC)
    {
      die ("Unsafe public key size: %d bits\n", key_bits);
    }
  else
    {
      if (EVP_PKEY_id(public_key) == EVP_PKEY_EC)
        if (key_bits >= MIN_ECC_PUB_KEY_LEN
            && key_bits <= MAX_ECC_PUB_KEY_LEN)
          {
            verb ("V: ECC key length appears safe\n");
          }
        else
          {
            die ("Unsafe ECC key size: %d bits\n", key_bits);
          }
      else
        {
          verb ("V: key length appears safe\n");
        }
    }
  EVP_PKEY_free (public_key);
}

void
inspect_key (SSL *ssl, const char *hostname)
{
  verify_signature (ssl, hostname);
  check_name (ssl, hostname);
}

/**
 * Run SSL handshake and store the resulting time value in the
 * 'time_map'.
 *
 * @param time_map where to store the current time
 */
static void
run_ssl (uint32_t *time_map, int time_is_an_illusion)
{
  BIO *s_bio;
  SSL_CTX *ctx;
  SSL *ssl;
  struct stat statbuf;
  SSL_load_error_strings();
  SSL_library_init();
  ctx = NULL;

  /*
   * Some of the XYZ_method() calls below are marked deprecated. We still want
   * to use them for compatibility reasons, so silence the warnings or they'll
   * break the build.
   */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

  if (0 == strcmp ("sslv23", g_protocol))
    {
      verb ("V: using SSLv23_client_method()\n");
      ctx = SSL_CTX_new (SSLv23_client_method());
    }
#ifndef OPENSSL_NO_SSL3_METHOD
  else if (0 == strcmp ("sslv3", g_protocol))
    {
      verb ("V: using SSLv3_client_method()\n");
      ctx = SSL_CTX_new (SSLv3_client_method());
    }
#endif
#ifndef OPENSSL_NO_TLS1_METHOD
  else if (0 == strcmp ("tlsv1", g_protocol))
    {
      verb ("V: using TLSv1_client_method()\n");
      ctx = SSL_CTX_new (TLSv1_client_method());
    }
#endif
#ifndef OPENSSL_NO_TLS1_1_METHOD
  else if (0 == strcmp ("tlsv11", g_protocol))
    {
      verb ("V: using TLSv1_1_client_method()\n");
      ctx = SSL_CTX_new (TLSv1_1_client_method());
    }
#endif
#ifndef OPENSSL_NO_TLS1_2_METHOD
  else if (0 == strcmp ("tlsv12", g_protocol))
    {
      verb ("V: using TLSv1_2_client_method()\n");
      ctx = SSL_CTX_new (TLSv1_2_client_method());
    }
#endif
  else
    die ("Unsupported protocol `%s'\n", g_protocol);

#pragma GCC diagnostic pop

  if (ctx == NULL)
    die ("OpenSSL failed to support protocol `%s'\n", g_protocol);
  if (g_ca_racket)
    {
      if (-1 == stat (g_ca_cert_container, &statbuf))
        {
          die ("Unable to stat CA certficate container\n");
        }
      else
        {
          switch (statbuf.st_mode & S_IFMT)
            {
            case S_IFREG:
              if (1 != SSL_CTX_load_verify_locations(
                           ctx, g_ca_cert_container, NULL))
                fprintf(stderr, "SSL_CTX_load_verify_locations failed\n");
              break;
            case S_IFDIR:
              if (1 != SSL_CTX_load_verify_locations(
                           ctx, NULL, g_ca_cert_container))
                fprintf(stderr, "SSL_CTX_load_verify_locations failed\n");
              break;
            default:
              die ("Unable to load CA certficate container\n");
            }
        }
    }

  if (time_is_an_illusion)
    {
      SSL_CTX_set_cert_verify_callback (ctx, verify_with_server_time, NULL);
    }

  verb ("V: setting up connection to %s:%s\n", g_host, g_port);
  if (NULL == (s_bio = make_ssl_bio(ctx, g_host, g_port, g_proxy)))
    die ("SSL BIO setup failed\n");
  BIO_get_ssl (s_bio, &ssl);
  if (NULL == ssl)
    die ("SSL setup failed\n");
  SSL_set_mode (ssl, SSL_MODE_AUTO_RETRY);
  SSL_set_tlsext_host_name (ssl, g_host);
  if (NULL == BIO_new_fp (stdout, BIO_NOCLOSE))
    die ("BIO_new_fp returned error, possibly: %s", strerror (errno));
  // This should run in seccomp
  // eg:     prctl(PR_SET_SECCOMP, 1);
  verb ("V: BIO_do_connect\n");
  if (1 != BIO_do_connect (s_bio)) // XXX TODO: BIO_should_retry() later?
    die ("SSL connection failed\n");
  verb ("V: BIO_do_handshake\n");
  if (1 != BIO_do_handshake (s_bio))
    die ("SSL handshake failed\n");
  // Verify the peer certificate against the CA certs on the local system
  if (g_ca_racket)
    {
      inspect_key (ssl, g_host);
    }
  else
    {
      verb ("V: Certificate verification skipped!\n");
    }
  check_key_length (ssl);
  // from /usr/include/openssl/ssl3.h
  //  ssl->s3->server_random is an unsigned char of 32 bits
  SSL_get_server_random(ssl, (unsigned char *)time_map, sizeof(uint32_t));
  SSL_free (ssl);
  SSL_CTX_free (ctx);
}

/** drop root rights and become 'nobody' */

int
main (int argc, char **argv)
{
  uint32_t *time_map;
  struct tlsdate_time start_time, end_time, warp_time;
  int status;
  pid_t ssl_child;
  long long rt_time_ms;
  uint32_t server_time_s;
  int setclock;
  int showtime;
  int showtime_raw;
  int timewarp;
  int leap;
  if (argc != 12)
    return 1;
  g_host = argv[1];
  g_port = argv[2];
  validate_port(g_port);
  g_protocol = argv[3];
  g_ca_cert_container = argv[6];
  g_ca_racket = (0 != strcmp ("unchecked", argv[4]));
  verbose = (0 != strcmp ("quiet", argv[5]));
  setclock = (0 == strcmp ("setclock", argv[7]));
  showtime = (0 == strcmp ("showtime", argv[8]));
  showtime_raw = (0 == strcmp ("showtime=raw", argv[8]));
  timewarp = (0 == strcmp ("timewarp", argv[9]));
  leap = (0 == strcmp ("leapaway", argv[10]));
  g_proxy = (0 == strcmp ("none", argv[11]) ? NULL : argv[11]);
  srandom(time(NULL));
  clock_init_time (&warp_time, RECENT_COMPILE_DATE, 0);
  if (timewarp)
    {
      verb ("V: RECENT_COMPILE_DATE is %lu.%06lu\n",
            (unsigned long) CLOCK_SEC (&warp_time),
            (unsigned long) CLOCK_USEC (&warp_time));
    }
  /* We are not going to set the clock, thus no need to stay root */
  if (0 == setclock && 0 == timewarp)
    {
      drop_privs_to (UNPRIV_USER, UNPRIV_GROUP);
    }
  time_map = mmap (NULL, sizeof (uint32_t),
                   PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (MAP_FAILED == time_map)
    {
      fprintf (stderr, "mmap failed: %s\n",
               strerror (errno));
      return 1;
    }
  /* Get the current time from the system clock. */
  if (0 != clock_get_real_time (&start_time))
    {
      die ("Failed to read current time of day: %s\n", strerror (errno));
    }
  verb ("V: time is currently %lu.%06lu\n",
        (unsigned long) CLOCK_SEC (&start_time),
        (unsigned long) CLOCK_NSEC (&start_time));
  if ( ( (unsigned long) CLOCK_SEC (&start_time)) < ( (unsigned long) CLOCK_SEC (&warp_time)))
    {
      verb ("V: local clock time is less than RECENT_COMPILE_DATE\n");
      if (timewarp)
        {
          verb ("V: Attempting to warp local clock into the future\n");
          if (0 != clock_set_real_time (&warp_time))
            {
              die ("setting time failed: %s (Attempted to set clock to %lu.%06lu)\n",
                   strerror (errno),
                   (unsigned long) CLOCK_SEC (&warp_time),
                   (unsigned long) CLOCK_SEC (&warp_time));
            }
          if (0 != clock_get_real_time (&start_time))
            {
              die ("Failed to read current time of day: %s\n", strerror (errno));
            }
          verb ("V: time is currently %lu.%06lu\n",
                (unsigned long) CLOCK_SEC (&start_time),
                (unsigned long) CLOCK_NSEC (&start_time));
          verb ("V: It's just a step to the left...\n");
        }
    }
  else
    {
      verb ("V: time is greater than RECENT_COMPILE_DATE\n");
    }
  /* initialize to bogus value, just to be on the safe side */
  *time_map = 0;
  /* Run SSL interaction in separate process (and not as 'root') */
  ssl_child = fork ();
  if (-1 == ssl_child)
    die ("fork failed: %s\n", strerror (errno));
  if (0 == ssl_child)
    {
      drop_privs_to (UNPRIV_USER, UNPRIV_GROUP);
      run_ssl (time_map, leap);
      (void) munmap (time_map, sizeof (uint32_t));
      _exit (0);
    }
  if (ssl_child != waitpid (ssl_child, &status, 0))
    die ("waitpid failed: %s\n", strerror (errno));
  if (! (WIFEXITED (status) && (0 == WEXITSTATUS (status))))
    die ("child process failed in SSL handshake\n");
  if (0 != clock_get_real_time (&end_time))
    die ("Failed to read current time of day: %s\n", strerror (errno));
  /* calculate RTT */
  rt_time_ms = (CLOCK_SEC (&end_time) - CLOCK_SEC (&start_time)) * 1000 + (CLOCK_USEC (&end_time) - CLOCK_USEC (&start_time)) / 1000;
  if (rt_time_ms < 0)
    rt_time_ms = 0; /* non-linear time... */
  server_time_s = ntohl (*time_map);
  munmap (time_map, sizeof (uint32_t));
  verb ("V: server time %u (difference is about %d s) was fetched in %lld ms\n",
        (unsigned int) server_time_s,
        CLOCK_SEC (&start_time) - server_time_s,
        rt_time_ms);
  /* warning if the handshake took too long */
  if (rt_time_ms > TLS_RTT_THRESHOLD)
    {
      verb ("V: the TLS handshake took more than %d msecs - consider using a different " \
            "server or run it again\n", TLS_RTT_THRESHOLD);
    }
  if (showtime_raw)
    {
      fwrite (&server_time_s, sizeof (server_time_s), 1, stdout);
    }
  if (showtime)
    {
      struct tm  ltm;
      time_t tim = server_time_s;
      char       buf[256];
      localtime_r (&tim, &ltm);
      if (0 == strftime (buf, sizeof buf, "%a %b %e %H:%M:%S %Z %Y", &ltm))
        {
          die ("strftime returned 0\n");
        }
      fprintf (stdout, "%s\n", buf);
    }
  /* finally, actually set the time */
  if (setclock)
    {
      struct tlsdate_time server_time;
      clock_init_time (&server_time,  server_time_s + (rt_time_ms / 2 / 1000),
                       (rt_time_ms / 2) % 1000);
      // We should never receive a time that is before the time we were last
      // compiled; we subscribe to the linear theory of time for this program
      // and this program alone!
      if (CLOCK_SEC (&server_time) >= MAX_REASONABLE_TIME)
        die ("remote server is a false ticker from the future!\n");
      if (CLOCK_SEC (&server_time) <= RECENT_COMPILE_DATE)
        die ("remote server is a false ticker!\n");
      if (0 != clock_set_real_time (&server_time))
        die ("setting time failed: %s (Difference from server is about %d)\n",
             strerror (errno),
             CLOCK_SEC (&start_time) - server_time_s);
      verb ("V: setting time succeeded\n");
    }
  return 0;
}
