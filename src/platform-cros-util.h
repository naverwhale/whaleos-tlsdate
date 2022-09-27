/*
 * platform-cros-util.h - Utility code for platform-cros.c
 * Copyright 2017 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */
#ifndef PLATFORM_CROS_H_
#define PLATFORM_CROS_H_

#include "config.h"

#include <stddef.h>

/* Convert PAC return format to tlsdated url format */
void canonicalize_pac (const char *pac_fmt, char *proxy_url, size_t len);

#endif  /* PLATFORM_CROS_H_ */
