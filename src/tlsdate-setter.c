/*
 * tlsdate-setter.c - privileged time setter for tlsdated
 * Copyright (c) 2013 The Chromium Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/rtc.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#include <event2/event.h>

#include "src/conf.h"
#include "src/dbus.h"
#include "src/seccomp.h"
#include "src/tlsdate.h"
#include "src/util.h"

/* Atomically writes the timestamp to the specified fd. */
int
save_timestamp_to_fd (int fd, time_t t)
{
  struct iovec iov[1];
  ssize_t ret;
  iov[0].iov_base = &t;
  iov[0].iov_len = sizeof (t);
  ret = IGNORE_EINTR (pwritev (fd, iov, 1, 0));
  if (ret != sizeof (t))
    return 1;
  return 0;
}

/*
 * Set the hardware clock referred to by fd (which should be a descriptor to
 * some device that implements the interface documented in rtc(4)) to the system
 * time. See hwclock(8) for details of why this is important. If we fail, we
 * just return - there's nothing the caller can really do about a failure of
 * this function except try later.
 */
int
sync_hwclock (int fd, time_t sec)
{
  struct tm tm;
  struct rtc_time rtctm;
  localtime_r (&sec, &tm);
  /* these structs are identical, but separately defined */
  rtctm.tm_sec = tm.tm_sec;
  rtctm.tm_min = tm.tm_min;
  rtctm.tm_hour = tm.tm_hour;
  rtctm.tm_mday = tm.tm_mday;
  rtctm.tm_mon = tm.tm_mon;
  rtctm.tm_year = tm.tm_year;
  rtctm.tm_wday = tm.tm_wday;
  rtctm.tm_yday = tm.tm_yday;
  rtctm.tm_isdst = tm.tm_isdst;
  return ioctl (fd, RTC_SET_TIME, &rtctm);
}

void
report_setter_error (siginfo_t *info)
{
  const char *code;
  int killit = 0;
  switch (info->si_code)
    {
    case CLD_EXITED:
      code = "EXITED";
      break;
    case CLD_KILLED:
      code = "KILLED";
      break;
    case CLD_DUMPED:
      code = "DUMPED";
      break;
    case CLD_STOPPED:
      code = "STOPPED";
      killit = 1;
      break;
    case CLD_TRAPPED:
      code = "TRAPPED";
      killit = 1;
      break;
    case CLD_CONTINUED:
      code = "CONTINUED";
      killit = 1;
      break;
    default:
      code = "???";
      killit = 1;
    }
  info ("tlsdate-setter exitting: code:%s status:%d pid:%d uid:%d",
        code, info->si_status, info->si_pid, info->si_uid);
  if (killit)
    kill (info->si_pid, SIGKILL);
}

void
time_setter_coprocess (int time_fd, int notify_fd, struct state *state)
{
  int save_fd = -1;
  int status;
  prctl (PR_SET_NAME, "tlsdated-setter");
  if (state->opts.should_save_disk && !state->opts.dry_run)
    {
      if ( (save_fd = open (state->timestamp_path,
                            O_WRONLY | O_CREAT | O_NOFOLLOW | O_CLOEXEC,
                            S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) < 0)
        {
          /* Attempt to unlink the path on the way out. */
          unlink (state->timestamp_path);
          status = SETTER_NO_SAVE;
          goto notify_and_die;
        }
    }
  /* XXX: Drop all privs but CAP_SYS_TIME */
#ifdef HAVE_SECCOMP_FILTER
  if (enable_setter_seccomp())
    {
      status = SETTER_NO_SBOX;
      goto notify_and_die;
    }
#endif
  while (1)
    {
      struct timeval tv = { 0, 0 };
      /* The wire protocol is a time_t, but the caller should
       * always be the unprivileged tlsdated process which spawned this
       * helper.
       * There are two special messages:
       * (time_t)   0: requests a clean shutdown
       * (time_t) < 0: indicates not to write to disk
       * On Linux, time_t is a signed long.  Expanding the protocol
       * is easy, but writing one long only is ideal.
       */
      ssize_t bytes = read (time_fd, &tv.tv_sec, sizeof (tv.tv_sec));
      int save = 1;
      if (bytes == -1)
        {
          if (errno == EINTR)
            continue;
          status = SETTER_READ_ERR;
          goto notify_and_die;
        }
      if (bytes == 0)
        {
          /* End of pipe */
          status = SETTER_READ_ERR;
          goto notify_and_die;
        }
      if (bytes != sizeof (tv.tv_sec))
        continue;
      if (tv.tv_sec < 0)
        {
          /* Don't write to disk */
          tv.tv_sec = -tv.tv_sec;
          save = 0;
        }
      if (tv.tv_sec == 0)
        {
          status = SETTER_EXIT;
          goto notify_and_die;
        }
      if (is_sane_time (tv.tv_sec))
        {
          /* It would be nice if time was only allowed to move forward, but
           * if a single time source is wrong, then it could make it impossible
           * to recover from once the time is written to disk.
           */
          status = SETTER_BAD_TIME;
          if (!state->opts.dry_run)
            {
              struct timeval our_time = { 0, 0 };
              if (gettimeofday (&our_time, NULL) < 0)
                {
                  status = SETTER_GETTIME_ERR;
                  goto notify_and_die;
                }
              /* Do not adjust clock gradually even if it is close enough to
               * the right time, to avoid clock speed mismatch between
               * VMs and the host. b/197780049
               * The old logic to adjust clocks gradually using adjtime(3) was
               * previously introduced in crrev/c/1344802 but now it's removed.
               * For more info, please refer to discussion on crrev/c/4573202.
               */
              if (settimeofday (&tv, NULL) < 0)
                {
                  status = SETTER_SET_ERR;
                  goto notify_and_die;
                }
              else
                info ("tlsdate-setter: system time updated to %lu.%09lu",
                      tv.tv_sec, tv.tv_usec);
              if (state->opts.should_sync_hwclock &&
                  sync_hwclock (state->hwclock_fd, tv.tv_sec))
                {
                  status = SETTER_NO_RTC;
                  goto notify_and_die;
                }
              if (save && save_fd != -1 &&
                  save_timestamp_to_fd (save_fd, tv.tv_sec))
                {
                  status = SETTER_NO_SAVE;
                  goto notify_and_die;
                }
            }
          status = SETTER_TIME_SET;
        }
      IGNORE_EINTR (write (notify_fd, &status, sizeof(status)));
    }
notify_and_die:
  IGNORE_EINTR (write (notify_fd, &status, sizeof(status)));
  close (notify_fd);
  close (save_fd);
  _exit (status);
}
