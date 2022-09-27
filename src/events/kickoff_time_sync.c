/*
 * kickoff_time_sync.c - network time synchronization
 * Copyright (c) 2013 The Chromium Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "config.h"

#include <openssl/rand.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <event2/event.h>

#include "src/conf.h"
#include "src/util.h"
#include "src/tlsdate.h"

int
add_jitter (int base, int jitter)
{
  int n = 0;
  if (!jitter)
    return base;
  if (RAND_bytes ( (unsigned char *) &n, sizeof (n)) != 1)
    fatal ("RAND_bytes() failed");
  return base + (abs (n) % (2 * jitter)) - jitter;
}

void
invalidate_time (struct state *state)
{
  state->last_sync_type = SYNC_TYPE_RTC;
  state->last_time = time (NULL);
  /* Note(!) this does not invalidate the clock_delta implicitly.
   * This allows forced invalidation to not lose synchronization
   * data.
   */
}

void
action_invalidate_time (evutil_socket_t fd, short what, void *arg)
{
  struct state *state = arg;
  debug ("[event:%s] fired", __func__);
  /* If time is already invalid and being acquired, do nothing. */
  if (state->last_sync_type == SYNC_TYPE_RTC &&
      event_pending (state->events[E_TLSDATE], EV_TIMEOUT, NULL))
    return;
  /* Time out our trust in network synchronization but don't persist
   * the change to disk or notify the system.  Let a network sync
   * failure or success do that.
   */
  invalidate_time (state);
  /* Then trigger a network sync if possible. */
  action_kickoff_time_sync (-1, EV_TIMEOUT, arg);
}

int
setup_event_timer_sync (struct state *state)
{
  int wait_time = add_jitter (state->opts.steady_state_interval,
                              state->opts.jitter);
  struct timeval interval = { wait_time, 0 };
  state->events[E_STEADYSTATE] = event_new (state->base, -1,
                                 EV_TIMEOUT|EV_PERSIST,
                                 action_invalidate_time, state);
  if (!state->events[E_STEADYSTATE])
    {
      error ("Failed to create interval event");
      return 1;
    }
  event_priority_set (state->events[E_STEADYSTATE], PRI_ANY);
  return event_add (state->events[E_STEADYSTATE], &interval);
}

/* Begins a network synchronization attempt.  If the local clocks
 * are synchronized, then make sure that the _current_ synchronization
 * source is set to the real-time clock and note that the clock_delta
 * is unreliable.  If the clock was in sync and the last synchronization
 * source was the network, then this action does nothing.
 *
 * In the case of desynchronization, the clock_delta value is used as a
 * guard to indicate that even if the synchronization source isn't the
 * network, the source is still tracking the clock delta that was
 * established from a network source.
 * TODO(wad) Change the name of clock_delta to indicate that it is the local
 *           clock delta after the last network sync.
 */
void action_kickoff_time_sync (evutil_socket_t fd, short what, void *arg)
{
  struct state *state = arg;
  debug ("[event:%s] fired", __func__);
  time_t delta = state->clock_delta;
  int jitter = 0;
  int reschedule = 0;
  if (check_continuity (&delta) > 0)
    {
      info ("[event:%s] clock delta desync detected (%d != %d)", __func__,
            state->clock_delta, delta);
      /* Add jitter iff we had network synchronization once before. */
      if (state->clock_delta)
        jitter = add_jitter (30, 30); /* TODO(wad) make configurable */
      /* Forget the old delta until we have time again. */
      state->clock_delta = 0;
      invalidate_time (state);
    }
  if (state->last_sync_type == SYNC_TYPE_NET)
    {
      debug ("[event:%s] time in sync. skipping", __func__);
      return;
    }
  /* Keep parity with run_tlsdate: for every wake, allow it to retry again. */
  if (state->tries > 0)
    {
      state->tries -= 1;
      /* Add an extra attempt to be performed after the current attempt
       * completes in case there is new data. Don't automatically reschedule
       * because flapping could mean we never resolve the time.
       */
      if (state->backoff == state->opts.wait_between_tries)
        {
          debug ("[event:%s] called while tries are in progress", __func__);
          return;
        }
      reschedule = 1;
      state->backoff = state->opts.wait_between_tries;
    }
  /* If a wake event arrives while a request to start tlsdate is pending, do
   * not reschedule automatically.  Doing so would allow a flood of wake events
   * to block the event from ever running.  Instead, only reschedule if
   * requested above and never allow less than wait_between_tries between
   * tlsdate events.
   */
  if (event_pending (state->events[E_TLSDATE], EV_TIMEOUT, NULL))
    {
      if (!reschedule)
        {
          debug ("[event:%s] tlsdate pending and not being rescheduled",
                 __func__);
          return;
        }
      debug ("[event:%s] pending tlsdate being rescheduled", __func__);
      jitter = state->backoff;
    }
  if (!state->events[E_RESOLVER])
    {
      trigger_event (state, E_TLSDATE, jitter);
      return;
    }
  /* If the resolver relies on an external response, then make sure that a
   * tlsdate event is waiting in the wings if the resolver is too slow.  Even
   * if this fires, it won't stop eventual handling of the resolver since it
   * doesn't event_del() E_RESOLVER.
   */
  trigger_event (state, E_TLSDATE, jitter + RESOLVER_TIMEOUT);
  trigger_event (state, E_RESOLVER, jitter);
}
