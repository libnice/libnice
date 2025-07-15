/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2025 Axis Communications AB.
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is the Nice GLib ICE library.
 *
 * The Initial Developers of the Original Code are Collabora Ltd and Nokia
 * Corporation. All Rights Reserved.
 *
 * Contributors:
 *   Martin Nordholts, Axis Communications AB, 2025.
 *
 * Alternatively, the contents of this file may be used under the terms of the
 * the GNU Lesser General Public License Version 2.1 (the "LGPL"), in which
 * case the provisions of LGPL are applicable instead of those above. If you
 * wish to allow use of your version of this file only under the terms of the
 * LGPL and not to allow others to use your version of this file under the
 * MPL, indicate your decision by deleting the provisions above and replace
 * them with the notice and other provisions required by the LGPL. If you do
 * not delete the provisions above, a recipient may use your version of this
 * file under either the MPL or the LGPL.
 */

#include <dlfcn.h>
#include <errno.h>
#include <glib.h>
#include <sys/socket.h>

#include "instrument-send.h"

/* Since receving is lossy for UDP even over localhost (because of a relatively
 * small default SO_RCVBUF), we instrument sending to make sure all messages are
 * queued for sending over the network. We don't want to drop messages before we
 * even try to send them. To ensure good test coverage, we sometimes synthesize
 * EWOULDBLOCK errors.
 */

static GMutex mutex;

static size_t messages_sent = 0; /* Protected by `mutex` */
static guint average_ewouldblock_interval = 0; /* Protected by `mutex` */
static void (*post_increment_callback) (gpointer user_data) = NULL; /* Protected by `mutex` */
static gpointer *post_increment_user_data; /* Protected by `mutex` */

static void
increment_messages_sent (size_t sent)
{
  void (*callback) (gpointer) = NULL;
  gpointer user_data = NULL;

  g_mutex_lock (&mutex);
  messages_sent += sent;
  callback = post_increment_callback;
  user_data = post_increment_user_data;
  g_mutex_unlock (&mutex);

  if (callback) {
    callback (user_data);
  }
}

/**
 * nice_test_instrument_send_set_average_ewouldblock_interval:
 * @param average_interval The average number of calls to `send()` between each
 * synthetic EWOULDBLOCK.
 *
 * Set the average number of calls to `send()` before a synthetic EWOULDBLOCK
 * error is injected. The value `0` means "never inject EWOULDBLOCK". The term
 * "average" is used because rand() is used to determine exactly when to inject.
 * This is to avoid "resonance frequencies" where unnaturally regular
 * EWOULDBLOCK causes components to never recover.
 */
void
nice_test_instrument_send_set_average_ewouldblock_interval (size_t average_interval)
{
  // We want repeatable randomness. Always use the same seed.
  srand (0);

  g_mutex_lock (&mutex);
  average_ewouldblock_interval = average_interval;
  g_mutex_unlock (&mutex);
}

static gboolean
should_inject_ewouldblock (void)
{
  gboolean should_inject = FALSE;

  g_mutex_lock (&mutex);
  /* The special value `0` means "never". */
  if (average_ewouldblock_interval > 0) {
    should_inject = rand () % average_ewouldblock_interval == 0;
  }
  g_mutex_unlock (&mutex);

  if (should_inject) {
    g_debug ("Injecting synthetic EWOULDBLOCK");
    return TRUE;
  } else {
    return FALSE;
  }
}

size_t
nice_test_instrument_send_get_messages_sent (void)
{
  size_t sent = 0;
  g_mutex_lock (&mutex);
  sent = messages_sent;
  g_mutex_unlock (&mutex);
  return sent;
}

void
nice_test_instrument_send_set_post_increment_callback (
    void (*callback) (gpointer user_data),
    gpointer user_data)
{
  g_mutex_lock (&mutex);
  post_increment_callback = callback;
  post_increment_user_data = user_data;
  g_mutex_unlock (&mutex);
}

ssize_t
send (int sockfd, const void *buf, size_t len, int flags)
{
  if (should_inject_ewouldblock ()) {
    errno = EWOULDBLOCK;
    return -1;
  } else {
    /* For simplicity, don't cache the `dlsym()` return value. This code is not
     * performance critical and `dlsym()` is thread safe.
     */
    ssize_t ret = ((ssize_t (*) (int sockfd, const void *buf, size_t len, int flags)) (
        dlsym (RTLD_NEXT, "send"))) (sockfd, buf, len, flags);
    if (ret != -1) {
      increment_messages_sent (1);
    }
    return ret;
  }
}

ssize_t
sendto (
    int sockfd,
    const void *buf,
    size_t len,
    int flags,
    const struct sockaddr *dest_addr,
    socklen_t addrlen)
{
  if (should_inject_ewouldblock ()) {
    errno = EWOULDBLOCK;
    return -1;
  } else {
    ssize_t ret = ((ssize_t (*) (int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen)) (
        dlsym (RTLD_NEXT, "sendto"))) (sockfd, buf, len, flags, dest_addr, addrlen);
    if (ret != -1) {
      increment_messages_sent (1);
    }
    return ret;
  }
}

ssize_t
sendmsg (int sockfd, const struct msghdr *msg, int flags)
{
  if (should_inject_ewouldblock ()) {
    errno = EWOULDBLOCK;
    return -1;
  } else {
    ssize_t ret = ((ssize_t (*) (int sockfd, const struct msghdr *msg, int flags)) (
        dlsym (RTLD_NEXT, "sendmsg"))) (sockfd, msg, flags);
    if (ret != -1) {
      increment_messages_sent (1);
    }
    return ret;
  }
}

int
sendmmsg (int sockfd, struct mmsghdr *msgvec, unsigned int vlen, int flags)
{
  if (should_inject_ewouldblock ()) {
    errno = EWOULDBLOCK;
    return -1;
  } else {
    int ret = ((int (*) (int sockfd, struct mmsghdr *msgvec, unsigned int vlen, int flags)) (
        dlsym (RTLD_NEXT, "sendmmsg"))) (sockfd, msgvec, vlen, flags);
    if (ret != -1) {
      increment_messages_sent (ret);
    }
    return ret;
  }
}
