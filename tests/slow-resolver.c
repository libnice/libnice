/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2007 Nokia Corporation. All rights reserved.
 *  Contact: Kai Vehmanen
 * (C) 2025 Johan Sternerup <johast@axis.com>
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
 *   Kai Vehmanen, Nokia
 *   Johan Sternerup, Axis Communications AB
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
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sched.h>
#include <time.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int
fake_getaddrinfo (const char *__restrict __name,
    const char *__restrict __service,
    const struct addrinfo *__restrict __req,
    struct addrinfo **__restrict __pai);

int
fake_getaddrinfo (const char *__restrict __name,
    const char *__restrict __service,
    const struct addrinfo *__restrict __req, struct addrinfo **__restrict __pai)
{
  static int in_progress[2] = { 0 };
  static int cancel = 0;
  static int one = 1;
  static int zero = 0;

  int stun = 0;
  int turn = 0;

  if (strstr (__name, "query") != NULL) {
    /* test code asks for how many resolve operations are in progress */
    int sum = 0;
    int tmp;
    __atomic_load (&in_progress[0], &tmp, __ATOMIC_SEQ_CST);
    sum += tmp;
    __atomic_load (&in_progress[1], &tmp, __ATOMIC_SEQ_CST);
    sum += tmp;
    return sum;
  } else if (strstr (__name, "cancel") != NULL) {
    /* test code tells us to cancel (stop blocking) resolve operations */
    __atomic_store (&cancel, &one, __ATOMIC_SEQ_CST);
    return 0;
  } else if (strstr (__name, "block") != NULL) {
    /* test code tells us to block all resolve operations containing "bogus.nonexisting" */
    __atomic_store (&cancel, &zero, __ATOMIC_SEQ_CST);
    return 0;
  } else if (strstr (__name, "stun") != NULL) {
    /* signal stun resolving in progress */
    __atomic_store (&in_progress[0], &one, __ATOMIC_SEQ_CST);
    stun = 1;
  } else if (strstr (__name, "turn") != NULL) {
    /* signal turn resolving in progress */
    __atomic_store (&in_progress[1], &one, __ATOMIC_SEQ_CST);
    turn = 1;
  } else {
    return EAI_ADDRFAMILY;
  }

  /* loop until we get cancel */
  while (1) {
    struct timespec ts;
    int tmp;

    __atomic_load (&cancel, &tmp, __ATOMIC_SEQ_CST);
    if (tmp == 1) {
      break;
    }

    ts.tv_sec = 0;
    ts.tv_nsec = 1000;
    nanosleep (&ts, NULL);
  }

  if (stun == 1) {
    /* signal stun resolved */
    __atomic_store (&in_progress[0], &zero, __ATOMIC_SEQ_CST);
  } else if (turn == 1) {
    /* signal turn resolved */
    __atomic_store (&in_progress[1], &zero, __ATOMIC_SEQ_CST);
  }

  return EAI_ADDRFAMILY;
}

int
getaddrinfo (const char *__restrict __name,
    const char *__restrict __service,
    const struct addrinfo *__restrict __req, struct addrinfo **__restrict __pai)
{
  static int
      (*real_getaddrinfo) (const char *__restrict __name,
      const char *__restrict __service,
      const struct addrinfo * __restrict __req,
      struct addrinfo ** __restrict __pai) = NULL;

  if (__name != NULL && strstr (__name, "bogus.nonexisting") != NULL &&
      (__req == NULL || ((__req->ai_flags & AI_NUMERICHOST) == 0))) {
    return fake_getaddrinfo (__name, __service, __req, __pai);
  }

  if (real_getaddrinfo == NULL) {
    real_getaddrinfo = dlsym (RTLD_NEXT, "getaddrinfo");
  }

  return real_getaddrinfo (__name, __service, __req, __pai);
}
