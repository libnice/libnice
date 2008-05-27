/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2007 Nokia Corporation. All rights reserved.
 *  Contact: Rémi Denis-Courmont
 * COPYRIGHT (C) 1986 Gary S. Brown 
 *  See documentation of the function crc32() below.
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
 *   Rémi Denis-Courmont, Nokia
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

#include <sys/socket.h>
#include <netinet/in.h> /* htons() */
#include <assert.h>

#include "crc32.h"
#include "stun-msg.h"

uint32_t stun_fingerprint (const uint8_t *msg, size_t len)
{
  struct iovec iov[3];
  uint16_t fakelen = htons (len - 20u);

  assert (len >= 28u);

  iov[0].iov_base = (void *)msg;
  iov[0].iov_len = 2;
  iov[1].iov_base = &fakelen;
  iov[1].iov_len = 2;
  iov[2].iov_base = (void *)(msg + 4);
  /* first 4 bytes done, last 8 bytes not summed */
  iov[2].iov_len = len - 12u;

  return crc32 (iov, sizeof (iov) / sizeof (iov[0])) ^ 0x5354554e;
}
