/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2007 Nokia Corporation. All rights reserved.
 *  Contact: Rémi Denis-Courmont
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
 *   Kai Vehmanen, Nokia
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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <sys/types.h>
#include <sys/socket.h>

#include "stun-msg.h"

#include <assert.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>


/**
 * @param msg valid STUN message
 * @param pw nul-terminated local username fragment
 * @return 0 if the username in the message is valid and matches
 * the local username fragment, EPERM if the username was incorrect,
 * and ENOENT if there was no USERNAME attribute
 */
int stun_verify_username (const uint8_t *msg, const char *local_ufrag, uint32_t compat)
{
  const char *username, *n;
  uint16_t username_len;
  uint16_t local_username_len;

  assert (msg != NULL);
  username = (const char *)stun_find (msg, STUN_USERNAME, &username_len);
  if (username == NULL)
  {
    DBG ("STUN auth error: no USERNAME attribute!\n");
    return ENOENT;
  }
  if (compat == 1) {
    local_username_len = strlen (local_ufrag);
  } else {
    n = strchr (username, ':');
    if (n == NULL)
    {
      DBG ("STUN auth error: no colon in USERNAME!\n");
      return EPERM;
    }
    local_username_len = n - username;
  }
  if (strncmp(username, local_ufrag, local_username_len) != 0)
  {
    DBG ("STUN auth error: local ufrag doesn't match (uname:%s,ufrag:%s)!\n", username,local_ufrag);
    return EPERM;
  }
  
  return 0;
}

