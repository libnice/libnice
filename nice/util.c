/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2006, 2007 Collabora Ltd.
 *  Contact: Dafydd Harries
 * (C) 2006, 2007 Nokia Corporation. All rights reserved.
 *  Contact: Kai Vehmanen
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
 *   Dafydd Harries, Collabora Ltd.
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

#include <arpa/inet.h>

#include <stdlib.h>
#include <string.h>

#include "agent.h"

#include "util.h"

/* format is:
 *   type/ip/port/username/password
 */
NiceCandidate *
nice_candidate_from_string (const gchar *s)
{
  NiceCandidateType type;
  NiceCandidate *candidate;
  guint32 ip;
  guint16 port;
  gchar **bits;

  if (s == NULL || s[0] == '\0')
    return NULL;

  bits = g_strsplit (s, "/", 5);

  if (g_strv_length (bits) != 5)
    goto ERROR;

  switch (bits[0][0])
    {
    case 'H':
      type = NICE_CANDIDATE_TYPE_HOST;
      break;
    case 'S':
      type = NICE_CANDIDATE_TYPE_SERVER_REFLEXIVE;
      break;
    case 'P':
      type = NICE_CANDIDATE_TYPE_PEER_REFLEXIVE;
      break;
    case 'R':
      type = NICE_CANDIDATE_TYPE_RELAYED;
      break;
    default:
      goto ERROR;
    }

  /* extract IP address */

  if (inet_pton (AF_INET, bits[1], &ip) < 1)
    goto ERROR;

  /* extract port */

  port = strtol (bits[2], NULL, 10);

  candidate = nice_candidate_new (type);
  nice_address_set_ipv4 (&candidate->addr, ntohl (ip));
  candidate->addr.port = port;

  memcpy (candidate->username, bits[3],
      MIN (strlen (bits[3]), sizeof (candidate->username)));
  memcpy (candidate->password, bits[4],
      MIN (strlen (bits[4]), sizeof (candidate->password)));

  g_strfreev (bits);
  return candidate;

ERROR:
  g_strfreev (bits);
  return NULL;
}

gchar *
nice_candidate_to_string (NiceCandidate *candidate)
{
  gchar addr_tmp[NICE_ADDRESS_STRING_LEN];
  gchar *ret;
  gchar type;

  switch (candidate->type)
    {
    case NICE_CANDIDATE_TYPE_HOST:
      type = 'H';
      break;
    case NICE_CANDIDATE_TYPE_SERVER_REFLEXIVE:
      type = 'S';
      break;
    case NICE_CANDIDATE_TYPE_PEER_REFLEXIVE:
      type = 'P';
      break;
    case NICE_CANDIDATE_TYPE_RELAYED:
      type = 'R';
      break;
    default:
      return NULL;
    }

  nice_address_to_string (&(candidate->addr), addr_tmp);
  ret = g_strdup_printf ("%c/%s/%d/%s/%s", type, addr_tmp,
      candidate->addr.port, candidate->username, candidate->password);
  return ret;
}

