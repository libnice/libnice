/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2008-2009 Collabora Ltd.
 *  Contact: Youness Alaoui
 * (C) 2007 Nokia Corporation. All rights reserved.
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
 *   Youness Alaoui, Collabora Ltd.
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

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>

#include "debug.h"


static int debug_enabled = 1;

void stun_debug_enable (void) {
  debug_enabled = 1;
}
void stun_debug_disable (void) {
  debug_enabled = 0;
}

#if     __GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ > 4)
#define GNUC_PRINTF(format_idx, arg_idx) \
  __attribute__((__format__ (__printf__, format_idx, arg_idx)))
#else
#define GNUC_PRINTF( format_idx, arg_idx)
#endif

static void
default_handler (const char *format, va_list ap) GNUC_PRINTF (1, 0);

static void
default_handler (const char *format, va_list ap)
{
  vfprintf (stderr, format, ap);
  fprintf (stderr, "\n");
}

static StunDebugHandler handler = default_handler;

void stun_debug (const char *fmt, ...)
{
  va_list ap;
  if (debug_enabled) {
    va_start (ap, fmt);
    handler (fmt, ap);
    va_end (ap);
  }
}

void stun_debug_bytes (const char *prefix, const void *data, size_t len)
{
  size_t i;
  size_t prefix_len = strlen (prefix);
  char *bytes;

  if (!debug_enabled)
    return;

  bytes = malloc (prefix_len + 2 + (len * 2) + 1);
  bytes[0] = 0;
  strcpy (bytes, prefix);
  strcpy (bytes + prefix_len, "0x");

  for (i = 0; i < len; i++)
    sprintf (bytes + prefix_len + 2 + (i * 2), "%02x", ((const unsigned char *)data)[i]);

  stun_debug ("%s", bytes);
  free (bytes);
}


void stun_set_debug_handler (StunDebugHandler _handler)
{
  if (_handler == NULL)
    _handler = default_handler;

  handler = _handler;
}

