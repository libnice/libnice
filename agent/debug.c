/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2008 Collabora Ltd.
 *  Contact: Youness Alaoui
 * (C) 2008 Nokia Corporation. All rights reserved.
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

#include "debug.h"

#include "stunagent.h"
#include "pseudotcp.h"

#include "agent-priv.h"

static int debug_enabled = 0;

#define NICE_DEBUG_STUN 1
#define NICE_DEBUG_NICE 2
#define NICE_DEBUG_PSEUDOTCP 4
#define NICE_DEBUG_PSEUDOTCP_VERBOSE 8

static const GDebugKey keys[] = {
  { (gchar *)"stun",  NICE_DEBUG_STUN },
  { (gchar *)"nice",  NICE_DEBUG_NICE },
  { (gchar *)"pseudotcp",  NICE_DEBUG_PSEUDOTCP },
  { (gchar *)"pseudotcp-verbose",  NICE_DEBUG_PSEUDOTCP_VERBOSE },
  { NULL, 0},
};

static void
stun_handler (const char *format, va_list ap) G_GNUC_PRINTF (1, 0);

static void
stun_handler (const char *format, va_list ap)
{
  g_logv ("libnice-stun", G_LOG_LEVEL_DEBUG, format, ap);
}

void nice_debug_init (void)
{
  static gboolean debug_initialized = FALSE;
  const gchar *flags_string;
  const gchar *gflags_string;
  guint flags = 0;

  if (!debug_initialized) {
    debug_initialized = TRUE;

    flags_string = g_getenv ("NICE_DEBUG");
    gflags_string = g_getenv ("G_MESSAGES_DEBUG");

    if (flags_string)
      flags = g_parse_debug_string (flags_string, keys,  4);
    if (gflags_string && strstr (gflags_string, "libnice-pseudotcp-verbose"))
      flags |= NICE_DEBUG_PSEUDOTCP_VERBOSE;

    stun_set_debug_handler (stun_handler);
    nice_debug_enable (TRUE);

    /* Set verbose before normal so that if we use 'all', then only
       normal debug is enabled, we'd need to set pseudotcp-verbose without the
       pseudotcp flag in order to actually enable verbose pseudotcp */
    if (flags & NICE_DEBUG_PSEUDOTCP_VERBOSE)
      pseudo_tcp_set_debug_level (PSEUDO_TCP_DEBUG_VERBOSE);
    else
      pseudo_tcp_set_debug_level (PSEUDO_TCP_DEBUG_NORMAL);
  }
}

#ifndef NDEBUG
gboolean nice_debug_is_enabled (void)
{
  return debug_enabled;
}
#else
/* Defined in agent-priv.h. */
#endif

void nice_debug_enable (gboolean with_stun)
{
  nice_debug_init ();
  debug_enabled = 1;
  if (with_stun)
    stun_debug_enable ();
}
void nice_debug_disable (gboolean with_stun)
{
  nice_debug_init ();
  debug_enabled = 0;
  if (with_stun)
    stun_debug_disable ();
}

#ifndef NDEBUG
void nice_debug (const char *fmt, ...)
{
  va_list ap;
  if (debug_enabled) {
    va_start (ap, fmt);
    g_logv (G_LOG_DOMAIN, G_LOG_LEVEL_DEBUG, fmt, ap);
    va_end (ap);
  }
}
#else
/* Defined in agent-priv.h. */
#endif
