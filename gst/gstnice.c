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
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "gstnicesrc.h"
#include "gstnicesink.h"

static gboolean
plugin_init (GstPlugin *plugin)
{
  if (!gst_element_register (plugin, "nicesrc",
        GST_RANK_NONE, GST_TYPE_NICE_SRC))
    return FALSE;

  if (!gst_element_register (plugin, "nicesink",
        GST_RANK_NONE, GST_TYPE_NICE_SINK))
    return FALSE;

  return TRUE;
}

#if GST_CHECK_VERSION (1,0,0)
#define PLUGIN_NAME nice
#else
#define PLUGIN_NAME "nice"
#endif

GST_PLUGIN_DEFINE (
    GST_VERSION_MAJOR,
    GST_VERSION_MINOR,
    PLUGIN_NAME,
    "Interactive UDP connectivity establishment",
    plugin_init, VERSION, "LGPL", PACKAGE_NAME,
    "http://telepathy.freedesktop.org/wiki/");

