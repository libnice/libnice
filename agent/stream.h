/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2006-2010 Collabora Ltd.
 *  Contact: Youness Alaoui
 * (C) 2006-2010 Nokia Corporation. All rights reserved.
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

#ifndef _NICE_STREAM_H
#define _NICE_STREAM_H

#include <glib.h>

typedef struct _Stream Stream;

#include "component.h"
#include "random.h"

G_BEGIN_DECLS

/* Maximum and default sizes for ICE attributes, 
 * last updated from ICE ID-19 
 * (the below sizes include the terminating NULL): */

#define NICE_STREAM_MAX_UFRAG   256 + 1  /* ufrag + NULL */
#define NICE_STREAM_MAX_UNAME   256 * 2 + 1 + 1 /* 2*ufrag + colon + NULL */
#define NICE_STREAM_MAX_PWD     256 + 1  /* pwd + NULL */
#define NICE_STREAM_DEF_UFRAG   4 + 1    /* ufrag + NULL */
#define NICE_STREAM_DEF_PWD     22 + 1   /* pwd + NULL */

struct _Stream
{
  gchar *name;
  guint id;
  guint n_components;
  gboolean initial_binding_request_received;
  GSList *components; /* list of 'Component' structs */
  GSList *conncheck_list;         /* list of CandidateCheckPair items */
  gchar local_ufrag[NICE_STREAM_MAX_UFRAG];
  gchar local_password[NICE_STREAM_MAX_PWD];
  gchar remote_ufrag[NICE_STREAM_MAX_UFRAG];
  gchar remote_password[NICE_STREAM_MAX_PWD];
  gboolean gathering;
  gboolean gathering_started;
  gint tos;
};


Stream *
stream_new (guint n_components, NiceAgent *agent);

void
stream_close (Stream *stream);

void
stream_free (Stream *stream);

gboolean
stream_all_components_ready (const Stream *stream);

Component *
stream_find_component_by_id (const Stream *stream, guint id);

void
stream_initialize_credentials (Stream *stream, NiceRNG *rng);

void
stream_restart (NiceAgent *agent, Stream *stream);

G_END_DECLS

#endif /* _NICE_STREAM_H */

