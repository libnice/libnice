/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2006-2009 Collabora Ltd.
 *  Contact: Youness Alaoui
 * (C) 2006-2009 Nokia Corporation. All rights reserved.
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
#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <string.h>

#include "stream.h"

/* Simple tracking for the number of alive streams. These must be accessed
 * atomically. */
static volatile unsigned int n_streams_created = 0;
static volatile unsigned int n_streams_destroyed = 0;

G_DEFINE_TYPE (NiceStream, nice_stream, G_TYPE_OBJECT);

static void
nice_stream_finalize (GObject *obj);

/*
 * @file stream.c
 * @brief ICE stream functionality
 */
NiceStream *
nice_stream_new (guint stream_id, guint n_components, NiceAgent *agent)
{
  NiceStream *stream = NULL;
  guint n;

  stream = g_object_new (NICE_TYPE_STREAM, NULL);

  stream->id = stream_id;

  /* Create the components. */
  for (n = 0; n < n_components; n++) {
    NiceComponent *component = NULL;

    component = nice_component_new (n + 1, agent, stream);
    stream->components = g_slist_append (stream->components, component);
  }

  stream->n_components = n_components;

  stream->peer_gathering_done = !agent->use_ice_trickle;

  return stream;
}

void
nice_stream_close (NiceAgent *agent, NiceStream *stream)
{
  GSList *i;

  for (i = stream->components; i; i = i->next) {
    NiceComponent *component = i->data;
    nice_component_close (agent, component);
  }
}

NiceComponent *
nice_stream_find_component_by_id (NiceStream *stream, guint id)
{
  GSList *i;

  for (i = stream->components; i; i = i->next) {
    NiceComponent *component = i->data;
    if (component && component->id == id)
      return component;
  }

  return NULL;
}

/*
 * Initialized the local crendentials for the stream.
 */
void
nice_stream_initialize_credentials (NiceStream *stream, NiceRNG *rng)
{
  /* note: generate ufrag/pwd for the stream (see ICE 15.4.
   *       '"ice-ufrag" and "ice-pwd" Attributes', ID-19) */
  nice_rng_generate_bytes_print (rng, NICE_STREAM_DEF_UFRAG - 1, stream->local_ufrag);
  nice_rng_generate_bytes_print (rng, NICE_STREAM_DEF_PWD - 1, stream->local_password);
}

/*
 * Resets the stream state to that of a ICE restarted
 * session.
 */
void
nice_stream_restart (NiceStream *stream, NiceAgent *agent)
{
  GSList *i;

  /* step: clean up all connectivity checks */
  conn_check_prune_stream (agent, stream);

  stream->initial_binding_request_received = FALSE;

  nice_stream_initialize_credentials (stream, agent->rng);

  for (i = stream->components; i; i = i->next) {
    NiceComponent *component = i->data;

    nice_component_restart (component);
  }
}

static void
nice_stream_class_init (NiceStreamClass *klass)
{
  GObjectClass *object_class = G_OBJECT_CLASS (klass);

  object_class->finalize = nice_stream_finalize;
}

static void
nice_stream_init (NiceStream *stream)
{
  g_atomic_int_inc (&n_streams_created);
  nice_debug ("Created NiceStream (%u created, %u destroyed)",
      n_streams_created, n_streams_destroyed);

  stream->n_components = 0;
  stream->initial_binding_request_received = FALSE;
}

/* Must be called with the agent lock released as it could dispose of
 * NiceIOStreams. */
static void
nice_stream_finalize (GObject *obj)
{
  NiceStream *stream;

  stream = NICE_STREAM (obj);

  g_free (stream->name);
  g_slist_free_full (stream->components, (GDestroyNotify) g_object_unref);

  g_atomic_int_inc (&n_streams_destroyed);
  nice_debug ("Destroyed NiceStream (%u created, %u destroyed)",
      n_streams_created, n_streams_destroyed);

  G_OBJECT_CLASS (nice_stream_parent_class)->finalize (obj);
}
