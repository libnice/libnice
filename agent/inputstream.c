/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2010, 2013 Collabora Ltd.
 *  Contact: Youness Alaoui
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
 *   Philip Withnall, Collabora Ltd.
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

/**
 * SECTION:nice_input_stream
 * @short_description: #GInputStream implementation for libnice
 * @see_also: #NiceAgent
 * @include: inputstream.h
 * @stability: Stable
 *
 * #NiceInputStream is a #GInputStream wrapper for a single reliable stream and
 * component of a #NiceAgent. Given an existing reliable #NiceAgent, plus the
 * IDs of an existing stream and component in the agent, it will provide a
 * streaming input interface for reading from the given component.
 *
 * A single #NiceInputStream can only be used with a single agent, stream and
 * component triple, and will be closed as soon as that stream is removed from
 * the agent (e.g. if nice_agent_remove_stream() is called from another thread).
 * If g_input_stream_close() is called on a #NiceInputStream, the input stream
 * will be marked as closed, but the underlying #NiceAgent stream will not be
 * removed. Use nice_agent_remove_stream() to do that.
 *
 * Since: 0.1.5
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "inputstream.h"
#include "agent-priv.h"

static void streams_removed_cb (NiceAgent *agent, guint *stream_ids,
    gpointer user_data);

G_DEFINE_TYPE (NiceInputStream, nice_input_stream, G_TYPE_INPUT_STREAM);

enum
{
  PROP_AGENT = 1,
  PROP_STREAM_ID,
  PROP_COMPONENT_ID,
};

struct _NiceInputStreamPrivate
{
  GWeakRef/*<NiceAgent>*/ agent_ref;
  guint stream_id;
  guint component_id;
};

static void nice_input_stream_dispose (GObject *object);
static void nice_input_stream_get_property (GObject *object, guint prop_id,
    GValue *value, GParamSpec *pspec);
static void nice_input_stream_set_property (GObject *object, guint prop_id,
    const GValue *value, GParamSpec *pspec);
static gssize nice_input_stream_read (GInputStream *stream, void *buffer,
    gsize count, GCancellable *cancellable, GError **error);

static void
nice_input_stream_class_init (NiceInputStreamClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
  GInputStreamClass *stream_class = G_INPUT_STREAM_CLASS (klass);

  g_type_class_add_private (klass, sizeof (NiceInputStreamPrivate));

  gobject_class->set_property = nice_input_stream_set_property;
  gobject_class->get_property = nice_input_stream_get_property;
  gobject_class->dispose = nice_input_stream_dispose;

  stream_class->read_fn = nice_input_stream_read;

  /**
   * NiceInputStream:agent:
   *
   * The #NiceAgent to wrap with an input stream. This must be an existing
   * reliable agent.
   *
   * A reference is not held on the #NiceAgent. If the agent is destroyed before
   * the #NiceInputStream, %G_IO_ERROR_CLOSED will be returned for all
   * subsequent operations on the stream.
   *
   * Since: 0.1.5
   */
  g_object_class_install_property (gobject_class, PROP_AGENT,
      g_param_spec_object ("agent",
          "NiceAgent",
          "The underlying NiceAgent",
          NICE_TYPE_AGENT,
          G_PARAM_CONSTRUCT_ONLY | G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

  /**
   * NiceInputStream:stream-id:
   *
   * ID of the stream to use in the #NiceInputStream:agent.
   *
   * Since: 0.1.5
   */
  g_object_class_install_property (gobject_class, PROP_STREAM_ID,
      g_param_spec_uint (
          "stream-id",
          "Agent’s stream ID",
          "The ID of the agent’s stream to wrap.",
          0, G_MAXUINT,
          0,
          G_PARAM_CONSTRUCT_ONLY | G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

  /**
   * NiceInputStream:component-id:
   *
   * ID of the component to use in the #NiceInputStream:agent.
   *
   * Since: 0.1.5
   */
  g_object_class_install_property (gobject_class, PROP_COMPONENT_ID,
      g_param_spec_uint (
          "component-id",
          "Agent’s component ID",
          "The ID of the agent’s component to wrap.",
          0, G_MAXUINT,
          0,
          G_PARAM_CONSTRUCT_ONLY | G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));
}

static void
nice_input_stream_dispose (GObject *object)
{
  NiceInputStream *self = NICE_INPUT_STREAM (object);
  NiceAgent *agent;

  agent = g_weak_ref_get (&self->priv->agent_ref);
  if (agent != NULL) {
    g_signal_handlers_disconnect_by_func (agent, streams_removed_cb, self);
    g_object_unref (agent);
  }

  g_weak_ref_clear (&self->priv->agent_ref);

  G_OBJECT_CLASS (nice_input_stream_parent_class)->dispose (object);
}

static void
nice_input_stream_get_property (GObject *object, guint prop_id,
    GValue *value, GParamSpec *pspec)
{
  NiceInputStream *self = NICE_INPUT_STREAM (object);

  switch (prop_id) {
    case PROP_AGENT:
      g_value_take_object (value, g_weak_ref_get (&self->priv->agent_ref));
      break;
    case PROP_STREAM_ID:
      g_value_set_uint (value, self->priv->stream_id);
      break;
    case PROP_COMPONENT_ID:
      g_value_set_uint (value, self->priv->component_id);
      break;
     default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
    }
}

static void
nice_input_stream_set_property (GObject *object, guint prop_id,
    const GValue *value, GParamSpec *pspec)
{
  NiceInputStream *self = NICE_INPUT_STREAM (object);

  switch (prop_id) {
    case PROP_AGENT: {
      /* Construct only. */
      NiceAgent *agent = g_value_dup_object (value);
      g_weak_ref_set (&self->priv->agent_ref, agent);

      /* agent may be NULL if the stream is being constructed by
       * nice_io_stream_get_input_stream() after the NiceIOStream’s agent has
       * already been finalised. */
      if (agent != NULL) {
        g_signal_connect (agent, "streams-removed",
            (GCallback) streams_removed_cb, self);
        g_object_unref (agent);
      }

      break;
    }
    case PROP_STREAM_ID:
      /* Construct only. */
      self->priv->stream_id = g_value_get_uint (value);
      break;
    case PROP_COMPONENT_ID:
      /* Construct only. */
      self->priv->component_id = g_value_get_uint (value);
      break;
     default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
    }
}

static void
nice_input_stream_init (NiceInputStream *stream)
{
  stream->priv = G_TYPE_INSTANCE_GET_PRIVATE (stream, NICE_TYPE_INPUT_STREAM,
      NiceInputStreamPrivate);

  g_weak_ref_init (&stream->priv->agent_ref, NULL);
}

/**
 * nice_input_stream_new:
 * @agent: A #NiceAgent
 * @stream_id: The ID of the agent’s stream to wrap
 * @component_id: The ID of the agent’s component to wrap
 *
 * Create a new #NiceInputStream wrapping the given stream/component from
 * @agent, which must be a reliable #NiceAgent.
 *
 * The constructed #NiceInputStream will not hold a reference to @agent. If
 * @agent is destroyed before the input stream, %G_IO_ERROR_CLOSED will be
 * returned for all subsequent operations on the stream.
 *
 * Returns: The new #NiceInputStream object
 *
 * Since: 0.1.5
 */
NiceInputStream *
nice_input_stream_new (NiceAgent *agent, guint stream_id, guint component_id)
{
  g_return_val_if_fail (NICE_IS_AGENT (agent), NULL);
  g_return_val_if_fail (stream_id >= 1, NULL);
  g_return_val_if_fail (component_id >= 1, NULL);

  return g_object_new (NICE_TYPE_INPUT_STREAM,
      "agent", agent,
      "stream-id", stream_id,
      "component-id", component_id,
      NULL);
}

static gssize
nice_input_stream_read (GInputStream *stream, void *buffer, gsize count,
    GCancellable *cancellable, GError **error)
{
  NiceInputStreamPrivate *priv = NICE_INPUT_STREAM (stream)->priv;
  NiceAgent *agent;  /* owned */
  gssize len;

  /* Closed streams are not readable. */
  if (g_input_stream_is_closed (stream))
    return 0;

  /* Has the agent disappeared? */
  agent = g_weak_ref_get (&priv->agent_ref);
  if (agent == NULL) {
    g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_CLOSED,
        "Stream is closed due to the NiceAgent being finalised.");
    return -1;
  }

  len = nice_agent_recv (agent, priv->stream_id, priv->component_id,
                         buffer, count, cancellable, error);

  g_object_unref (agent);

  return len;
}

static void
streams_removed_cb (NiceAgent *agent, guint *stream_ids, gpointer user_data)
{
  NiceInputStream *self = NICE_INPUT_STREAM (user_data);
  guint i;

  for (i = 0; stream_ids[i] != 0; i++) {
    if (stream_ids[i] == self->priv->stream_id) {
      /* The socket has been closed. */
      g_input_stream_close (G_INPUT_STREAM (self), NULL, NULL);
      break;
    }
  }
}
