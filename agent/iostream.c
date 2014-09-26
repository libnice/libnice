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

/***
 * SECTION:nice_io_stream
 * @short_description: #GIOStream implementation for libnice
 * @see_also: #NiceAgent
 * @include: iostream.h
 * @stability: Stable
 *
 * #NiceIOStream is a #GIOStream wrapper for a single reliable stream and
 * component of a #NiceAgent. Given an existing reliable #NiceAgent, plus the
 * IDs of an existing stream and component in the agent, it will provide a
 * streaming input and output interface for communication over the given
 * component.
 *
 * A single #NiceIOStream can only be used with a single agent, stream and
 * component triple, and will be closed as soon as that stream is removed from
 * the agent (e.g. if nice_agent_remove_stream() is called from another thread).
 * If g_io_stream_close() is called on a #NiceIOStream, the I/O stream and
 * underlying #NiceAgent stream will be closed in both directions, but the
 * underlying stream will not be removed. Use nice_agent_remove_stream() to do
 * that, but only do so after g_io_stream_close() has completed, or the stream
 * will return broken pipe errors.
 *
 * Since: 0.1.5
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "iostream.h"
#include "inputstream.h"
#include "outputstream.h"

G_DEFINE_TYPE (NiceIOStream, nice_io_stream, G_TYPE_IO_STREAM);

enum
{
  PROP_AGENT = 1,
  PROP_STREAM_ID,
  PROP_COMPONENT_ID,
};

struct _NiceIOStreamPrivate
{
  GWeakRef/*<NiceAgent>*/ agent_ref;
  guint stream_id;
  guint component_id;

  GInputStream *input_stream;  /* owned */
  GOutputStream *output_stream;  /* owned */
};

static void nice_io_stream_dispose (GObject *object);
static void nice_io_stream_get_property (GObject *object, guint prop_id,
    GValue *value, GParamSpec *pspec);
static void nice_io_stream_set_property (GObject *object, guint prop_id,
    const GValue *value, GParamSpec *pspec);
static GInputStream *nice_io_stream_get_input_stream (GIOStream *stream);
static GOutputStream *nice_io_stream_get_output_stream (GIOStream *stream);

static void streams_removed_cb (NiceAgent *agent, guint *stream_ids,
    gpointer user_data);

static void
nice_io_stream_class_init (NiceIOStreamClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
  GIOStreamClass *stream_class = G_IO_STREAM_CLASS (klass);

  g_type_class_add_private (klass, sizeof (NiceIOStreamPrivate));

  gobject_class->set_property = nice_io_stream_set_property;
  gobject_class->get_property = nice_io_stream_get_property;
  gobject_class->dispose = nice_io_stream_dispose;

  stream_class->get_input_stream = nice_io_stream_get_input_stream;
  stream_class->get_output_stream = nice_io_stream_get_output_stream;

  /*
   * NiceIOStream:agent:
   *
   * The #NiceAgent to wrap with an I/O stream. This must be an existing
   * reliable agent.
   *
   * A reference is not held on the #NiceAgent. If the agent is destroyed before
   * the #NiceIOStream, %G_IO_ERROR_CLOSED will be returned for all subsequent
   * operations on the stream.
   *
   * Since: 0.1.5
   */
  g_object_class_install_property (gobject_class, PROP_AGENT,
      g_param_spec_object ("agent",
          "NiceAgent",
          "The underlying NiceAgent",
          NICE_TYPE_AGENT,
          G_PARAM_CONSTRUCT_ONLY | G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

  /*
   * NiceIOStream:stream-id:
   *
   * ID of the stream to use in the #NiceIOStream:agent.
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

  /*
   * NiceIOStream:component-id:
   *
   * ID of the component to use in the #NiceIOStream:agent.
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
nice_io_stream_init (NiceIOStream *self)
{
  self->priv = G_TYPE_INSTANCE_GET_PRIVATE (self, NICE_TYPE_IO_STREAM,
      NiceIOStreamPrivate);

  g_weak_ref_init (&self->priv->agent_ref, NULL);

  /* Invalidate the stream/component IDs to begin with. */
  self->priv->stream_id = 0;
  self->priv->component_id = 0;
}

static void
nice_io_stream_dispose (GObject *object)
{
  NiceIOStream *self = NICE_IO_STREAM (object);
  NiceAgent *agent;

  /* Ensure the stream is closed before continuing. Otherwise, if the input or
   * output streams haven’t yet been lazily created, closing the stream in
   * g_io_stream_dispose() will lazily create them, but NiceAgent will be NULL
   * by that point and things will explode. */
  if (!g_io_stream_is_closed (G_IO_STREAM (object)))
    g_io_stream_close (G_IO_STREAM (object), NULL, NULL);

  /* Clear everything away. */
  if (self->priv->input_stream != NULL)
    g_object_unref (self->priv->input_stream);
  self->priv->input_stream = NULL;

  if (self->priv->output_stream != NULL)
    g_object_unref (self->priv->output_stream);
  self->priv->output_stream = NULL;

  agent = g_weak_ref_get (&self->priv->agent_ref);
  if (agent != NULL) {
    g_signal_handlers_disconnect_by_func (agent, streams_removed_cb, self);
    g_object_unref (agent);
  }

  g_weak_ref_clear (&self->priv->agent_ref);

  G_OBJECT_CLASS (nice_io_stream_parent_class)->dispose (object);
}

static void
nice_io_stream_get_property (GObject *object, guint prop_id,
    GValue *value, GParamSpec *pspec)
{
  NiceIOStream *self = NICE_IO_STREAM (object);

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
nice_io_stream_set_property (GObject *object, guint prop_id,
    const GValue *value, GParamSpec *pspec)
{
  NiceIOStream *self = NICE_IO_STREAM (object);

  switch (prop_id) {
    case PROP_AGENT: {
      /* Construct only. */
      NiceAgent *agent = g_value_dup_object (value);
      g_weak_ref_set (&self->priv->agent_ref, agent);
      g_signal_connect (agent, "streams-removed",
          (GCallback) streams_removed_cb, self);
      g_object_unref (agent);

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

/***
 * nice_io_stream_new:
 * @agent: A #NiceAgent
 * @stream_id: The ID of the agent’s stream to wrap
 * @component_id: The ID of the agent’s component to wrap
 *
 * Create a new #NiceIOStream wrapping the given stream/component from @agent,
 * which must be a reliable #NiceAgent.
 *
 * The constructed #NiceIOStream will not hold a reference to @agent. If @agent
 * is destroyed before the I/O stream, %G_IO_ERROR_CLOSED will be returned for
 * all subsequent operations on the stream.
 *
 * Returns: The new #NiceIOStream object
 *
 * Since: 0.1.5
 */
GIOStream *
nice_io_stream_new (NiceAgent *agent, guint stream_id, guint component_id)
{
  g_return_val_if_fail (NICE_IS_AGENT (agent), NULL);
  g_return_val_if_fail (stream_id > 0, NULL);
  g_return_val_if_fail (component_id > 0, NULL);

  return g_object_new (NICE_TYPE_IO_STREAM,
      "agent", agent,
      "stream-id", stream_id,
      "component-id", component_id,
      NULL);
}

static GInputStream *
nice_io_stream_get_input_stream (GIOStream *stream)
{
  NiceIOStream *self = NICE_IO_STREAM (stream);

  if (G_UNLIKELY (self->priv->input_stream == NULL)) {
    NiceAgent *agent;

    /* Note that agent may be NULL here. NiceInputStream must support
     * construction with a NULL agent. */
    agent = g_weak_ref_get (&self->priv->agent_ref);
    self->priv->input_stream = G_INPUT_STREAM (nice_input_stream_new (
            agent, self->priv->stream_id, self->priv->component_id));
    if (agent != NULL)
      g_object_unref (agent);
  }

  return self->priv->input_stream;
}

static GOutputStream *
nice_io_stream_get_output_stream (GIOStream *stream)
{
  NiceIOStream *self = NICE_IO_STREAM (stream);

  if (G_UNLIKELY (self->priv->output_stream == NULL)) {
    NiceAgent *agent;

    /* Note that agent may be NULL here. NiceOutputStream must support
     * construction with a NULL agent. */
    agent = g_weak_ref_get (&self->priv->agent_ref);
    self->priv->output_stream = g_object_new (NICE_TYPE_OUTPUT_STREAM,
        "agent", agent,
        "stream-id", self->priv->stream_id,
        "component-id", self->priv->component_id,
      NULL);

    if (agent != NULL)
      g_object_unref (agent);
  }

  return self->priv->output_stream;
}

static void
streams_removed_cb (NiceAgent *agent, guint *stream_ids, gpointer user_data)
{
  NiceIOStream *self = NICE_IO_STREAM (user_data);
  guint i;

  for (i = 0; stream_ids[i] != 0; i++) {
    if (stream_ids[i] == self->priv->stream_id) {
      /* The socket has been closed. */
      g_io_stream_close (G_IO_STREAM (self), NULL, NULL);
      break;
    }
  }
}
