
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
 *   Martin Nordholts, Axis Communications AB, 2025.
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

#include "gstnicesink.h"


GST_DEBUG_CATEGORY_STATIC (nicesink_debug);
#define GST_CAT_DEFAULT nicesink_debug

static GstFlowReturn
gst_nice_sink_render (
  GstBaseSink *basesink,
  GstBuffer *buffer);
static GstFlowReturn
gst_nice_sink_render_list (
  GstBaseSink *basesink,
  GstBufferList *buffer_list);

static gboolean
gst_nice_sink_unlock (GstBaseSink *basesink);

static gboolean
gst_nice_sink_unlock_stop (GstBaseSink *basesink);

static void
_reliable_transport_writable (
    NiceAgent *agent,
    guint stream_id,
    guint component_id,
    GstNiceSink *sink);

static void
gst_nice_sink_set_property (
  GObject *object,
  guint prop_id,
  const GValue *value,
  GParamSpec *pspec);

static void
gst_nice_sink_get_property (
  GObject *object,
  guint prop_id,
  GValue *value,
  GParamSpec *pspec);

static void
gst_nice_sink_dispose (GObject *object);
static void
gst_nice_sink_finalize (GObject *object);

static GstStateChangeReturn
gst_nice_sink_change_state (
    GstElement * element,
    GstStateChange transition);

static GstStaticPadTemplate gst_nice_sink_sink_template =
GST_STATIC_PAD_TEMPLATE (
    "sink",
    GST_PAD_SINK,
    GST_PAD_ALWAYS,
    GST_STATIC_CAPS_ANY);

G_DEFINE_TYPE (GstNiceSink, gst_nice_sink, GST_TYPE_BASE_SINK);

enum
{
  PROP_AGENT = 1,
  PROP_STREAM,
  PROP_COMPONENT
};

static void
gst_nice_sink_class_init (GstNiceSinkClass *klass)
{
  GstBaseSinkClass *gstbasesink_class;
  GstElementClass *gstelement_class;
  GObjectClass *gobject_class;

  GST_DEBUG_CATEGORY_INIT (nicesink_debug, "nicesink",
      0, "libnice sink");

  gstbasesink_class = (GstBaseSinkClass *) klass;
  gstbasesink_class->render = GST_DEBUG_FUNCPTR (gst_nice_sink_render);
  gstbasesink_class->render_list = GST_DEBUG_FUNCPTR (gst_nice_sink_render_list);
  gstbasesink_class->unlock = GST_DEBUG_FUNCPTR (gst_nice_sink_unlock);
  gstbasesink_class->unlock_stop = GST_DEBUG_FUNCPTR (gst_nice_sink_unlock_stop);

  gobject_class = (GObjectClass *) klass;
  gobject_class->set_property = gst_nice_sink_set_property;
  gobject_class->get_property = gst_nice_sink_get_property;
  gobject_class->dispose = gst_nice_sink_dispose;
  gobject_class->finalize = gst_nice_sink_finalize;

  gstelement_class = (GstElementClass *) klass;
  gstelement_class->change_state = gst_nice_sink_change_state;

  gst_element_class_add_pad_template (gstelement_class,
      gst_static_pad_template_get (&gst_nice_sink_sink_template));
  gst_element_class_set_metadata (gstelement_class,
    "ICE sink",
    "Sink",
    "Interactive UDP connectivity establishment",
    "Dafydd Harries <dafydd.harries@collabora.co.uk>");


  g_object_class_install_property (gobject_class, PROP_AGENT,
      g_param_spec_object (
         "agent",
         "Agent",
         "The NiceAgent this source is bound to",
         NICE_TYPE_AGENT,
         G_PARAM_READWRITE));

  g_object_class_install_property (gobject_class, PROP_STREAM,
      g_param_spec_uint (
         "stream",
         "Stream ID",
         "The ID of the stream to read from",
         0,
         G_MAXUINT,
         0,
         G_PARAM_READWRITE));

  g_object_class_install_property (gobject_class, PROP_COMPONENT,
      g_param_spec_uint (
         "component",
         "Component ID",
         "The ID of the component to read from",
         0,
         G_MAXUINT,
         0,
         G_PARAM_READWRITE));
}

static void
gst_nice_sink_init (GstNiceSink *sink)
{
  guint max_mem;

  g_cond_init (&sink->writable_cond);

  /* pre-allocate OutputVector, MapInfo and OutputMessage arrays
   * for use in the render and render_list functions */
  max_mem = gst_buffer_get_max_memory ();

  sink->n_vecs = max_mem;
  sink->vecs = g_new (GOutputVector, sink->n_vecs);

  sink->n_maps = max_mem;
  sink->maps = g_new (GstMapInfo, sink->n_maps);

  sink->n_messages = 1;
  sink->messages = g_new (NiceOutputMessage, sink->n_messages);

#if GST_CHECK_VERSION (1,12,0)
  gst_base_sink_set_drop_out_of_segment (GST_BASE_SINK (sink), FALSE);
#endif
}

static void
_reliable_transport_writable (NiceAgent *agent, guint stream_id,
    guint component_id, GstNiceSink *sink)
{
  GST_OBJECT_LOCK (sink);
  if (stream_id == sink->stream_id && component_id == sink->component_id) {
    g_cond_broadcast (&sink->writable_cond);
  }
  GST_OBJECT_UNLOCK (sink);
}

static gsize
fill_vectors (GOutputVector * vecs, GstMapInfo * maps, guint n, GstBuffer * buf)
{
  GstMemory *mem;
  gsize size = 0;
  guint i;

  g_assert (gst_buffer_n_memory (buf) == n);

  for (i = 0; i < n; ++i) {
    mem = gst_buffer_peek_memory (buf, i);
    if (gst_memory_map (mem, &maps[i], GST_MAP_READ)) {
      vecs[i].buffer = maps[i].data;
      vecs[i].size = maps[i].size;
    } else {
      GST_WARNING ("Failed to map memory %p for reading", mem);
      vecs[i].buffer = "";
      vecs[i].size = 0;
    }
    size += vecs[i].size;
  }

  return size;
}

/* Buffer list code written by
 *   Tim-Philipp Müller <tim@centricular.com>
 * taken from
 *   gst-plugins-good/gst/udp/gstmultiudpsink.c
 */
static GstFlowReturn
gst_nice_sink_render_buffers (GstNiceSink * sink, GstBuffer ** buffers,
    guint num_buffers, guint8 * mem_nums, guint total_mem_num)
{
  NiceOutputMessage *msgs;
  GOutputVector *vecs;
  GstMapInfo *map_infos;
  guint i, mem;
  guint written = 0;
  gint ret;
  gboolean keep_sending = TRUE;
  GstFlowReturn flow_ret = GST_FLOW_OK;

  GST_LOG_OBJECT (sink, "%u buffers, %u memories -> to be sent",
      num_buffers, total_mem_num);

  if (sink->n_vecs < total_mem_num) {
    sink->n_vecs = GST_ROUND_UP_16 (total_mem_num);
    g_free (sink->vecs);
    sink->vecs = g_new (GOutputVector, sink->n_vecs);
  }
  vecs = sink->vecs;

  if (sink->n_maps < total_mem_num) {
    sink->n_maps = GST_ROUND_UP_16 (total_mem_num);
    g_free (sink->maps);
    sink->maps = g_new (GstMapInfo, sink->n_maps);
  }
  map_infos = sink->maps;

  if (sink->n_messages < num_buffers) {
    sink->n_messages = GST_ROUND_UP_16 (num_buffers);
    g_free (sink->messages);
    sink->messages = g_new (NiceOutputMessage, sink->n_messages);
  }
  msgs = sink->messages;

  for (i = 0, mem = 0; i < num_buffers; ++i) {
    fill_vectors (&vecs[mem], &map_infos[mem], mem_nums[i], buffers[i]);
    msgs[i].buffers = &vecs[mem];
    msgs[i].n_buffers = mem_nums[i];
    mem += mem_nums[i];
  }

  GST_OBJECT_LOCK (sink);
  do {
    GError *err = NULL;

    ret = nice_agent_send_messages_nonblocking(sink->agent, sink->stream_id,
        sink->component_id, msgs + written, num_buffers - written, NULL, &err);

    if (ret > 0)
      written += ret;

    if (written < num_buffers) {
      gboolean wait_for_writable =
          sink->reliable || g_error_matches (err, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK);
      /* Note: We must check `sink->flushing` before we `g_cond_wait()` in case
       * it became `TRUE` before we got the lock.
       */
      if (wait_for_writable && !sink->flushing) {
        GST_LOG_OBJECT (sink, "Waiting for writable after %d of %d messages", written, num_buffers);
        g_cond_wait (&sink->writable_cond, GST_OBJECT_GET_LOCK (sink));
      } else if (!sink->reliable && err) {
        /* We are in non-reliable mode and something serious has happened. Let's
         * stop sending to not risk ending up in an infinite loop.
         */
        GST_WARNING_OBJECT (
            sink,
            "Failed sending %d of %d messages: %s",
            num_buffers - written,
            num_buffers,
            err->message);
        keep_sending = FALSE;
      }
    }

    if (sink->flushing) {
      flow_ret = GST_FLOW_FLUSHING;
      keep_sending = FALSE;
    }

    /* Don't `continue` or `break` the loop because that leaks any `err`s. */
    g_clear_error (&err);
  } while (keep_sending && written < num_buffers);
  GST_OBJECT_UNLOCK (sink);

  for (i = 0; i < mem; ++i)
    gst_memory_unmap (map_infos[i].memory, &map_infos[i]);

  return flow_ret;
}

static GstFlowReturn
gst_nice_sink_render (GstBaseSink *basesink, GstBuffer *buffer)
{
  GstNiceSink *nicesink = GST_NICE_SINK (basesink);
  GstFlowReturn flow_ret = GST_FLOW_OK;
  guint8 n_mem;

  n_mem = gst_buffer_n_memory (buffer);

  if (n_mem > 0) {
    flow_ret = gst_nice_sink_render_buffers (nicesink, &buffer, 1, &n_mem,
        n_mem);
  }

  return flow_ret;
}

static GstFlowReturn
gst_nice_sink_render_list (GstBaseSink *basesink, GstBufferList *buffer_list)
{
  GstNiceSink *nicesink = GST_NICE_SINK (basesink);
  GstBuffer **buffers;
  GstFlowReturn flow_ret = GST_FLOW_OK;
  guint8 *mem_nums;
  guint total_mems;
  guint i, num_buffers;

  num_buffers = gst_buffer_list_length (buffer_list);
  if (num_buffers == 0)
    goto no_data;

  buffers = g_newa (GstBuffer *, num_buffers);
  mem_nums = g_newa (guint8, num_buffers);
  for (i = 0, total_mems = 0; i < num_buffers; ++i) {
    buffers[i] = gst_buffer_list_get (buffer_list, i);
    mem_nums[i] = gst_buffer_n_memory (buffers[i]);
    total_mems += mem_nums[i];
  }

  flow_ret = gst_nice_sink_render_buffers (nicesink, buffers, num_buffers,
      mem_nums, total_mems);

  return flow_ret;

no_data:
  {
    GST_LOG_OBJECT (nicesink, "empty buffer");
    return GST_FLOW_OK;
  }

  return flow_ret;
}

static gboolean gst_nice_sink_unlock (GstBaseSink *basesink)
{
  GstNiceSink *nicesink = GST_NICE_SINK (basesink);

  GST_OBJECT_LOCK (nicesink);
  nicesink->flushing = TRUE;
  g_cond_broadcast (&nicesink->writable_cond);
  GST_OBJECT_UNLOCK (nicesink);

  return TRUE;
}

static gboolean gst_nice_sink_unlock_stop (GstBaseSink *basesink)
{
  GstNiceSink *nicesink = GST_NICE_SINK (basesink);

  GST_OBJECT_LOCK (nicesink);
  nicesink->flushing = FALSE;
  GST_OBJECT_UNLOCK (nicesink);

  return TRUE;
}

static void
gst_nice_sink_dispose (GObject *object)
{
  GstNiceSink *sink = GST_NICE_SINK (object);

  if (sink->agent && sink->writable_id)
    g_signal_handler_disconnect (sink->agent, sink->writable_id);
  sink->writable_id = 0;
  g_clear_object (&sink->agent);

  g_cond_clear (&sink->writable_cond);

  G_OBJECT_CLASS (gst_nice_sink_parent_class)->dispose (object);
}

static void
gst_nice_sink_finalize (GObject *object)
{
  GstNiceSink *sink = GST_NICE_SINK (object);

  g_free (sink->vecs);
  sink->vecs = NULL;
  sink->n_vecs = 0;
  g_free (sink->maps);
  sink->maps = NULL;
  sink->n_maps = 0;
  g_free (sink->messages);
  sink->messages = NULL;
  sink->n_messages = 0;

  G_OBJECT_CLASS (gst_nice_sink_parent_class)->finalize (object);
}

static void
gst_nice_sink_set_property (
  GObject *object,
  guint prop_id,
  const GValue *value,
  GParamSpec *pspec)
{
  GstNiceSink *sink = GST_NICE_SINK (object);

  switch (prop_id)
    {
    case PROP_AGENT:
      if (sink->agent) {
        GST_ERROR_OBJECT (object,
            "Changing the agent on a nice sink not allowed");
      } else {
        sink->agent = g_value_dup_object (value);
        g_object_get (sink->agent, "reliable", &sink->reliable, NULL);
        sink->writable_id = g_signal_connect (
            sink->agent,
            "reliable-transport-writable",
            (GCallback) _reliable_transport_writable,
            sink);
      }
      break;

    case PROP_STREAM:
      GST_OBJECT_LOCK (sink);
      sink->stream_id = g_value_get_uint (value);
      GST_OBJECT_UNLOCK (sink);
      break;

    case PROP_COMPONENT:
      {
        guint new_component_id = g_value_get_uint (value);
        GST_OBJECT_LOCK (sink);
        if (sink->component_id != new_component_id) {
          sink->component_id = new_component_id;
          g_cond_broadcast (&sink->writable_cond);
        }
        GST_OBJECT_UNLOCK (sink);
      }
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
    }
}

static void
gst_nice_sink_get_property (
  GObject *object,
  guint prop_id,
  GValue *value,
  GParamSpec *pspec)
{
  GstNiceSink *sink = GST_NICE_SINK (object);

  switch (prop_id)
    {
    case PROP_AGENT:
      g_value_set_object (value, sink->agent);
      break;

    case PROP_STREAM:
      GST_OBJECT_LOCK (sink);
      g_value_set_uint (value, sink->stream_id);
      GST_OBJECT_UNLOCK (sink);
      break;

    case PROP_COMPONENT:
      GST_OBJECT_LOCK (sink);
      g_value_set_uint (value, sink->component_id);
      GST_OBJECT_UNLOCK (sink);
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
    }
}

static GstStateChangeReturn
gst_nice_sink_change_state (GstElement * element, GstStateChange transition)
{
  GstNiceSink *sink;
  GstStateChangeReturn ret;

  sink = GST_NICE_SINK (element);

  switch (transition) {
    case GST_STATE_CHANGE_NULL_TO_READY:
      GST_OBJECT_LOCK (element);
      if (sink->agent == NULL) {
        GST_ERROR_OBJECT (element,
            "Trying to start Nice sink without an agent set");
        goto failure;
      }
      else if (sink->stream_id == 0) {
        GST_ERROR_OBJECT (element,
            "Trying to start Nice sink without a stream set");
        goto failure;
      }
      else if (sink->component_id == 0) {
        GST_ERROR_OBJECT (element,
            "Trying to start Nice sink without a component set");
        goto failure;
      }
      GST_OBJECT_UNLOCK (element);
      break;
    case GST_STATE_CHANGE_READY_TO_PAUSED:
    case GST_STATE_CHANGE_PAUSED_TO_PLAYING:
    case GST_STATE_CHANGE_PLAYING_TO_PAUSED:
    case GST_STATE_CHANGE_PAUSED_TO_READY:
    case GST_STATE_CHANGE_READY_TO_NULL:
    default:
      break;
  }

  ret = GST_ELEMENT_CLASS (gst_nice_sink_parent_class)->change_state (element,
      transition);

  return ret;

failure:
  GST_OBJECT_UNLOCK (element);
  return GST_STATE_CHANGE_FAILURE;
}

gboolean
gst_element_register_nicesink (GstPlugin * plugin)
{
  return gst_element_register (plugin, "nicesink", GST_RANK_NONE,
      GST_TYPE_NICE_SINK);
}
