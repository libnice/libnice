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

#include <string.h>

#include "gstnicesrc.h"


#define BUFFER_SIZE (65536)

static GstFlowReturn
gst_nice_src_create (
  GstBaseSrc *basesrc,
  guint64 offset,
  guint length,
  GstBuffer **buffer);

static void
gst_nice_src_set_property (
  GObject *object,
  guint prop_id,
  const GValue *value,
  GParamSpec *pspec);

static void
gst_nice_src_get_property (
  GObject *object,
  guint prop_id,
  GValue *value,
  GParamSpec *pspec);

static const GstElementDetails gst_nice_src_details =
GST_ELEMENT_DETAILS (
    "ICE source",
    "Source",
    "Interactive UDP connectivity establishment",
    "Dafydd Harries <dafydd.harries@collabora.co.uk>");

static GstStaticPadTemplate gst_nice_src_src_template =
GST_STATIC_PAD_TEMPLATE (
    "src",
    GST_PAD_SRC,
    GST_PAD_ALWAYS,
    GST_STATIC_CAPS_ANY);

GST_BOILERPLATE (GstNiceSrc, gst_nice_src, GstBaseSrc, GST_TYPE_BASE_SRC);

enum
{
  PROP_AGENT = 1,
  PROP_STREAM,
  PROP_COMPONENT
};

static void
gst_nice_src_base_init (gpointer g_class)
{
  GstElementClass *element_class = GST_ELEMENT_CLASS (g_class);

  gst_element_class_add_pad_template (element_class,
      gst_static_pad_template_get (&gst_nice_src_src_template));
  gst_element_class_set_details (element_class, &gst_nice_src_details);
}

static void
gst_nice_src_class_init (GstNiceSrcClass *klass)
{
  GstBaseSrcClass *gstbasesrc_class;
  GObjectClass *gobject_class;

  gstbasesrc_class = (GstBaseSrcClass *) klass;
  gstbasesrc_class->create = GST_DEBUG_FUNCPTR (gst_nice_src_create);

  gobject_class = (GObjectClass *) klass;
  gobject_class->set_property = gst_nice_src_set_property;
  gobject_class->get_property = gst_nice_src_get_property;

  g_object_class_install_property (gobject_class, PROP_AGENT,
      g_param_spec_pointer (
         "agent",
         "Agent",
         "The NiceAgent this source is bound to",
         G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

  g_object_class_install_property (gobject_class, PROP_STREAM,
      g_param_spec_uint (
         "stream",
         "Stream ID",
         "The ID of the stream to read from",
         0,
         G_MAXUINT,
         0,
         G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

  g_object_class_install_property (gobject_class, PROP_COMPONENT,
      g_param_spec_uint (
         "component",
         "Component ID",
         "The ID of the component to read from",
         0,
         G_MAXUINT,
         0,
         G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
}

static void
gst_nice_src_init (GstNiceSrc *src, GstNiceSrcClass *g_class)
{
  gst_base_src_set_live (GST_BASE_SRC (src), TRUE);
}

static GstFlowReturn
gst_nice_src_create (
  GstBaseSrc *basesrc,
  guint64 offset,
  guint length,
  GstBuffer **buffer)
{
  GstFlowReturn res;
  GstBuffer *buf;
  GstNiceSrc *nicesrc;
  guint len;

  nicesrc = GST_NICE_SRC (basesrc);
  res = gst_pad_alloc_buffer (basesrc->srcpad, offset, BUFFER_SIZE, GST_PAD_CAPS
      (basesrc->srcpad), &buf);

  if (res != GST_FLOW_OK)
    return res;

  len = nice_agent_recv (nicesrc->agent, nicesrc->stream_id,
      nicesrc->component_id, BUFFER_SIZE, (gchar *) buf->data);
  g_assert (len);
  buf->size = len;
  *buffer = buf;
  return GST_FLOW_OK;
}

static void
gst_nice_src_set_property (
  GObject *object,
  guint prop_id,
  const GValue *value,
  GParamSpec *pspec)
{
  GstNiceSrc *src = GST_NICE_SRC (object);

  switch (prop_id)
    {
    case PROP_AGENT:
      src->agent = g_value_get_pointer (value);
      break;

    case PROP_STREAM:
      src->stream_id = g_value_get_uint (value);
      break;

    case PROP_COMPONENT:
      src->component_id = g_value_get_uint (value);
      break;
    }
}

static void
gst_nice_src_get_property (
  GObject *object,
  guint prop_id,
  GValue *value,
  GParamSpec *pspec)
{
  GstNiceSrc *src = GST_NICE_SRC (object);

  switch (prop_id)
    {
    case PROP_AGENT:
      g_value_set_pointer (value, src->agent);
      break;

    case PROP_STREAM:
      g_value_set_uint (value, src->stream_id);
      break;

    case PROP_COMPONENT:
      g_value_set_uint (value, src->component_id);
      break;
    }
}

