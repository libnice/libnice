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

#ifndef _GST_NICE_SINK_H
#define _GST_NICE_SINK_H

#include <gst/gst.h>
#include <gst/base/gstbasesink.h>

#include <nice/nice.h>

G_BEGIN_DECLS

#define GST_TYPE_NICE_SINK \
  (gst_nice_sink_get_type())
#define GST_NICE_SINK(obj) \
  (G_TYPE_CHECK_INSTANCE_CAST((obj),GST_TYPE_NICE_SINK,GstNiceSink))
#define GST_NICE_SINK_CLASS(klass) \
  (G_TYPE_CHECK_CLASS_CAST((klass),GST_TYPE_NICE_SINK,GstNiceSinkClass))
#define GST_IS_NICE_SINK(obj) \
  (G_TYPE_CHECK_INSTANCE_TYPE((obj),GST_TYPE_NICE_SINK))
#define GST_IS_NICE_SINK_CLASS(klass) \
  (G_TYPE_CHECK_CLASS_TYPE((klass),GST_TYPE_NICE_SINK))

typedef struct _GstNiceSink GstNiceSink;

struct _GstNiceSink
{
  GstBaseSink parent;
  GstPad *sinkpad;
  NiceAgent *agent;
  guint stream_id;
  guint component_id;
  gboolean reliable;
  GCond writable_cond;
  gulong writable_id;
  gboolean flushing;

#if GST_CHECK_VERSION (1,0,0)
  /* pre-allocated scrap space for render function */
  GOutputVector *vecs;
  guint n_vecs;
  GstMapInfo *maps;
  guint n_maps;
  NiceOutputMessage *messages;
  guint n_messages;
#endif
};

typedef struct _GstNiceSinkClass GstNiceSinkClass;

struct _GstNiceSinkClass
{
  GstBaseSinkClass parent_class;
};

GType gst_nice_sink_get_type (void);

G_END_DECLS

#endif
