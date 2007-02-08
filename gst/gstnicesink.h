
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
};

typedef struct _GstNiceSinkClass GstNiceSinkClass;

struct _GstNiceSinkClass
{
  GstBaseSinkClass parent_class;
};

GType gst_nice_sink_get_type (void);

G_END_DECLS

#endif
