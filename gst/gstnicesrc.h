
#ifndef _GSTNICE_H
#define _GSTNICE_H

#include <gst/gst.h>
#include <gst/base/gstbasesrc.h>

#include <nice/nice.h>

G_BEGIN_DECLS

#define GST_TYPE_NICE_SRC \
  (gst_nice_src_get_type())
#define GST_NICE_SRC(obj) \
  (G_TYPE_CHECK_INSTANCE_CAST((obj),GST_TYPE_NICE_SRC,GstNiceSrc))
#define GST_NICE_SRC_CLASS(klass) \
  (G_TYPE_CHECK_CLASS_CAST((klass),GST_TYPE_NICE_SRC,GstNiceSrcClass))
#define GST_IS_NICE_SRC(obj) \
  (G_TYPE_CHECK_INSTANCE_TYPE((obj),GST_TYPE_NICE_SRC))
#define GST_IS_NICE_SRC_CLASS(klass) \
  (G_TYPE_CHECK_CLASS_TYPE((klass),GST_TYPE_NICE_SRC))

typedef struct _GstNiceSrc GstNiceSrc;

struct _GstNiceSrc
{
  GstBaseSrc parent;
  GstPad *srcpad;
  NiceAgent *agent;
  guint stream_id;
  guint component_id;
};

typedef struct _GstNiceSrcClass GstNiceSrcClass;

struct _GstNiceSrcClass
{
  GstBaseSrcClass parent_class;
};

GType gst_nice_src_get_type (void);

G_END_DECLS

#endif // _GSTNICE_H

