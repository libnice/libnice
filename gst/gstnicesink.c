
#include "config.h"
#include "gstnicesink.h"

static GstFlowReturn
gst_nice_sink_render (
  GstBaseSink *basesink,
  GstBuffer *buffer);

static void
gst_nice_sink_set_property (
    GObject *object, guint prop_id, const GValue *value, GParamSpec *pspec);

static void
gst_nice_sink_get_property (
    GObject *object, guint prop_id, GValue *value, GParamSpec *pspec);

static const GstElementDetails gst_nice_sink_details =
GST_ELEMENT_DETAILS (
    "ICE sink",
    "Sink",
    "Interactive UDP connectivity establishment",
    "Dafydd Harries <dafydd.harries@collabora.co.uk>");

static GstStaticPadTemplate gst_nice_sink_sink_template =
GST_STATIC_PAD_TEMPLATE (
    "sink",
    GST_PAD_SINK,
    GST_PAD_ALWAYS,
    GST_STATIC_CAPS_ANY);

GST_BOILERPLATE (GstNiceSink, gst_nice_sink, GstBaseSink, GST_TYPE_BASE_SINK);

enum
{
  PROP_AGENT = 1,
  PROP_STREAM,
  PROP_COMPONENT
};

static void
gst_nice_sink_base_init (gpointer g_class)
{
  GstElementClass *element_class = GST_ELEMENT_CLASS (g_class);

  gst_element_class_add_pad_template (element_class,
      gst_static_pad_template_get (&gst_nice_sink_sink_template));
  gst_element_class_set_details (element_class, &gst_nice_sink_details);
}

static void
gst_nice_sink_class_init (GstNiceSinkClass *klass)
{
  GstBaseSinkClass *gstbasesink_class;
  GObjectClass *gobject_class;

  gstbasesink_class = (GstBaseSinkClass *) klass;
  gstbasesink_class->render = GST_DEBUG_FUNCPTR (gst_nice_sink_render);

  gobject_class = (GObjectClass *) klass;
  gobject_class->set_property = gst_nice_sink_set_property;
  gobject_class->get_property = gst_nice_sink_get_property;

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
gst_nice_sink_init (GstNiceSink *sink, GstNiceSinkClass *g_class)
{
}

static GstFlowReturn
gst_nice_sink_render (
    GstBaseSink *basesink, GstBuffer *buffer)
{
  GstNiceSink *nicesink;

  nicesink = GST_NICE_SINK (basesink);
  nice_agent_send (nicesink->agent, nicesink->stream_id,
      nicesink->component_id, GST_BUFFER_SIZE (buffer),
      (gchar *) GST_BUFFER_DATA (buffer));

  return GST_FLOW_OK;
}

static void
gst_nice_sink_set_property (
    GObject *object, guint prop_id, const GValue *value, GParamSpec *pspec)
{
  GstNiceSink *sink = GST_NICE_SINK (object);

  switch (prop_id)
    {
    case PROP_AGENT:
      sink->agent = g_value_get_pointer (value);
      break;

    case PROP_STREAM:
      sink->stream_id = g_value_get_uint (value);
      break;

    case PROP_COMPONENT:
      sink->component_id = g_value_get_uint (value);
      break;
    }
}

static void
gst_nice_sink_get_property (
    GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
  GstNiceSink *sink = GST_NICE_SINK (object);

  switch (prop_id)
    {
    case PROP_AGENT:
      g_value_set_pointer (value, sink->agent);
      break;

    case PROP_STREAM:
      g_value_set_uint (value, sink->stream_id);
      break;

    case PROP_COMPONENT:
      g_value_set_uint (value, sink->component_id);
      break;
    }
}

