
#include "config.h"
#include "gstnicesrc.h"
#include "gstnicesink.h"

static gboolean
plugin_init (GstPlugin * plugin)
{
  if (!gst_element_register (plugin, "nicesrc",
        GST_RANK_NONE, GST_TYPE_NICE_SRC))
    return FALSE;

  if (!gst_element_register (plugin, "nicesink",
        GST_RANK_NONE, GST_TYPE_NICE_SINK))
    return FALSE;

  return TRUE;
}

GST_PLUGIN_DEFINE (
    GST_VERSION_MAJOR,
    GST_VERSION_MINOR,
    "nice",
    "Interactive UDP connectivity establishment",
    plugin_init, VERSION, "LGPL", PACKAGE_NAME,
    "http://telepathy.freedesktop.org/wiki/");

