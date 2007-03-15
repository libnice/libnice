
#include "stream.h"

Stream *
stream_new (void)
{
  Stream *stream;

  stream = g_slice_new0 (Stream);
  stream->component = component_new (COMPONENT_TYPE_RTP);
  return stream;
}


void
stream_free (Stream *stream)
{
  component_free (stream->component);
  g_slice_free (Stream, stream);
}


