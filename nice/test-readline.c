
#include <string.h>

#include <unistd.h>

#include <glib.h>

#include "readline.h"

/* this overrides libc read() -- is this reliable? */
int
read (
  G_GNUC_UNUSED
  int fd,
  void *buf,
  size_t count)
{
  static int offset = 0;
  const gchar *line = "test\n";

  g_assert (count == 1);

  if (offset < 5)
    {
      * (gchar *) buf = line[offset++];
      return 1;
    }
  else
    {
      return 0;
    }
}

int
main (void)
{
  gchar *line;

  line = readline (0);
  g_assert (0 == strcmp (line, "test"));
  g_free (line);
  line = readline (0);
  g_assert (line == NULL);
  return 0;
}

