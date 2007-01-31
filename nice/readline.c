
#include <unistd.h>

#include <glib.h>

gchar *
readline (guint fileno)
{
  gchar buf[1024];
  guint i;

  for (i = 0; i < sizeof (buf); i++)
    {
      guint ret;

      ret = read (fileno, buf + i, 1);

      if (ret == -1)
        break;

      if (ret == 0 && i == 0)
        {
          /* EOF on first read */
          break;
        }
      else if (ret == 0 || buf[i] == '\n')
        {
          buf[i] = '\0';
          return g_strdup (buf);
        }
    }

  return NULL;
}

