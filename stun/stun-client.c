
#include <netdb.h>
#include <string.h>
#include <sys/socket.h>

#include <glib.h>

#include <stun.h>

static gchar *server = "stun.fwdnet.net";
const guint port = 3478;

static gboolean
resolve (const gchar *name, struct hostent *ret)
{
  int res;
  int h_errno;
  struct hostent *he;
  gchar buf[1024];

  res = gethostbyname_r (server, ret, buf, sizeof (buf) / sizeof (gchar), &he,
      &h_errno);
  return (res == 0);
}

int
main (int argc, char **argv)
{
  struct hostent he;
  struct sockaddr_in sin;
  guint sock;
  gchar *packed;
  guint length;
  gchar buffer[256];
  StunMessage *msg;
  StunAttribute **attr;

  if (argc > 1)
    server = argv[1];

  if (!resolve(server, &he))
    {
      g_debug ("failed to resolve %s\n", server);
      return 1;
    }

  g_assert (he.h_addr_list != NULL);

  sin.sin_family = AF_INET;
  sin.sin_port = htons (port);
  memcpy (&sin.sin_addr, he.h_addr_list[0], sizeof (struct in_addr));

  sock = socket (AF_INET, SOCK_DGRAM, 0);
  connect (sock, (struct sockaddr *) &sin, sizeof (struct sockaddr));

  msg = stun_message_binding_request_new ();
  length = stun_message_pack (msg, &packed);

#ifdef DEBUG
  {
    gchar *dump = stun_message_dump (msg);
    g_debug (dump);
    g_free (dump);
  }
#endif

  send (sock, packed, length, 0);
  g_free (packed);
  stun_message_free (msg);

  length = recv (sock, buffer, 256, 0);
  msg = stun_message_unpack (length, buffer);

#ifdef DEBUG
  {
    gchar *dump = stun_message_dump (msg);
    g_debug (dump);
    g_free (dump);
  }
#endif

  for (attr = msg->attributes; *attr; attr++)
    {
      if ((*attr)->type == STUN_ATTRIBUTE_MAPPED_ADDRESS)
        {
          guint32 ip = (*attr)->address.ip;

          g_print ("%d.%d.%d.%d\n",
              (ip & 0xff000000) >> 24,
              (ip & 0x00ff0000) >> 16,
              (ip & 0x0000ff00) >>  8,
              (ip & 0x000000ff));
          break;
        }
    }

  stun_message_free (msg);
  return 0;
}

