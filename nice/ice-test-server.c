
#include <string.h>

#include <errno.h>
#include <unistd.h>


#include "nice.h"
#include "readline.h"
#include "util.h"

static void
handle_recv (
  NiceAgent *agent,
  guint stream_id,
  guint component_id,
  guint len,
  gchar *buf,
  gpointer data)
{
  g_debug ("got media");
}

/* create an agent and give it one fixed local IP address */
static gboolean
make_agent (
  gchar *ip,
  NiceUDPSocketFactory *factory,
  NiceAgent **ret_agent,
  NiceUDPSocket **ret_sock)
{
  NiceAgent *agent;
  NiceAddress addr_local;
  NiceCandidate *candidate;

  agent = nice_agent_new (factory);

  nice_address_set_ipv4_from_string (&addr_local, ip);
  nice_agent_add_local_address (agent, &addr_local);

  nice_agent_add_stream (agent, handle_recv, NULL);

  g_assert (agent->local_candidates != NULL);
  candidate = agent->local_candidates->data;
  g_debug ("allocated socket %d port %d for candidate %d",
      candidate->sock.fileno, ntohs (candidate->sock.addr.sin_port),
      candidate->id);

  *ret_agent = agent;
  *ret_sock = &(candidate->sock);

  return TRUE;
}

static gboolean
handle_tcp_read (guint fileno, NiceAgent *agent)
{
  NiceCandidate *candidate;
  gchar *line;

  line = readline (fileno);

  if (line == NULL)
    /* EOF */
    return FALSE;

  candidate = nice_candidate_from_string (line);

  if (candidate == NULL)
    /* invalid candidate string */
    return FALSE;

  g_debug ("got remote candidate: %s", line);
  nice_agent_add_remote_candidate (agent, 1, 1, candidate->type,
      &candidate->addr, candidate->username, candidate->password);
  nice_candidate_free (candidate);
  g_free (line);

  return TRUE;
}

static void
handle_connection (guint fileno, const struct sockaddr_in *sin, gpointer data)
{
  NiceAgent *agent;
  NiceUDPSocketFactory factory;
  NiceUDPSocket *sock;
  GSList *sockets = NULL;
  gchar ip_str[INET_ADDRSTRLEN];
  fd_set fds;
  guint max_fd;
  gchar *candidate_str;

  inet_ntop (AF_INET, &(sin->sin_addr), ip_str, INET_ADDRSTRLEN);
  g_debug ("got connection from %s:%d", ip_str, ntohs (sin->sin_port));

  nice_udp_bsd_socket_factory_init (&factory);

  if (!make_agent ((gchar *) data, &factory, &agent, &sock))
    return;

  sockets = g_slist_append (sockets, sock);

  /* send first local candidate to remote end */
  candidate_str = nice_candidate_to_string (
      nice_agent_get_local_candidates (agent)->data);
  send (fileno, candidate_str, strlen (candidate_str), 0);
  send (fileno, "\n", 1, 0);
  g_free (candidate_str);

  /* event loop */

  FD_ZERO (&fds);
  FD_SET (fileno, &fds);
  FD_SET (sock->fileno, &fds);
  max_fd = MAX (fileno, sock->fileno) + 1;

  g_debug ("fileno = %d", fileno);

  for (;;)
    {
      fd_set tmp = fds;
      guint ret;
      guint i;

      ret = select (max_fd, &tmp, NULL, NULL, 0);

      for (i = 0; i < max_fd; i++)
        {
          if (!FD_ISSET (i, &tmp))
            continue;

          if (i == fileno)
            {
              /* TCP data */

              g_debug ("got TCP data");

              if (!handle_tcp_read (fileno, agent))
                goto END;
            }
          else if (i == sock->fileno)
            {
              /* UDP data */
              /* XXX: candidate number is hardcoded */
              nice_agent_recv (agent, 1);
            }
        }
    }

END:
  g_debug ("-- connection closed --");

  while (sockets != NULL)
    {
      GSList *tmp;
      NiceUDPSocket *sock = sockets->data;

      tmp = sockets;
      sockets = sockets->next;
      g_slist_free_1 (tmp);
      nice_udp_socket_close (sock);
      g_slice_free (NiceUDPSocket, sock);
    }

  g_slist_free (sockets);
  nice_udp_socket_factory_close (&factory);
  nice_agent_free (agent);
}

static gboolean
tcp_listen_loop (
  guint port,
  void (*handler) (guint sock, const struct sockaddr_in *sin, gpointer data),
  gpointer data)
{
  guint sock;
  struct sockaddr_in sin;

  sock = socket (AF_INET, SOCK_STREAM, 0);

  if (sock < 0)
    {
      g_print ("socket() failed: %s\n", g_strerror (errno));
      return FALSE;
    }

  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = INADDR_ANY;
  sin.sin_port = htons (port);

  if (bind (sock, (struct sockaddr *) &sin, sizeof (sin)) < 0)
    {
      g_print ("bind() failed: %s\n", g_strerror (errno));
      return 1;
    }

  if (listen (sock, 5) < 0)
    {
      g_print ("listen() failed: %s\n", g_strerror (errno));
      return FALSE;
    }

  for (;;)
    {
      gint conn;
      struct sockaddr_in from;
      guint from_len = sizeof (from);

      conn = accept (sock, (struct sockaddr *) &from, &from_len);

      if (conn < 0)
        {
          g_print ("accept() failed: %s\n", g_strerror (errno));
          return FALSE;
        }

      handler (conn, &from, data);
      close (conn);
    }

  return TRUE;
}

int
main (int argc, char **argv)
{
  if (argc != 2)
    {
      g_print ("usage: %s interface\n", argv[0]);
      return 1;
    }

  if (!tcp_listen_loop (7899, handle_connection, argv[1]))
    return 1;

  return 0;
}


