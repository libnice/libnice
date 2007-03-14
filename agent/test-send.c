
#include <string.h>

#include <sys/select.h>

#include "agent.h"
#include "stun.h"
#include "udp-fake.h"
#include "random-glib.h"

static gboolean cb_called = FALSE;

static void
cb_component_state_changed (
  NiceAgent *agent,
  guint stream_id,
  guint component_id,
  guint state)
{
  g_assert (agent != NULL);
  g_assert (stream_id == 1);
  g_assert (component_id == 1);
  g_assert (state == NICE_COMPONENT_STATE_CONNECTED);
  g_assert (cb_called == FALSE);
  cb_called = TRUE;
}


static gboolean
fd_is_readable (guint fd)
{
  fd_set fds;
  struct timeval timeout = {0,};

  FD_ZERO (&fds);
  FD_SET (fd, &fds);

  switch (select (fd + 1, &fds, NULL, NULL, &timeout))
    {
    case -1:
      g_assert_not_reached ();
    case 0:
      return FALSE;
    case 1:
      return TRUE;
    default:
      g_assert_not_reached ();
    }
}


static void
send_connectivity_check (
  NiceAgent *agent,
  NiceAddress *remote_addr)
{
  NiceUDPSocket *sock;
  NiceCandidate *local;
  NiceCandidate *remote;
  gchar *username;

  {
    GSList *candidates;

    candidates = nice_agent_get_local_candidates (agent, 1, 1);
    g_assert (g_slist_length (candidates) > 0);
    local = candidates->data;
    g_assert (local->id == 1);
    g_slist_free (candidates);
  }

  {
    GSList *candidates;

    candidates = nice_agent_get_remote_candidates (agent, 1, 1);
    g_assert (g_slist_length (candidates) > 0);
    remote = candidates->data;
    g_slist_free (candidates);
  }

  sock = &local->sock;

  username = g_strconcat (local->username, remote->username, NULL);

  {
    StunMessage *msg;
    gchar *packed;
    guint len;

    msg = stun_message_new (STUN_MESSAGE_BINDING_REQUEST, NULL, 1);
    msg->attributes[0] = stun_attribute_username_new (username);
    len = stun_message_pack (msg, &packed);
    nice_udp_fake_socket_push_recv (sock, remote_addr, len, packed);
    g_free (packed);
    stun_message_free (msg);
  }

  nice_agent_poll_read (agent, NULL, NULL, NULL);

  {
    StunMessage *msg;
    NiceAddress addr = {0,};
    gchar packed[1024];
    gchar *dump;
    guint len;

    len = nice_udp_fake_socket_pop_send (sock, &addr, 1024, packed);
    g_assert (nice_address_equal (&addr, remote_addr));
    msg = stun_message_unpack (len, packed);
    dump = stun_message_dump (msg);
    g_assert (0 == strcmp (dump,
        "BINDING-RESPONSE 00000000:00000000:00000000:00000000\n"
        "  MAPPED-ADDRESS 192.168.0.2:2345\n"
        "  USERNAME \"S9PObXR5username\"\n"));
    g_free (dump);
    stun_message_free (msg);
  }

  {
    StunMessage *msg;
    NiceAddress addr = {0,};
    gchar packed[1024];
    gchar *dump;
    guint len;

    len = nice_udp_fake_socket_pop_send (sock, &addr, 1024, packed);
    g_assert (nice_address_equal (&addr, remote_addr));
    msg = stun_message_unpack (len, packed);
    dump = stun_message_dump (msg);
    g_assert (0 == strcmp (dump,
        "BINDING-REQUEST 588c3ac1:e62757ae:5851a519:4d480994\n"
        "  USERNAME \"usernameS9PObXR5\"\n"));
    g_free (dump);
    stun_message_free (msg);
  }

  g_free (username);
}


int
main (void)
{
  NiceUDPSocketFactory factory;
  NiceAgent *agent;
  NiceAddress local_addr = {0,};
  NiceAddress remote_addr = {0,};

  g_type_init ();

  /* set up */

  nice_rng_set_new_func (nice_rng_glib_new_predictable);

  nice_udp_fake_socket_factory_init (&factory);
  agent = nice_agent_new (&factory);

  if (!nice_address_set_ipv4_from_string (&local_addr, "192.168.0.1"))
    g_assert_not_reached ();

  nice_agent_add_local_address (agent, &local_addr);
  nice_agent_add_stream (agent, 1);

  if (!nice_address_set_ipv4_from_string (&remote_addr, "192.168.0.2"))
    g_assert_not_reached ();

  remote_addr.port = 2345;
  nice_agent_add_remote_candidate (agent, 1, 1, NICE_CANDIDATE_TYPE_HOST,
      &remote_addr, "username", "password");

  g_signal_connect (agent, "component-state-changed",
      (GCallback) cb_component_state_changed, NULL);

  /* test */

  {
    NiceUDPSocket *sock;
    NiceAddress addr;
    gchar buf[1024];
    guint len;

      {
        GSList *candidates;
        NiceCandidate *candidate;

        candidates = nice_agent_get_local_candidates (agent, 1, 1);
        candidate = candidates->data;
        sock = &candidate->sock;
        g_slist_free (candidates);
      }

    /* If we send data before we've received a connectivity check, we won't
     * have an affinity for any of the remote candidates, so the packet will
     * get silently dropped.
     */

    nice_agent_send (agent, 1, 1, 5, "hello");
    g_assert (0 == fd_is_readable (nice_udp_fake_socket_get_peer_fd (sock)));

    send_connectivity_check (agent, &remote_addr);

    /* Now that we've received a valid connectivity check, we have a local
     * socket to send from, and a remote address to send to.
     */

    nice_agent_send (agent, 1, 1, 5, "hello");
    len = nice_udp_fake_socket_pop_send (sock, &addr, 1024, buf);
    g_assert (len == 5);
    g_assert (0 == strncmp (buf, "hello", len));

    /* Signal to say component is connected should have been emitted. */

    g_assert (cb_called == TRUE);
  }

  /* clean up */

  g_object_unref (agent);
  nice_udp_socket_factory_close (&factory);

  return 0;
}

