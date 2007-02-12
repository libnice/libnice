
#include <string.h>

#include "agent.h"
#include "stun.h"
#include "udp-fake.h"
#include "random-glib.h"

static void
send_connectivity_check (
  NiceAgent *agent,
  NiceUDPSocketFactory *factory,
  NiceAddress *remote_addr)
{
  NiceUDPSocket *sock;
  NiceCandidate *local;
  NiceCandidate *remote;
  gchar *username;

  g_assert (agent->local_candidates);
  g_assert (agent->local_candidates->data);
  local = agent->local_candidates->data;
  g_assert (local->id == 1);

  g_assert (agent->remote_candidates);
  g_assert (agent->remote_candidates->data);
  remote = agent->remote_candidates->data;

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
        "BINDING-REQUEST ac2f75c0:43fbc367:09d315f2:245746d8\n"
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

  /* test */

  {
    NiceUDPSocket *sock;
    NiceCandidate *candidate;
    NiceAddress addr;
    gchar buf[1024];
    guint len;

    candidate = agent->local_candidates->data;
    sock = &candidate->sock;

    /* If we send data before we've received a connectivity check, we won't
     * have an affinity for any of the remote candidates, so the packet will
     * get silently dropped.
     */

    nice_agent_send (agent, 1, 1, 5, "hello");
    g_assert (0 == nice_udp_fake_socket_pop_send (sock, &addr, 1024, buf));

    send_connectivity_check (agent, &factory, &remote_addr);

    /* Now that we've received a valid connectivity check, we have a local
     * socket to send from, and a remote address to send to.
     */

    nice_agent_send (agent, 1, 1, 5, "hello");
    len = nice_udp_fake_socket_pop_send (sock, &addr, 1024, buf);
    g_assert (len == 5);
    g_assert (0 == strncmp (buf, "hello", len));
  }

  /* clean up */

  nice_agent_free (agent);
  nice_udp_socket_factory_close (&factory);

  return 0;
}

