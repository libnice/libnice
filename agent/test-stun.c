
#include <string.h>

#include "stun.h"
#include "udp-fake.h"
#include "agent.h"

static void
handle_recv (
  NiceAgent *agent,
  guint stream_id,
  guint component_id,
  guint len,
  gchar *buf,
  gpointer data)
{
  g_assert_not_reached ();
}

static void
test_stun_no_password (
  NiceAgent *agent,
  NiceAddress from)
{
  NiceCandidate *candidate;
  NiceUDPSocket *sock;
  NiceAddress to = {0,};
  guint len;
  gchar buf[1024];
  guint packed_len;
  gchar *packed;

  memset (buf, '\0', 1024);

  candidate = agent->local_candidates->data;
  sock = &candidate->sock;

    {
      StunMessage *breq;

      /* send binding request without username */
      breq = stun_message_new (STUN_MESSAGE_BINDING_REQUEST,
          "0123456789abcdef", 0);
      packed_len = stun_message_pack (breq, &packed);
      nice_udp_fake_socket_push_recv (sock, &from, packed_len, packed);
      g_free (packed);
      stun_message_free (breq);
    }

  /* tell the agent there's a packet waiting */
  nice_agent_recv (agent, candidate->id);

  /* error response should have been sent */
  len = nice_udp_fake_socket_pop_send (sock, &to, sizeof (buf) / sizeof (gchar),
      buf);
  g_assert (len != 0);

    {
      StunMessage *bres;

      /* construct expected response */
      bres = stun_message_new (STUN_MESSAGE_BINDING_ERROR_RESPONSE,
          "0123456789abcdef", 0);
      packed_len = stun_message_pack (bres, &packed);

      stun_message_free (bres);
    }

  g_assert (len == packed_len);
  g_assert (0 == memcmp (buf, packed, len));
  g_free (packed);
}

static void
test_stun_invalid_password (
  NiceAgent *agent,
  NiceAddress from)
{
  NiceCandidate *candidate;
  NiceUDPSocket *sock;
  NiceAddress to = {0,};
  guint len;
  gchar buf[1024];
  guint packed_len;
  gchar *packed;

  memset (buf, '\0', 1024);

  candidate = agent->local_candidates->data;
  sock = &candidate->sock;

    {
      StunMessage *breq;

      /* send binding request with incorrect username */
      breq = stun_message_new (STUN_MESSAGE_BINDING_REQUEST,
          "0123456789abcdef", 1);
      breq->attributes[0] = stun_attribute_username_new ("lala");
      packed_len = stun_message_pack (breq, &packed);
      g_assert (packed_len != 0);
      nice_udp_fake_socket_push_recv (sock, &from, packed_len, packed);
      g_free (packed);
      stun_message_free (breq);
    }

  /* tell the agent there's a packet waiting */
  nice_agent_recv (agent, candidate->id);

  /* error should have been sent */
  len = nice_udp_fake_socket_pop_send (sock, &to, sizeof (buf) / sizeof (gchar),
      buf);
  g_assert (len != 0);

    {
      StunMessage *bres;

      /* construct expected response */
      bres = stun_message_new (STUN_MESSAGE_BINDING_ERROR_RESPONSE,
          "0123456789abcdef", 0);
      packed_len = stun_message_pack (bres, &packed);
      stun_message_free (bres);
    }

  g_assert (len == packed_len);
  g_assert (0 == memcmp (buf, packed, len));
  g_free (packed);
}

static void
test_stun_valid_password (
  NiceAgent *agent,
  NiceAddress from)
{
  NiceCandidate *candidate;
  NiceUDPSocket *sock;
  NiceAddress to = {0,};
  guint len;
  guint packed_len;
  gchar buf[1024];
  gchar *packed;
  gchar *username;

  memset (buf, '\0', 1024);

  candidate = agent->local_candidates->data;
  sock = &candidate->sock;

  username = g_strconcat (
      ((NiceCandidate *) agent->local_candidates->data)->username,
      "username",
      NULL);

    {
      StunMessage *breq;
      guint packed_len;
      gchar *packed;

      /* send binding request with correct username */
      breq = stun_message_new (STUN_MESSAGE_BINDING_REQUEST,
          "0123456789abcdef", 1);
      breq->attributes[0] = stun_attribute_username_new (username);
      packed_len = stun_message_pack (breq, &packed);
      g_assert (packed_len != 0);
      nice_udp_fake_socket_push_recv (sock, &from, packed_len, packed);
      g_free (packed);
      stun_message_free (breq);
    }

    {
      StunMessage *bres;

      /* construct expected response packet */
      bres = stun_message_new (STUN_MESSAGE_BINDING_RESPONSE,
          "0123456789abcdef", 2);
      bres->attributes[0] = stun_attribute_mapped_address_new (
          from.addr_ipv4, 5678);
      bres->attributes[1] = stun_attribute_username_new (username);
      packed_len = stun_message_pack (bres, &packed);
      stun_message_free (bres);
    }

  g_free (username);

  /* tell the agent there's a packet waiting */
  nice_agent_recv (agent, candidate->id);

  /* compare sent packet to expected */
  len = nice_udp_fake_socket_pop_send (sock, &to,
      sizeof (buf) / sizeof (gchar), buf);
  g_assert (len == packed_len);
  g_assert (0 == memcmp (buf, packed, len));
  g_assert (nice_address_equal (&to, &from));
  g_free (packed);
}

int
main (void)
{
  NiceAgent *agent;
  NiceAddress local_addr, remote_addr;
  NiceCandidate *candidate;
  NiceUDPSocketFactory factory;
  NiceUDPSocket *sock;

  nice_udp_fake_socket_factory_init (&factory);

  g_assert (nice_address_set_ipv4_from_string (&local_addr, "192.168.0.1"));
  g_assert (nice_address_set_ipv4_from_string (&remote_addr, "192.168.0.5"));
  remote_addr.port = 5678;

  /* set up agent */
  agent = nice_agent_new (&factory);
  nice_agent_add_local_address (agent, &local_addr);
  nice_agent_add_stream (agent, handle_recv, NULL);
  nice_agent_add_remote_candidate (agent, 1, 1, NICE_CANDIDATE_TYPE_HOST,
      &remote_addr, "username", "password");
  g_assert (agent->local_candidates != NULL);
  candidate = agent->local_candidates->data;
  sock = &(candidate->sock);

  /* run tests */
  test_stun_no_password (agent, remote_addr);
  test_stun_invalid_password (agent, remote_addr);
  test_stun_valid_password (agent, remote_addr);

  /* clean up */
  nice_agent_free (agent);
  nice_udp_socket_factory_close (&factory);

  return 0;
}

