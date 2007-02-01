
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
  struct sockaddr_in from)
{
  NiceCandidate *candidate;
  UDPSocket *sock;
  guint len;
  struct sockaddr_in to = {0,};
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
      udp_fake_socket_push_recv (sock, &from, packed_len, packed);
      g_free (packed);
      stun_message_free (breq);
    }

  /* tell the agent there's a packet waiting */
  nice_agent_recv (agent, candidate->id);

  /* error response should have been sent */
  len = udp_fake_socket_pop_send (sock, &to, sizeof (buf) / sizeof (gchar),
      buf);
  g_assert (len != 0);

    {
      StunMessage *bres;

      /* construct expected response */
      bres = stun_message_new (STUN_MESSAGE_BINDING_ERROR_RESPONSE,
          "0123456789abcdef", 0);
      packed_len = stun_message_pack (bres, &packed);
    }

  g_assert (len == packed_len);
  g_assert (0 == memcmp (buf, packed, len));
}

static void
test_stun_invalid_password (
  NiceAgent *agent,
  struct sockaddr_in from)
{
  NiceCandidate *candidate;
  UDPSocket *sock;
  guint len;
  struct sockaddr_in to = {0,};
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
      udp_fake_socket_push_recv (sock, &from, packed_len, packed);
      g_free (packed);
      stun_message_free (breq);
    }

  /* tell the agent there's a packet waiting */
  nice_agent_recv (agent, candidate->id);

  /* error should have been sent */
  len = udp_fake_socket_pop_send (sock, &to, sizeof (buf) / sizeof (gchar),
      buf);
  g_assert (len != 0);

    {
      StunMessage *bres;

      /* construct expected response */
      bres = stun_message_new (STUN_MESSAGE_BINDING_ERROR_RESPONSE,
          "0123456789abcdef", 0);
      packed_len = stun_message_pack (bres, &packed);
    }

  g_assert (len == packed_len);
  g_assert (0 == memcmp (buf, packed, len));
}

static void
test_stun_valid_password (
  NiceAgent *agent,
  struct sockaddr_in from)
{
  NiceCandidate *candidate;
  UDPSocket *sock;
  guint len;
  guint packed_len;
  struct sockaddr_in to = {0,};
  gchar buf[1024];
  gchar *packed;

  memset (buf, '\0', 1024);

  candidate = agent->local_candidates->data;
  sock = &candidate->sock;

    {
      StunMessage *breq;
      guint packed_len;
      gchar *packed;
      gchar *username;

      /* send binding request with correct username */
      breq = stun_message_new (STUN_MESSAGE_BINDING_REQUEST,
          "0123456789abcdef", 1);
      username = g_strconcat (
          "username",
          ((NiceCandidate *) agent->local_candidates->data)->username,
          NULL);
      breq->attributes[0] = stun_attribute_username_new (username);
      g_free (username);
      packed_len = stun_message_pack (breq, &packed);
      g_assert (packed_len != 0);
      udp_fake_socket_push_recv (sock, &from, packed_len, packed);
      g_free (packed);
      stun_message_free (breq);
    }

    {
      StunMessage *bres;

      /* construct expected response packet */
      bres = stun_message_new (STUN_MESSAGE_BINDING_RESPONSE,
          "0123456789abcdef", 1);
      bres->attributes[0] = stun_attribute_mapped_address_new (
        ntohl (from.sin_addr.s_addr), 5678);
      packed_len = stun_message_pack (bres, &packed);
      g_assert (packed_len == 32);
      stun_message_free (bres);
    }

  /* tell the agent there's a packet waiting */
  nice_agent_recv (agent, candidate->id);

  /* compare sent packet to expected */
  len = udp_fake_socket_pop_send (sock, &to, sizeof (buf) / sizeof (gchar),
      buf);
  g_assert (len == packed_len);
  g_assert (0 == memcmp (buf, packed, len));
  g_assert (to.sin_family == from.sin_family);
  g_assert (to.sin_addr.s_addr == from.sin_addr.s_addr);
  g_assert (to.sin_port == from.sin_port);
  g_free (packed);
}

int
main (void)
{
  NiceAgent *agent;
  NiceAddress local_addr, remote_addr;
  NiceCandidate *candidate;
  UDPSocketManager mgr;
  UDPSocket *sock;
  struct sockaddr_in from = {0,};

  udp_fake_socket_manager_init (&mgr);

  nice_address_set_ipv4_from_string (&local_addr, "192.168.0.1");
  nice_address_set_ipv4_from_string (&remote_addr, "192.168.0.5");

  from.sin_family = AF_INET;
  from.sin_addr.s_addr = htonl (remote_addr.addr_ipv4);
  from.sin_port = htons (5678);

  /* set up agent */
  agent = nice_agent_new (&mgr);
  nice_agent_add_local_address (agent, &local_addr);
  nice_agent_add_stream (agent, handle_recv, NULL);
  nice_agent_add_remote_candidate (agent, 1, 1, NICE_CANDIDATE_TYPE_HOST,
      &remote_addr, 5678, "username", "password");
  g_assert (agent->local_candidates != NULL);
  candidate = agent->local_candidates->data;
  sock = &(candidate->sock);

  /* run tests */
  test_stun_no_password (agent, from);
  test_stun_invalid_password (agent, from);
  test_stun_valid_password (agent, from);

  /* clean up */
  nice_agent_free (agent);
  udp_socket_manager_close (&mgr);

  return 0;
}

