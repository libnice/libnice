
#include <string.h>

#include "stun.h"
#include "udp-fake.h"
#include "agent.h"

void
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

int
main (void)
{
  NiceAgent *agent;
  NiceAddress local_addr, remote_addr;
  NiceCandidate *candidate;
  UDPSocketManager mgr;
  UDPSocket *sock;
  StunMessage *breq, *bres;
  struct sockaddr_in from, to;
  guint packed_len;
  gchar *packed;
  guint len;
  gchar buf[1024];

  memset (buf, '\0', 1024);

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
  g_assert (agent->local_candidates != NULL);
  candidate = agent->local_candidates->data;
  sock = &(candidate->sock);

  /* send binding request without password */
  breq = stun_message_new (STUN_MESSAGE_BINDING_REQUEST);
  memcpy (breq->transaction_id, "0123456789abcdef", 16);
  packed_len = stun_message_pack (breq, &packed);
  udp_fake_socket_push_recv (sock, &from, packed_len, packed);
  g_free (packed);
  stun_message_free (breq);

  /* tell the agent there's a packet waiting */
  nice_agent_recv (agent, candidate->id);

  /* no reply should have been sent */
  len = udp_fake_socket_pop_send (sock, &to, sizeof (buf) / sizeof (gchar),
      buf);
  g_assert (len == 0);

  /* send binding request with password */
  breq = stun_message_new (STUN_MESSAGE_BINDING_REQUEST);
  breq->attributes = g_malloc0 (2 * sizeof (StunAttribute *));
  breq->attributes[0] = stun_attribute_username_new ("lala");
  memcpy (breq->transaction_id, "0123456789abcdef", 16);
  packed_len = stun_message_pack (breq, &packed);
  g_assert (packed_len != 0);
  udp_fake_socket_push_recv (sock, &from, packed_len, packed);
  g_free (packed);
  stun_message_free (breq);

  /* tell the agent there's a packet waiting */
  nice_agent_recv (agent, candidate->id);

  /* construct expected response packet */
  bres = stun_message_new (STUN_MESSAGE_BINDING_RESPONSE);
  memcpy (bres->transaction_id, "0123456789abcdef", 16);
  bres->attributes = g_malloc0 (2 * sizeof (StunAttribute *));
  bres->attributes[0] = stun_attribute_mapped_address_new (
    remote_addr.addr_ipv4, 5678);
  packed_len = stun_message_pack (bres, &packed);
  g_assert (packed_len == 32);

  /* compare sent packet to expected */
  len = udp_fake_socket_pop_send (sock, &to, sizeof (buf) / sizeof (gchar),
      buf);
  g_assert (len == packed_len);
  g_assert (0 == memcmp (buf, packed, len));
  g_assert (to.sin_family == from.sin_family);
  g_assert (to.sin_addr.s_addr == from.sin_addr.s_addr);
  g_assert (to.sin_port == from.sin_port);

  g_free (packed);
  stun_message_free (bres);

  /* clean up */
  nice_agent_free (agent);
  udp_socket_manager_close (&mgr);

  return 0;
}

