
#include <string.h>

#include <sys/select.h>

#include <glib.h>

#include <stun.h>
#include <udp.h>

#include "agent.h"
#include "random.h"


/*** component ***/


/* (ICE-13 §4.1.1) For RTP-based media streams, the RTP itself has a component
 * ID of 1, and RTCP a component ID of 2.  If an agent is using RTCP it MUST
 * obtain a candidate for it.  If an agent is using both RTP and RTCP, it
 * would end up with 2*K host candidates if an agent has K interfaces.
 */

typedef enum _ComponentType ComponentType;

enum _ComponentType
{
  COMPONENT_TYPE_RTP,
  COMPONENT_TYPE_RTCP,
};


typedef struct _Component Component;

struct _Component
{
  ComponentType type;
  /* the local candidate that last received a valid connectivity check */
  NiceCandidate *active_candidate;
  /* the remote address that the last connectivity check came from */
  NiceAddress *peer_addr;
  guint id;
};


static Component *
component_new (
  G_GNUC_UNUSED
  ComponentType type)
{
  Component *component;

  component = g_slice_new0 (Component);
  component->id = 1;
  return component;
}


static void
component_free (Component *cmp)
{
  g_slice_free (Component, cmp);
}


/*** stream ***/


typedef struct _Stream Stream;

struct _Stream
{
  guint id;
  /* XXX: streams can have multiple components */
  Component *component;
  NiceAgentRecvFunc handle_recv;
  gpointer handle_recv_data;
};


static Stream *
stream_new (void)
{
  Stream *stream;

  stream = g_slice_new0 (Stream);
  stream->component = component_new (COMPONENT_TYPE_RTP);
  return stream;
}


static void
stream_free (Stream *stream)
{
  component_free (stream->component);
  g_slice_free (Stream, stream);
}


/*** candidate_pair ***/


typedef struct _CandidatePair CandidatePair;

struct _CandidatePair
{
  NiceCandidate local;
  NiceCandidate remote;
};


typedef enum check_state CheckState;

/* ICE-13 §5.7 (p24) */
enum check_state
{
  CHECK_STATE_WAITING,
  CHECK_STATE_IN_PROGRESS,
  CHECK_STATE_SUCCEEDED,
  CHECK_STATE_FAILED,
  CHECK_STATE_FROZEN,
};


typedef enum check_list_state CheckListState;

enum check_list_state
{
  CHECK_LIST_STATE_RUNNING,
  CHECK_LIST_STATE_COMPLETED,
};


/* ICE-13 §5.7 */
guint64
candidate_pair_priority (
      guint64 offerer_prio,
      guint64 answerer_prio)
{
  return (
      0x100000000LL * MIN (offerer_prio, answerer_prio) +
      2 * MAX (offerer_prio, answerer_prio) +
      (offerer_prio > answerer_prio ? 1 : 0));
}


/*** agent ***/


/**
 * nice_agent_new:
 * @factory: a NiceUDPSocketFactory used for allocating sockets
 *
 * Create a new NiceAgent.
 *
 * Returns: the new agent
 **/
NiceAgent *
nice_agent_new (NiceUDPSocketFactory *factory)
{
  NiceAgent *agent;

  agent = g_slice_new0 (NiceAgent);
  agent->socket_factory = factory;
  agent->next_candidate_id = 1;
  agent->next_stream_id = 1;
  return agent;
}


static void
nice_agent_add_local_host_candidate (
  NiceAgent *agent,
  guint stream_id,
  guint component_id,
  NiceAddress *address)
{
  NiceRNG *rng;
  NiceCandidate *candidate;

  candidate = nice_candidate_new (NICE_CANDIDATE_TYPE_HOST);
  candidate->id = agent->next_candidate_id++;
  candidate->stream_id = stream_id;
  candidate->component_id = component_id;
  candidate->addr = *address;
  candidate->base_addr = *address;
  agent->local_candidates = g_slist_append (agent->local_candidates,
      candidate);

  /* generate username/password */
  rng = nice_rng_new ();
  nice_rng_generate_bytes_print (rng, 8, candidate->username);
  nice_rng_generate_bytes_print (rng, 8, candidate->password);
  nice_rng_free (rng);

  /* XXX: handle error */
  if (!nice_udp_socket_factory_make (agent->socket_factory,
        &(candidate->sock), address))
    g_assert_not_reached ();

  candidate->addr = candidate->sock.addr;
  candidate->base_addr = candidate->sock.addr;
}


/**
 * nice_agent_add_stream:
 *  @agent: a NiceAgent
 *  @handle_recv: a function called when the stream recieves data
 *  @handle_recv_data: data passed as last parameter to @handle_recv
 *
 * Add a data stream to @agent.
 *
 * Returns: the ID of the new stream
 **/
guint
nice_agent_add_stream (
  NiceAgent *agent,
  guint n_components)
{
  Stream *stream;
  GSList *i;

  g_assert (n_components == 1);
  stream = stream_new ();
  stream->id = agent->next_stream_id++;
  agent->streams = g_slist_append (agent->streams, stream);

  /* generate a local host candidate for each local address */

  for (i = agent->local_addresses; i; i = i->next)
    {
      NiceAddress *addr = i->data;

      nice_agent_add_local_host_candidate (agent, stream->id,
          stream->component->id, addr);

      /* XXX: need to check for redundant candidates? */
      /* later: send STUN requests to obtain server-reflexive candidates */
    }

  return stream->id;
}


static Stream *
_stream_lookup (NiceAgent *agent, guint stream_id)
{
  GSList *i;

  for (i = agent->streams; i; i = i->next)
    {
      Stream *s = i->data;

      if (s->id == stream_id)
        return s;
    }

  return NULL;
}


/**
 * nice_agent_remove_stream:
 *  @agent: a NiceAgent
 *  @stream_id: the ID of the stream to remove
 **/
void
nice_agent_remove_stream (
  NiceAgent *agent,
  guint stream_id)
{
  /* note that streams/candidates can be in use by other threads */

  Stream *stream;

  stream = _stream_lookup (agent, stream_id);

  if (!stream)
    return;

  /* remove candidates */

    {
      GSList *i;
      GSList *candidates = agent->local_candidates;

      for (i = agent->local_candidates; i; i = i->next)
        {
          NiceCandidate *candidate = i->data;

          if (candidate->stream_id == stream_id)
            {
              candidates = g_slist_remove (candidates, candidate);
              nice_candidate_free (candidate);
            }
        }

      agent->local_candidates = candidates;
    }

  /* remove stream */

  stream_free (stream);
  agent->streams = g_slist_remove (agent->streams, stream);
}


/**
 * nice_agent_add_local_address:
 *  @agent: A NiceAgent
 *  @addr: the address of a local IP interface
 *
 * Inform the agent of the presence of an address that a local network
 * interface is bound to.
 **/
void
nice_agent_add_local_address (NiceAgent *agent, NiceAddress *addr)
{
  NiceAddress *dup;

  dup = nice_address_dup (addr);
  dup->port = 0;
  agent->local_addresses = g_slist_append (agent->local_addresses, dup);

  /* XXX: Should we generate local candidates for existing streams at this
   * point, or require that local addresses are set before media streams are
   * added?
   */
}

/**
 * nice_agent_add_remote_candidate
 *  @agent: a NiceAgent
 *  @stream_id: the ID of the stream the candidate is for
 *  @component_id: the ID of the component the candidate is for
 *  @type: the type of the new candidate
 *  @addr: the new candidate's IP address
 *  @port: the new candidate's port
 *  @username: the new candidate's username
 *  @password: the new candidate's password
 *
 * Add a candidate our peer has informed us about to the agent's list.
 **/
void
nice_agent_add_remote_candidate (
  NiceAgent *agent,
  guint stream_id,
  guint component_id,
  NiceCandidateType type,
  NiceAddress *addr,
  gchar *username,
  gchar *password)
{
  /* append to agent->remote_candidates */

  NiceCandidate *candidate;

  candidate = nice_candidate_new (type);
  candidate->stream_id = stream_id;
  candidate->component_id = component_id;
  /* do remote candidates need IDs? */
  candidate->id = 0;
  candidate->addr = *addr;
  strncpy (candidate->username, username, sizeof (candidate->username));
  strncpy (candidate->password, password, sizeof (candidate->password));

  agent->remote_candidates = g_slist_append (agent->remote_candidates,
      candidate);

  /* later: for each component, generate a new check with the new candidate */
}


#if 0
static NiceCandidate *
_local_candidate_lookup (NiceAgent *agent, guint candidate_id)
{
  GSList *i;

  for (i = agent->local_candidates; i; i = i->next)
    {
      NiceCandidate *c = i->data;

      if (c->id == candidate_id)
        return c;
    }

  return NULL;
}
#endif


static NiceCandidate *
_local_candidate_lookup_by_fd (NiceAgent *agent, guint fd)
{
  GSList *i;

  for (i = agent->local_candidates; i; i = i->next)
    {
      NiceCandidate *c = i->data;

      if (c->sock.fileno == fd)
        return c;
    }

  return NULL;
}


static void
_handle_stun_binding_request (
  NiceAgent *agent,
  Stream *stream,
  NiceCandidate *local,
  NiceAddress from,
  StunMessage *msg)
{
  GSList *i;
  StunAttribute **attr;
  gchar *username = NULL;
  NiceCandidate *remote = NULL;

  /* msg should have either:
   *
   *   Jingle P2P:
   *     username = local candidate username + remote candidate username
   *   ICE:
   *     username = local candidate username + ":" + local candidate username
   *     password = local candidate pwd
   *     priority = priority to use if a new candidate is generated
   *
   * Note that:
   *
   *  - "local"/"remote" are from the perspective of the receiving side
   *  - the remote candidate username is not necessarily unique; Jingle seems
   *    to always generate a unique username/password for each candidate, but
   *    ICE makes no guarantees
   *
   * There are three cases we need to deal with:
   *
   *  - valid username with a known address
   *    --> send response
   *  - valid username with an unknown address
   *    --> send response
   *    --> later: create new remote candidate
   *  - invalid username
   *    --> send error
   */

  if (msg->attributes)
    for (attr = msg->attributes; *attr; attr++)
      if ((*attr)->type == STUN_ATTRIBUTE_USERNAME)
        {
          username = (*attr)->username;
          break;
        }

  if (username == NULL)
    /* no username attribute found */
    goto ERROR;

  /* validate username */
  /* XXX: what about the case where the username uniquely identifies a remote
   * candidate, but the transport address is not the one we expected?
   */

  for (i = agent->remote_candidates; i; i = i->next)
    {
      guint len;

      remote = i->data;

      if (!g_str_has_prefix (username, local->username))
        continue;

      len = strlen (local->username);

      if (0 != strcmp (username + len, remote->username))
        continue;

#if 0
      /* usernames match; check address */

      if (rtmp->addr.addr_ipv4 == ntohs (from.sin_addr.s_addr) &&
          rtmp->port == ntohl (from.sin_port))
        {
          /* this is a candidate we know about, just send a reply */
          /* is candidate pair active now? */
          remote = rtmp;
        }
#endif

      /* send response */
      goto RESPOND;
    }

  /* username is not valid */
  goto ERROR;

RESPOND:

#ifdef DEBUG
    {
      gchar *ip;

      ip = nice_address_to_string (&remote->addr);
      g_debug ("got valid connectivity check for candidate %d (%s:%d)",
          remote->id, ip, remote->addr.port);
      g_free (ip);
    }
#endif

  /* update candidate/peer affinity */

    {
      Component *component;

      component = stream->component;
      g_assert (component);

      component->active_candidate = local;
      component->peer_addr = &remote->addr;
    }

  /* send STUN response */

    {
      StunMessage *response;
      guint len;
      gchar *packed;

      response = stun_message_new (STUN_MESSAGE_BINDING_RESPONSE,
          msg->transaction_id, 2);
      response->attributes[0] = stun_attribute_mapped_address_new (
          from.addr_ipv4, from.port);
      response->attributes[1] = stun_attribute_username_new (username);
      len = stun_message_pack (response, &packed);
      nice_udp_socket_send (&local->sock, &from, len, packed);

      g_free (packed);
      stun_message_free (response);
    }

  /* send reciprocal ("triggered") connectivity check */
  /* XXX: possibly we shouldn't do this if we're being an ICE Lite agent */

    {
      NiceRNG *rng;
      StunMessage *extra;
      gchar *username;
      guint len;
      gchar *packed;

      extra = stun_message_new (STUN_MESSAGE_BINDING_REQUEST,
          NULL, 1);

      username = g_strconcat (remote->username, local->username, NULL);
      extra->attributes[0] = stun_attribute_username_new (username);
      g_free (username);

      rng = nice_rng_new ();
      nice_rng_generate_bytes (rng, 16, extra->transaction_id);
      nice_rng_free (rng);

      len = stun_message_pack (extra, &packed);
      nice_udp_socket_send (&local->sock, &from, len, packed);
      g_free (packed);

      stun_message_free (extra);
    }

  return;

ERROR:

#ifdef DEBUG
    {
      gchar *ip;

      ip = nice_address_to_string (&remote->addr);
      g_debug ("got invalid connectivity check for candidate %d (%s:%d)",
          remote->id, ip, remote->addr.port);
      g_free (ip);
    }
#endif

  /* XXX: add ERROR-CODE parameter */

    {
      StunMessage *response;
      guint len;
      gchar *packed;

      response = stun_message_new (STUN_MESSAGE_BINDING_ERROR_RESPONSE,
          msg->transaction_id, 0);
      len = stun_message_pack (response, &packed);
      nice_udp_socket_send (&local->sock, &from, len, packed);

      g_free (packed);
      stun_message_free (response);
    }

  /* XXX: we could be clever and keep around STUN packets that we couldn't
   * validate, then re-examine them when we get new remote candidates -- would
   * this fix some timing problems (i.e. TCP being slower than UDP)
   */
  /* XXX: if the peer is the controlling agent, it may include a USE-CANDIDATE
   * attribute in the binding request
   */
}


static void
_handle_stun (
  NiceAgent *agent,
  Stream *stream,
  NiceCandidate *local,
  NiceAddress from,
  StunMessage *msg)
{
  switch (msg->type)
    {
    case STUN_MESSAGE_BINDING_REQUEST:
      _handle_stun_binding_request (agent, stream, local, from, msg);
      break;
    case STUN_MESSAGE_BINDING_RESPONSE:
      /* XXX: check it matches a request we sent */
      break;
    default:
      /* a message type we don't know how to handle */
      /* XXX: send error response */
      break;
    }
}


static guint
_nice_agent_recv (
  NiceAgent *agent,
  Stream *stream,
  NiceCandidate *candidate,
  guint buf_len,
  gchar *buf)
{
  NiceAddress from;
  guint len;

  len = nice_udp_socket_recv (&(candidate->sock), &from,
      buf_len, buf);
  g_assert (len > 0);
  g_assert (len < buf_len);

  /* XXX: verify sender; maybe:
   * 
   * if (candidate->other != NULL)
   *   {
   *     if (from != candidate->other.addr)
   *       // ignore packet from unexpected sender
   *       return;
   *   }
   * else
   *   {
   *     // go through remote candidates, looking for one matching packet from
   *     // address; if found, assign it to candidate->other and call handler,
   *     // otherwise ignore it
   *   }
   *
   * Perhaps remote socket affinity is superfluous and all we need is the
   * second part.
   * Perhaps we should also check whether this candidate is supposed to be
   * active.
   */

  /* The top two bits of an RTP message are the version number; the current
   * version number is 2. The top two bits of a STUN message are always 0.
   */

  if ((buf[0] & 0xc0) == 0x80)
    {
      /* looks like RTP */
      return len;
    }
  else if ((buf[0] & 0xc0) == 0)
    {
      /* looks like a STUN message (connectivity check) */
      /* connectivity checks are described in ICE-13 §7. */
      StunMessage *msg;

      msg = stun_message_unpack (len, buf);

      if (msg != NULL)
        {
          _handle_stun (agent, stream, candidate, from, msg);
          stun_message_free (msg);
        }
    }

  /* anything else is ignored */
  return 0;
}


/**
 * nice_agent_recv:
 *  @agent: a NiceAgent
 *  @stream_id: the ID of the stream to recieve data from
 *  @component_id: the ID of the component to receive data from
 *  @buf_len: the size of @buf
 *  @buf: the buffer to read data into
 *
 * Recieve data on a particular component.
 *
 * Returns: the amount of data read into @buf
 **/
guint
nice_agent_recv (
  NiceAgent *agent,
  guint stream_id,
  guint component_id,
  guint buf_len,
  gchar *buf)
{
  guint len = 0;
  fd_set fds;
  guint max_fd = 0;
  gint num_readable;
  GSList *i;

  for (i = agent->local_candidates; i; i = i->next)
    {
      NiceCandidate *candidate;

      candidate = i->data;

      if (candidate->stream_id == stream_id &&
          candidate->component_id == component_id)
        {
          FD_SET (candidate->sock.fileno, &fds);
          max_fd = MAX (candidate->sock.fileno, max_fd);
        }
    }

  /* Loop on candidate sockets until we find one that has non-STUN data
   * waiting on it.
   */

  for (;;)
    {
      num_readable = select (max_fd + 1, &fds, NULL, NULL, 0);
      g_assert (num_readable >= 0);

      if (num_readable > 0)
        {
          guint j;

          for (j = 0; j <= max_fd; j++)
            if (FD_ISSET (j, &fds))
              {
                NiceCandidate *candidate;
                Stream *stream;

                candidate = _local_candidate_lookup_by_fd (agent, j);
                g_assert (candidate);
                stream = _stream_lookup (agent, candidate->stream_id);
                len = _nice_agent_recv (agent, stream, candidate, buf_len,
                    buf);

                if (len > 0)
                  return len;
              }
        }
    }

  g_assert_not_reached ();
}


/**
 * nice_agent_poll_read:
 *  @agent: A NiceAgent
 *  @other_fds: A GSList of other file descriptors to poll
 *
 * Polls the agent's sockets until at least one of them is readable, and
 * additionally if @other_fds is not NULL, polls those for readability too.
 * @other_fds should contain the file descriptors directly, i.e. using
 * GUINT_TO_POINTER.
 *
 * Returns: A list of file descriptors from @other_fds that are readable
 **/
GSList *
nice_agent_poll_read (
  NiceAgent *agent,
  GSList *other_fds,
  NiceAgentRecvFunc func,
  gpointer data)
{
  fd_set fds;
  guint max_fd = 0;
  gint num_readable;
  GSList *ret = NULL;
  GSList *i;
  guint j;

  FD_ZERO (&fds);

  for (i = agent->local_candidates; i; i = i->next)
    {
      NiceCandidate *candidate;

      candidate = i->data;
      FD_SET (candidate->sock.fileno, &fds);
      max_fd = MAX (candidate->sock.fileno, max_fd);
    }

  for (i = other_fds; i; i = i->next)
    {
      guint fileno;

      fileno = GPOINTER_TO_UINT (i->data);
      FD_SET (fileno, &fds);
      max_fd = MAX (fileno, max_fd);
    }

  num_readable = select (max_fd + 1, &fds, NULL, NULL, 0);

  if (num_readable < 1)
    /* none readable, or error */
    return NULL;

  for (j = 0; j <= max_fd; j++)
    if (FD_ISSET (j, &fds))
      {
        GSList *i;

        if (g_slist_find (other_fds, GUINT_TO_POINTER (j)))
          ret = g_slist_append (ret, GUINT_TO_POINTER (j));
        else
          for (i = agent->local_candidates; i; i = i->next)
            {
              NiceCandidate *candidate = i->data;

              if (candidate->sock.fileno == j)
                {
                  Stream *stream;
                  gchar buf[1024];
                  guint len;

                  stream = _stream_lookup (agent, candidate->stream_id);

                  if (stream == NULL)
                    break;

                  len = _nice_agent_recv (agent, stream, candidate, 1024, buf);

                  if (len && func != NULL)
                    func (agent, stream->id, candidate->component_id, len, buf,
                        stream->handle_recv_data);
                }
            }
      }

  return ret;
}


void
nice_agent_send (
  NiceAgent *agent,
  guint stream_id,
  G_GNUC_UNUSED
  guint component_id,
  guint len,
  gchar *buf)
{
  Stream *stream;
  Component *component;

  stream = _stream_lookup (agent, stream_id);
  component = stream->component;

  if (component->active_candidate != NULL)
    {
      NiceUDPSocket *sock;
      NiceAddress *addr;

      sock = &component->active_candidate->sock;
      addr = component->peer_addr;
      nice_udp_socket_send (sock, addr, len, buf);
    }
}


/**
 * Set the STUN server from which to obtain server-reflexive candidates.
 */
/*
void
nice_agent_set_stun_server (NiceAddress *addr, guint16 port)
{
}
*/

/**
 * nice_agent_get_local_candidates:
 *  @agent: A NiceAgent
 *
 * The caller does not own the returned GSList or the candidates contained
 * within it.
 *
 * Returns: a GSList of local candidates belonging to @agent
 **/
const GSList *
nice_agent_get_local_candidates (
  NiceAgent *agent)
{
  return agent->local_candidates;
}

/**
 * nice_agent_free:
 *  @agent: a NiceAgent
 *
 * Free the agent.
 **/
void
nice_agent_free (NiceAgent *agent)
{
  GSList *i;

  for (i = agent->local_addresses; i; i = i->next)
    {
      NiceAddress *a = i->data;

      nice_address_free (a);
    }

  g_slist_free (agent->local_addresses);
  agent->local_addresses = NULL;

  for (i = agent->local_candidates; i; i = i->next)
    {
      NiceCandidate *c = i->data;

      nice_candidate_free (c);
    }

  g_slist_free (agent->local_candidates);
  agent->local_candidates = NULL;

  for (i = agent->remote_candidates; i; i = i->next)
    {
      NiceCandidate *c = i->data;

      nice_candidate_free (c);
    }

  g_slist_free (agent->remote_candidates);
  agent->remote_candidates = NULL;

  for (i = agent->streams; i; i = i->next)
    {
      Stream *s = i->data;

      stream_free (s);
    }

  g_slist_free (agent->streams);
  agent->streams = NULL;

  g_slice_free (NiceAgent, agent);
}

