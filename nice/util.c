
#include <string.h>
#include <stdlib.h>

#include <arpa/inet.h>

#include <glib.h>

#include <udp.h>

#include <agent.h>

/* format is:
 *   type/ip/port
 */
NiceCandidate *
nice_candidate_from_string (const gchar *s)
{
  NiceCandidateType type;
  NiceCandidate *candidate;
  gchar *first_slash;
  gchar *last_slash;
  gchar tmp[128];
  guint len;
  guint32 ip;
  guint16 port;

  if (s == NULL || s[0] == '\0')
    return NULL;

  switch (s[0])
    {
    case 'H':
      type = NICE_CANDIDATE_TYPE_HOST;
      break;
    case 'S':
      type = NICE_CANDIDATE_TYPE_SERVER_REFLEXIVE;
      break;
    case 'P':
      type = NICE_CANDIDATE_TYPE_PEER_REFLEXIVE;
      break;
    case 'R':
      type = NICE_CANDIDATE_TYPE_RELAYED;
      break;
    default:
      return NULL;
    }

  /* extract IP address */

  first_slash = index (s, '/');
  last_slash = rindex (s, '/');

  if (first_slash == NULL ||
      last_slash == NULL ||
      first_slash == last_slash)
    return NULL;

  len = last_slash - first_slash - 1;

  if (len > sizeof (tmp) - 1)
    return NULL;

  strncpy (tmp, first_slash + 1, len);
  tmp[len] = '\0';

  if (inet_pton (AF_INET, tmp, &ip) < 1)
    return NULL;

  /* extract port */

  port = strtol (last_slash + 1, NULL, 10);

  candidate = nice_candidate_new (type);
  nice_address_set_ipv4 (&candidate->addr, ntohl (ip));
  candidate->port = port;

  return candidate;
}

gchar *
nice_candidate_to_string (NiceCandidate *candidate)
{
  gchar *addr_tmp;
  gchar *ret;
  gchar type;

  switch (candidate->type)
    {
    case NICE_CANDIDATE_TYPE_HOST:
      type = 'H';
      break;
    case NICE_CANDIDATE_TYPE_SERVER_REFLEXIVE:
      type = 'S';
      break;
    case NICE_CANDIDATE_TYPE_PEER_REFLEXIVE:
      type = 'P';
      break;
    case NICE_CANDIDATE_TYPE_RELAYED:
      type = 'R';
      break;
    default:
      return NULL;
    }

  addr_tmp = nice_address_to_string (&(candidate->addr));
  ret = g_strdup_printf ("%c/%s/%d", type, addr_tmp, candidate->port);
  g_free (addr_tmp);
  return ret;
}

