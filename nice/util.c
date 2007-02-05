
#include <arpa/inet.h>

#include <stdlib.h>
#include <string.h>

#include "agent.h"

/* format is:
 *   type/ip/port/username/password
 */
NiceCandidate *
nice_candidate_from_string (const gchar *s)
{
  NiceCandidateType type;
  NiceCandidate *candidate;
  guint32 ip;
  guint16 port;
  gchar **bits;

  if (s == NULL || s[0] == '\0')
    return NULL;

  bits = g_strsplit (s, "/", 5);

  if (g_strv_length (bits) != 5)
    goto ERROR;

  switch (bits[0][0])
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
      goto ERROR;
    }

  /* extract IP address */

  if (inet_pton (AF_INET, bits[1], &ip) < 1)
    goto ERROR;

  /* extract port */

  port = strtol (bits[2], NULL, 10);

  candidate = nice_candidate_new (type);
  nice_address_set_ipv4 (&candidate->addr, ntohl (ip));
  candidate->addr.port = port;

  memcpy (candidate->username, bits[3],
      MIN (strlen (bits[3]), sizeof (candidate->username)));
  memcpy (candidate->password, bits[4],
      MIN (strlen (bits[4]), sizeof (candidate->password)));

  g_strfreev (bits);
  return candidate;

ERROR:
  g_strfreev (bits);
  return NULL;
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
  ret = g_strdup_printf ("%c/%s/%d/%s/%s", type, addr_tmp,
      candidate->addr.port, candidate->username, candidate->password);
  g_free (addr_tmp);
  return ret;
}

