
#include "agent.h"


/* (ICE-13 §4.1.1) Every candidate is a transport address. It also has a type and
 * a base. Three types are defined and gathered by this specification - host
 * candidates, server reflexive candidates, and relayed candidates. */


NiceCandidate *
nice_candidate_new (NiceCandidateType type)
{
  NiceCandidate *candidate;

  candidate = g_slice_new0 (NiceCandidate);
  candidate->type = type;
  return candidate;
}


void
nice_candidate_free (NiceCandidate *candidate)
{
  /* better way of checking if socket is allocated? */

  if (candidate->sock.addr.addr_ipv4 != 0)
    nice_udp_socket_close (&(candidate->sock));

  g_slice_free (NiceCandidate, candidate);
}


gfloat
nice_candidate_jingle_priority (NiceCandidate *candidate)
{
  switch (candidate->type)
    {
    case NICE_CANDIDATE_TYPE_HOST:             return 1.0;
    case NICE_CANDIDATE_TYPE_SERVER_REFLEXIVE: return 0.9;
    case NICE_CANDIDATE_TYPE_PEER_REFLEXIVE:   return 0.9;
    case NICE_CANDIDATE_TYPE_RELAYED:          return 0.5;
    }

  /* appease GCC */
  return 0;
}


/* ICE-13 §4.1.2; returns number between 1 and 0x7effffff */
G_GNUC_CONST
static guint32
_candidate_ice_priority (
  // must be ∈ (0, 126) (max 2^7 - 2)
  guint type_preference,
  // must be ∈ (0, 65535) (max 2^16 - 1)
  guint local_preference,
  // must be ∈ (1, 255) (max 2 ^ 8 - 1)
  guint component_id)
{
  return (
      0x1000000 * type_preference +
      0x100 * local_preference +
      (0x100 - component_id));
}


guint32
nice_candidate_ice_priority (NiceCandidate *candidate)
{
  guint8 type_preference = 0;

  switch (candidate->type)
    {
    case NICE_CANDIDATE_TYPE_HOST:             type_preference = 120; break;
    case NICE_CANDIDATE_TYPE_PEER_REFLEXIVE:   type_preference = 110; break;
    case NICE_CANDIDATE_TYPE_SERVER_REFLEXIVE: type_preference = 100; break;
    case NICE_CANDIDATE_TYPE_RELAYED:          type_preference =  60; break;
    }

  return _candidate_ice_priority (type_preference, 1, candidate->component_id);
}

