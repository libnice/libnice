
#include <arpa/inet.h>

#include <glib.h>

#include "udp.h"
#include "agent.h"

int
main (void)
{
  NiceCandidate *candidate;

  candidate = nice_candidate_new (NICE_CANDIDATE_TYPE_HOST);
  g_assert (nice_candidate_ice_priority (candidate) == 0x78000200);
  g_assert (nice_candidate_jingle_priority (candidate) == 1.0);
  nice_candidate_free (candidate);

  return 0;
}

