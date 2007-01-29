
#include <arpa/inet.h>

#include <glib.h>

#include "udp.h"
#include "agent.h"

int
main (void)
{
  Candidate *candidate;

  candidate = candidate_new (CANDIDATE_TYPE_HOST);
  g_assert (candidate_ice_priority (candidate) == 0x78000200);
  g_assert (candidate_jingle_priority (candidate) == 1.0);
  candidate_free (candidate);

  return 0;
}

