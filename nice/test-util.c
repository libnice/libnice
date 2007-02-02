
#include <string.h>

#include "agent.h"
#include "util.h"

int
main (void)
{
  NiceAddress addr;
  NiceCandidate *candidate;
  gchar *str;

  candidate = nice_candidate_from_string ("x");
  g_assert (candidate == NULL);

  g_assert (nice_address_set_ipv4_from_string (&addr, "192.168.0.1"));
  candidate = nice_candidate_from_string ("H/192.168.0.1/1234/foo/bar");
  g_assert (candidate != NULL);
  g_assert (nice_address_equal (&addr, &(candidate->addr)));
  g_assert (candidate->port == 1234);
  g_assert (0 == strcmp (candidate->username, "foo"));
  g_assert (0 == strcmp (candidate->password, "bar"));

  str = nice_candidate_to_string (candidate);
  g_assert (0 == strcmp (str, "H/192.168.0.1/1234/foo/bar"));
  g_free (str);

  nice_candidate_free (candidate);
  return 0;
}

