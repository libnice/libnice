
#include <string.h>

#include <arpa/inet.h>

#include <glib.h>

#include <agent.h>
#include <util.h>

int
main (void)
{
  Address *addr;
  Candidate *candidate;
  gchar *str;

  candidate = candidate_from_string ("x");
  g_assert (candidate == NULL);

  addr = address_new_ipv4_from_string ("192.168.0.1");
  candidate = candidate_from_string ("H/192.168.0.1/1234");
  g_assert (candidate != NULL);
  g_assert (address_equal (addr, candidate->addr));
  g_assert (candidate->port == 1234);
  address_free (addr);

  str = candidate_to_string (candidate);
  g_assert (0 == strcmp (str, "H/192.168.0.1/1234"));
  g_free (str);

  candidate_free (candidate);
  return 0;
}

