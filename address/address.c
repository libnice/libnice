
#include <string.h>

#include <arpa/inet.h>

#include <glib.h>

#include "address.h"


NiceAddress *
nice_address_new (void)
{
  return g_slice_new0 (NiceAddress);
}


void
nice_address_set_ipv4 (NiceAddress *addr, guint32 addr_ipv4)
{
  addr->type = NICE_ADDRESS_TYPE_IPV4;
  addr->addr_ipv4 = addr_ipv4;
}


void
nice_address_set_ipv6 (NiceAddress *addr, const gchar *addr_ipv6)
{
  addr->type = NICE_ADDRESS_TYPE_IPV6;
  memcpy (addr->addr_ipv6, addr_ipv6, sizeof (addr->addr_ipv6));
}


/**
 * address_set_ipv4_from_string ()
 *
 * Returns FALSE on error.
 */
gboolean
nice_address_set_ipv4_from_string (NiceAddress *addr, const gchar *str)
{
  struct in_addr iaddr;

  if (inet_aton (str, &iaddr) != 0)
    {
      nice_address_set_ipv4 (addr, ntohl (iaddr.s_addr));
      return TRUE;
    }
  else
    {
      /* invalid address */
      return FALSE;
    }
}


gchar *
nice_address_to_string (NiceAddress *addr)
{
  struct in_addr iaddr;
  gchar ip_str[INET_ADDRSTRLEN];
  const gchar *ret;

  g_assert (addr->type == NICE_ADDRESS_TYPE_IPV4);
  iaddr.s_addr = htonl (addr->addr_ipv4);
  ret = inet_ntop (AF_INET, &iaddr, ip_str, INET_ADDRSTRLEN);
  g_assert (ret);
  return g_strdup (ip_str);
}


gboolean
nice_address_equal (NiceAddress *a, NiceAddress *b)
{
  if (a->type != b->type)
    return FALSE;

  if (a->type == NICE_ADDRESS_TYPE_IPV4)
    return (a->addr_ipv4 == b->addr_ipv4) && (a->port == b->port);

  g_assert_not_reached ();
}


NiceAddress *
nice_address_dup (NiceAddress *a)
{
  NiceAddress *dup = g_slice_new0 (NiceAddress);

  *dup = *a;
  return dup;
}


void
nice_address_free (NiceAddress *addr)
{
  g_slice_free (NiceAddress, addr);
}


/* "private" in the sense of "not routable on the Internet" */
static gboolean
ipv4_address_is_private (guint32 addr)
{
  /* http://tools.ietf.org/html/rfc3330 */
  return (
      /* 10.0.0.0/8 */
      ((addr & 0xff000000) == 0x0a000000) ||
      /* 172.16.0.0/12 */
      ((addr & 0xfff00000) == 0xac100000) ||
      /* 192.168.0.0/16 */
      ((addr & 0xffff0000) == 0xc0a80000) ||
      /* 127.0.0.0/8 */
      ((addr & 0xff000000) == 0x7f000000));
}


gboolean
nice_address_is_private (NiceAddress *a)
{
  if (a->type == NICE_ADDRESS_TYPE_IPV4)
    return ipv4_address_is_private (a->addr_ipv4);

  g_assert_not_reached ();
}

