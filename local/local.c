
#include <glib.h>

#include <arpa/inet.h>
#include <ifaddrs.h>

#include "local.h"

NiceInterface *
nice_interface_new ()
{
  return g_slice_new0 (NiceInterface);
}

void
nice_interface_free (NiceInterface *iface)
{
  g_free (iface->name);
  g_slice_free (NiceInterface, iface);
}

GSList *
nice_list_local_interfaces ()
{
  GSList *ret = NULL;
  struct ifaddrs *ifs;
  struct ifaddrs *i;

  getifaddrs (&ifs);

  for (i = ifs; i; i = i->ifa_next)
    {
      struct sockaddr_in *addr;

      addr = (struct sockaddr_in *) i->ifa_addr;

      if (addr->sin_family == AF_INET || addr->sin_family == AF_INET6)
        {
          NiceInterface *iface;

          iface = g_slice_new0 (NiceInterface);
          iface->name = g_strdup (i->ifa_name);

          if (addr->sin_family == AF_INET)
            nice_address_set_ipv4 (&iface->addr,
                ntohl (addr->sin_addr.s_addr));
          else
            nice_address_set_ipv6 (&iface->addr,
                (gchar *) &((struct sockaddr_in6 *) addr)->sin6_addr);

          ret = g_slist_append (ret, iface);
        }
    }

  freeifaddrs (ifs);
  return ret;
}

