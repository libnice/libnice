
#include <glib.h>

#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <unistd.h>

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
  char buf[1024];
  gint sock;
  guint i;
  GSList *ret = NULL;
  struct ifconf ifc;

  sock = socket (PF_INET, SOCK_DGRAM, 0);

  if (sock < 0)
    return NULL;

  ifc.ifc_len = sizeof (buf);
  ifc.ifc_buf = buf;

  if (ioctl (sock, SIOCGIFCONF, &ifc) < 0)
    return NULL;

  /* FIXME: test case where ifc.ifc_len == sizeof (buf) (overflow) */
  /* FIXME: support IPv6 */

  for (i = 0; i < ifc.ifc_len / sizeof (struct ifreq); i++)
    {
      struct ifreq *ifr = ifc.ifc_req + i;
      struct sockaddr_in *sin;
      NiceInterface *iface;

      if (ifr->ifr_addr.sa_family != AF_INET)
        /* this probably shouldn't happen */
        continue;

      iface = g_slice_new0 (NiceInterface);
      iface->name = g_strdup (ifr->ifr_name);

      sin = (struct sockaddr_in *) &(ifr->ifr_addr);
      iface->addr = (addr_ipv4) ntohl (sin->sin_addr.s_addr);

      ret = g_slist_append (ret, iface);
    }

  close (sock);
  return ret;
}

