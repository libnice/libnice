/*
 * interfaces.c - Source for interface discovery code
 *
 * Copyright (C) 2006 Youness Alaoui <kakaroto@kakaroto.homelinux.net>
 * Copyright (C) 2007 Collabora, Nokia
 *  Contact: Youness Alaoui
 * Copyright (C) 2008 Haakon Sporsheim <haakon.sporsheim@tandberg.com>
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is the Nice GLib ICE library.
 *
 * The Initial Developers of the Original Code are Collabora Ltd and Nokia
 * Corporation. All Rights Reserved.
 *
 * Contributors:
 *   Dafydd Harries, Collabora Ltd.
 *   Youness Alaoui, Collabora Ltd.
 *   Kai Vehmanen, Nokia
 *   Philip Withnall, Collabora Ltd.
 *   Haakon Sporsheim
 *
 * Alternatively, the contents of this file may be used under the terms of the
 * the GNU Lesser General Public License Version 2.1 (the "LGPL"), in which
 * case the provisions of LGPL are applicable instead of those above. If you
 * wish to allow use of your version of this file only under the terms of the
 * LGPL and not to allow others to use your version of this file under the
 * MPL, indicate your decision by deleting the provisions above and replace
 * them with the notice and other provisions required by the LGPL. If you do
 * not delete the provisions above, a recipient may use your version of this
 * file under either the MPL or the LGPL.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "interfaces.h"
#include "agent-priv.h"

#ifdef G_OS_UNIX

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#ifdef __sun
#include <sys/sockio.h>
#endif

#ifdef HAVE_GETIFADDRS
 #include <ifaddrs.h>
#endif

#include <net/if.h>
#include <arpa/inet.h>

#endif /* G_OS_UNIX */

#if (defined(G_OS_UNIX) && defined(HAVE_GETIFADDRS)) || defined(G_OS_WIN32)
/* Works on both UNIX and Windows. Magic! */
static gchar *
sockaddr_to_string (const struct sockaddr *addr)
{
  char addr_as_string[INET6_ADDRSTRLEN+1];
  size_t addr_len;

  switch (addr->sa_family) {
    case AF_INET: addr_len = sizeof (struct sockaddr_in); break;
    case AF_INET6: addr_len = sizeof (struct sockaddr_in6); break;
    default: return NULL;
  }

  if (getnameinfo (addr, addr_len,
          addr_as_string, sizeof (addr_as_string), NULL, 0,
          NI_NUMERICHOST) != 0) {
    return NULL;
  }

  return g_strdup (addr_as_string);
}
#endif

#ifdef G_OS_UNIX

#ifdef HAVE_GETIFADDRS

GList *
nice_interfaces_get_local_interfaces (void)
{
  GList *interfaces = NULL;
  struct ifaddrs *ifa, *results;

  if (getifaddrs (&results) < 0) {
    return NULL;
  }

  /* Loop and get each interface the system has, one by one... */
  for (ifa = results; ifa; ifa = ifa->ifa_next) {
    /* no ip address from interface that is down */
    if ((ifa->ifa_flags & IFF_UP) == 0)
      continue;

    if (ifa->ifa_addr == NULL)
      continue;

    if (ifa->ifa_addr->sa_family == AF_INET || ifa->ifa_addr->sa_family == AF_INET6) {
      nice_debug ("Found interface : %s", ifa->ifa_name);
      interfaces = g_list_prepend (interfaces, g_strdup (ifa->ifa_name));
    }
  }

  freeifaddrs (results);

  return interfaces;
}

#else /* ! HAVE_GETIFADDRS */

GList *
nice_interfaces_get_local_interfaces (void)
{
  GList *interfaces = NULL;
  gint sockfd;
  gint size = 0;
  struct ifreq *ifr;
  struct ifconf ifc;

  if ((sockfd = socket (AF_INET, SOCK_DGRAM, IPPROTO_IP)) < 0) {
    nice_debug ("error : Cannot open socket to retreive interface list");
    return NULL;
  }

  ifc.ifc_len = 0;
  ifc.ifc_req = NULL;

  /* Loop and get each interface the system has, one by one... */
  do {
    size += sizeof (struct ifreq);
    /* realloc buffer size until no overflow occurs  */
    if (NULL == (ifc.ifc_req = realloc (ifc.ifc_req, size))) {
      nice_debug ("Error : Out of memory while allocation interface"
          "configuration structure");
      close (sockfd);
      return NULL;
    }
    ifc.ifc_len = size;

    if (ioctl (sockfd, SIOCGIFCONF, &ifc)) {
      perror ("ioctl SIOCFIFCONF");
      close (sockfd);
      free (ifc.ifc_req);
      return NULL;
    }
  } while (size <= ifc.ifc_len);


  /* Loop throught the interface list and get the IP address of each IF */
  for (ifr = ifc.ifc_req;
       (gchar *) ifr < (gchar *) ifc.ifc_req + ifc.ifc_len;
       ++ifr) {
    nice_debug ("Found interface : %s", ifr->ifr_name);
    interfaces = g_list_prepend (interfaces, g_strdup (ifr->ifr_name));
  }

  free (ifc.ifc_req);
  close (sockfd);

  return interfaces;
}
#endif /* HAVE_GETIFADDRS */


static gboolean
nice_interfaces_is_private_ip (const struct sockaddr *_sa)
{
  union {
    const struct sockaddr *addr;
    const struct sockaddr_in *in;
  } sa;

  sa.addr = _sa;

  if (sa.addr->sa_family == AF_INET) {
    /* 10.x.x.x/8 */
    if (sa.in->sin_addr.s_addr >> 24 == 0x0A)
      return TRUE;

    /* 172.16.0.0 - 172.31.255.255 = 172.16.0.0/10 */
    if (sa.in->sin_addr.s_addr >> 20 == 0xAC1)
      return TRUE;

    /* 192.168.x.x/16 */
    if (sa.in->sin_addr.s_addr >> 16 == 0xC0A8)
      return TRUE;

    /* 169.254.x.x/16  (for APIPA) */
    if (sa.in->sin_addr.s_addr >> 16 == 0xA9FE)
      return TRUE;
  }
  
  return FALSE;
}

static GList *
add_ip_to_list (GList *list, gchar *ip, gboolean append)
{
  GList *i;

  for (i = list; i; i = i->next) {
    gchar *addr = (gchar *) i->data;

    if (g_strcmp0 (addr, ip) == 0)
      return list;
  }
  if (append)
    return g_list_append (list, ip);
  else
    return g_list_prepend (list, ip);
}

#ifdef HAVE_GETIFADDRS

GList *
nice_interfaces_get_local_ips (gboolean include_loopback)
{
  GList *ips = NULL;
  struct ifaddrs *ifa, *results;
  GList *loopbacks = NULL;


  if (getifaddrs (&results) < 0)
      return NULL;

  /* Loop through the interface list and get the IP address of each IF */
  for (ifa = results; ifa; ifa = ifa->ifa_next) {
    gchar *addr_string;

    /* no ip address from interface that is down */
    if ((ifa->ifa_flags & IFF_UP) == 0)
      continue;

    if (ifa->ifa_addr == NULL)
      continue;

    /* Convert to a string. */
    addr_string = sockaddr_to_string (ifa->ifa_addr);
    if (addr_string == NULL) {
      nice_debug ("Failed to convert address to string for interface ‘%s’.",
          ifa->ifa_name);
      continue;
    }

    nice_debug ("Interface:  %s", ifa->ifa_name);
    nice_debug ("IP Address: %s", addr_string);
    if ((ifa->ifa_flags & IFF_LOOPBACK) == IFF_LOOPBACK) {
      if (include_loopback) {
        loopbacks = add_ip_to_list (loopbacks, addr_string, TRUE);
      } else {
        nice_debug ("Ignoring loopback interface");
        g_free (addr_string);
      }
    } else {
      if (nice_interfaces_is_private_ip (ifa->ifa_addr))
        ips = add_ip_to_list (ips, addr_string, TRUE);
      else
        ips = add_ip_to_list (ips, addr_string, FALSE);
    }
  }

  freeifaddrs (results);

  if (loopbacks)
    ips = g_list_concat (ips, loopbacks);

  return ips;
}

#else /* ! HAVE_GETIFADDRS */

GList *
nice_interfaces_get_local_ips (gboolean include_loopback)
{
  GList *ips = NULL;
  gint sockfd;
  gint size = 0;
  struct ifreq *ifr;
  struct ifconf ifc;
  struct sockaddr_in *sa;
  gchar *loopback = NULL;

  if ((sockfd = socket (AF_INET, SOCK_DGRAM, IPPROTO_IP)) < 0) {
    nice_debug ("Error : Cannot open socket to retreive interface list");
    return NULL;
  }

  ifc.ifc_len = 0;
  ifc.ifc_req = NULL;

  /* Loop and get each interface the system has, one by one... */
  do {
    size += sizeof (struct ifreq);
    /* realloc buffer size until no overflow occurs  */
    if (NULL == (ifc.ifc_req = realloc (ifc.ifc_req, size))) {
      nice_debug ("Error : Out of memory while allocation interface"
          " configuration structure");
      close (sockfd);
      return NULL;
    }
    ifc.ifc_len = size;

    if (ioctl (sockfd, SIOCGIFCONF, &ifc)) {
      perror ("ioctl SIOCFIFCONF");
      close (sockfd);
      free (ifc.ifc_req);
      return NULL;
    }
  } while  (size <= ifc.ifc_len);


  /* Loop throught the interface list and get the IP address of each IF */
  for (ifr = ifc.ifc_req;
       (gchar *) ifr < (gchar *) ifc.ifc_req + ifc.ifc_len;
       ++ifr) {

    if (ioctl (sockfd, SIOCGIFFLAGS, ifr)) {
      nice_debug ("Error : Unable to get IP information for interface %s."
          " Skipping...", ifr->ifr_name);
      continue;  /* failed to get flags, skip it */
    }
    sa = (struct sockaddr_in *) &ifr->ifr_addr;
    nice_debug ("Interface:  %s", ifr->ifr_name);
    nice_debug ("IP Address: %s", inet_ntoa (sa->sin_addr));
    if ((ifr->ifr_flags & IFF_LOOPBACK) == IFF_LOOPBACK){
      if (include_loopback)
        loopback = g_strdup (inet_ntoa (sa->sin_addr));
      else
        nice_debug ("Ignoring loopback interface");
    } else {
      if (nice_interfaces_is_private_ip ((struct sockaddr *) sa)) {
        ips = add_ip_to_list (ips, g_strdup (inet_ntoa (sa->sin_addr)), TRUE);
      } else {
        ips = add_ip_to_list (ips, g_strdup (inet_ntoa (sa->sin_addr)), FALSE);
      }
    }
  }

  close (sockfd);
  free (ifc.ifc_req);

  if (loopback)
    ips = add_ip_to_list (ips, loopback, TRUE);

  return ips;
}

#endif /* HAVE_GETIFADDRS */

gchar *
nice_interfaces_get_ip_for_interface (gchar *interface_name)
{
  struct ifreq ifr;
  union {
    struct sockaddr *addr;
    struct sockaddr_in *in;
  } sa;
  gint sockfd;

  g_return_val_if_fail (interface_name != NULL, NULL);

  ifr.ifr_addr.sa_family = AF_INET;
  memset (ifr.ifr_name, 0, sizeof (ifr.ifr_name));
  g_strlcpy (ifr.ifr_name, interface_name, sizeof (ifr.ifr_name));

  if ((sockfd = socket (AF_INET, SOCK_DGRAM, IPPROTO_IP)) < 0) {
    nice_debug ("Error : Cannot open socket to retreive interface list");
    return NULL;
  }

  if (ioctl (sockfd, SIOCGIFADDR, &ifr) < 0) {
    nice_debug ("Error : Unable to get IP information for interface %s",
      interface_name);
    close (sockfd);
    return NULL;
  }

  close (sockfd);
  sa.addr = &ifr.ifr_addr;
  nice_debug ("Address for %s: %s", interface_name, inet_ntoa (sa.in->sin_addr));
  return g_strdup (inet_ntoa (sa.in->sin_addr));
}

#else /* G_OS_UNIX */
#ifdef G_OS_WIN32

#include <winsock2.h>
#include <iphlpapi.h>

// Should be in Iphlpapi.h, but mingw doesn't seem to have these
// Values copied directly from:
// http://msdn.microsoft.com/en-us/library/aa366845(v=vs.85).aspx
// (Title: MIB_IPADDRROW structure)

#ifndef MIB_IPADDR_DISCONNECTED
#define MIB_IPADDR_DISCONNECTED 0x0008
#endif

#ifndef MIB_IPADDR_DELETED
#define MIB_IPADDR_DELETED 0x0040
#endif

#if 0
static gboolean started_wsa_engine = FALSE;

/*
 * private function that initializes the WinSock engine and
 *  returns a prebuilt socket
 */
SOCKET nice_interfaces_get_WSA_socket ()
{
  WORD wVersionRequested;
  WSADATA wsaData;
  int err;
  SOCKET sock;

  if (started_wsa_engine == FALSE) {
    wVersionRequested = MAKEWORD ( 2, 0 );

    err = WSAStartup ( wVersionRequested, &wsaData );
    if ( err != 0 ) {
      nice_debug ("Error : Could not start the winsocket engine");
      return INVALID_SOCKET;
    }
    started_wsa_engine = TRUE;
  }


  if ((sock = socket (AF_INET, SOCK_DGRAM, 0)) == INVALID_SOCKET) {
    nice_debug ("Error : Could not open socket to retreive interface list,"
        " error no : %d", WSAGetLastError ());
    return INVALID_SOCKET;
  }

  return sock;
}
#endif

GList * nice_interfaces_get_local_interfaces (void)
{
  ULONG size = 0;
  PMIB_IFTABLE if_table;
  GList * ret = NULL;

  GetIfTable(NULL, &size, TRUE);

  if (!size)
    return NULL;

  if_table = (PMIB_IFTABLE)g_malloc0(size);

  if (GetIfTable(if_table, &size, TRUE) == ERROR_SUCCESS) {
    DWORD i;
    for (i = 0; i < if_table->dwNumEntries; i++) {
      ret = g_list_prepend (ret, g_strdup ((gchar*)if_table->table[i].bDescr));
    }
  }

  g_free(if_table);

  return ret;
}

GList * nice_interfaces_get_local_ips (gboolean include_loopback)
{
  IP_ADAPTER_ADDRESSES *addresses = NULL, *a;
  ULONG status;
  guint iterations;
  ULONG addresses_size;
  DWORD pref = 0;
  GList *ret = NULL;

  /* As suggested on
   * http://msdn.microsoft.com/en-gb/library/windows/desktop/aa365915%28v=vs.85%29.aspx */
  #define MAX_TRIES 3
  #define INITIAL_BUFFER_SIZE 15000

  addresses_size = INITIAL_BUFFER_SIZE;
  iterations = 0;

  do {
    g_free (addresses);
    addresses = g_malloc0 (addresses_size);

    status = GetAdaptersAddresses (AF_UNSPEC,
        GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
        GAA_FLAG_SKIP_DNS_SERVER, NULL, addresses, &addresses_size);
  } while ((status == ERROR_BUFFER_OVERFLOW) && (iterations++ < MAX_TRIES));

  nice_debug ("Queried addresses with status %lu.", status);

  #undef INITIAL_BUFFER_SIZE
  #undef MAX_TRIES

  /* Error? */
  if (status != NO_ERROR) {
    nice_debug ("Error retrieving local addresses (error code %lu).", status);
    g_free (addresses);
    return NULL;
  }

  /*
   * Get the best interface for transport to 0.0.0.0.
   * This interface should be first in list!
   */
  if (GetBestInterface (0, &pref) != NO_ERROR)
    pref = 0;

  /* Loop over the adapters. */
  for (a = addresses; a != NULL; a = a->Next) {
    IP_ADAPTER_UNICAST_ADDRESS *unicast;

    nice_debug ("Interface ‘%S’:", a->FriendlyName);

    /* Various conditions for ignoring the interface. */
    if (a->Flags & IP_ADAPTER_RECEIVE_ONLY ||
        a->OperStatus == IfOperStatusDown ||
        a->OperStatus == IfOperStatusNotPresent ||
        a->OperStatus == IfOperStatusLowerLayerDown) {
      nice_debug ("Rejecting interface due to being down or read-only.");
      continue;
    }

    if (!include_loopback &&
        a->IfType == IF_TYPE_SOFTWARE_LOOPBACK) {
      nice_debug ("Rejecting loopback interface ‘%S’.", a->FriendlyName);
      continue;
    }

    /* Grab the interface’s unicast addresses. */
    for (unicast = a->FirstUnicastAddress;
         unicast != NULL; unicast = unicast->Next) {
      gchar *addr_string;

      addr_string = sockaddr_to_string (unicast->Address.lpSockaddr);
      if (addr_string == NULL) {
        nice_debug ("Failed to convert address to string for interface ‘%S’.",
            a->FriendlyName);
        continue;
      }

      nice_debug ("IP address: %s", addr_string);

      if (a->IfIndex == pref || a->Ipv6IfIndex == pref)
        ret = g_list_prepend (ret, addr_string);
      else
        ret = g_list_append (ret, addr_string);
    }
  }

  g_free (addresses);

  return ret;
}

/*
 * returns ip address as an utf8 string
 */
// Source for idx's type (Was IF_INDEX):
// http://msdn.microsoft.com/en-us/library/aa366836(v=VS.85).aspx
// (Title: MIB_IFROW structure)
static gchar *
win32_get_ip_for_interface (DWORD idx)
{
  ULONG size = 0;
  PMIB_IPADDRTABLE ip_table;
  gchar * ret = NULL;

  GetIpAddrTable (NULL, &size, TRUE);

  if (!size)
    return NULL;

  ip_table = (PMIB_IPADDRTABLE)g_malloc0 (size);

  if (GetIpAddrTable (ip_table, &size, TRUE) == ERROR_SUCCESS) {
    DWORD i;
    for (i = 0; i < ip_table->dwNumEntries; i++) {
      PMIB_IPADDRROW ipaddr = &ip_table->table[i];
      if (ipaddr->dwIndex == idx &&
          !(ipaddr->wType & (MIB_IPADDR_DISCONNECTED | MIB_IPADDR_DELETED))) {
        ret = g_strdup_printf ("%lu.%lu.%lu.%lu",
            (ipaddr->dwAddr      ) & 0xFF,
            (ipaddr->dwAddr >>  8) & 0xFF,
            (ipaddr->dwAddr >> 16) & 0xFF,
            (ipaddr->dwAddr >> 24) & 0xFF);
        break;
      }
    }
  }

  g_free (ip_table);
  return ret;
}

gchar * nice_interfaces_get_ip_for_interface (gchar *interface_name)
{
  ULONG size = 0;
  PMIB_IFTABLE if_table;
  gchar * ret = NULL;

  GetIfTable (NULL, &size, TRUE);

  if (!size)
    return NULL;

  if_table = (PMIB_IFTABLE)g_malloc0 (size);

  if (GetIfTable (if_table, &size, TRUE) == ERROR_SUCCESS) {
    DWORD i;
    gchar * tmp_str;
    for (i = 0; i < if_table->dwNumEntries; i++) {
      tmp_str = g_utf16_to_utf8 (
          if_table->table[i].wszName, MAX_INTERFACE_NAME_LEN,
          NULL, NULL, NULL);

      if (strlen (interface_name) == strlen (tmp_str) &&
          g_ascii_strncasecmp (interface_name, tmp_str, strlen (interface_name)) == 0) {
        ret = win32_get_ip_for_interface (if_table->table[i].dwIndex);
        g_free (tmp_str);
        break;
      }

      g_free (tmp_str);
    }
  }

  g_free (if_table);

  return ret;
}


#else /* G_OS_WIN32 */
#error Can not use this method for retreiving ip list from OS other than unix or windows
#endif /* G_OS_WIN32 */
#endif /* G_OS_UNIX */
