/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2006, 2007 Collabora Ltd.
 *  Contact: Dafydd Harries
 * (C) 2006, 2007 Nokia Corporation. All rights reserved.
 *  Contact: Kai Vehmanen
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

#include <string.h>

#include <glib.h>

#include <arpa/inet.h>
#include <ifaddrs.h>

#include "local.h"

NICEAPI_EXPORT NiceInterface *
nice_interface_new ()
{
  NiceInterface *iface;
  NiceAddress *addr = nice_address_new ();
  if (addr == NULL)
    return NULL;

  iface = g_slice_new0 (NiceInterface);
  if (iface == NULL)
  {
    nice_address_free (addr);
    return NULL;
  }

  iface->addr = addr;
  return iface;
}

NICEAPI_EXPORT void
nice_interface_free (NiceInterface *iface)
{
  if (iface->addr != NULL)
    nice_address_free (iface->addr);
  g_slice_free (NiceInterface, iface);
}

NICEAPI_EXPORT GSList *
nice_list_local_interfaces ()
{
  GSList *ret = NULL;
  struct ifaddrs *ifs;
  struct ifaddrs *i;

  getifaddrs (&ifs);

  for (i = ifs; i; i = i->ifa_next)
    {
      const struct sockaddr *addr;

      addr = (struct sockaddr *) i->ifa_addr;
      if (addr == NULL)
          continue; /* interface with no address */

      if (addr->sa_family == AF_INET || addr->sa_family == AF_INET6)
        {
          NiceInterface *iface;

          iface = nice_interface_new ();
          strncpy (iface->name, i->ifa_name, sizeof (iface->name));
          iface->name[sizeof (iface->name) - 1] = '\0';
          nice_address_set_from_sockaddr (iface->addr, addr);
          ret = g_slist_append (ret, iface);
        }
    }

  freeifaddrs (ifs);
  return ret;
}

