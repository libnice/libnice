
#include "local.h"

int
main (void)
{
  GSList *i;
  GSList *interfaces;

  interfaces = nice_list_local_interfaces ();

  for (i = interfaces; i; i = i->next)
    {
      NiceInterface *iface = i->data;
      gchar *addr;

      addr = nice_address_to_string (&iface->addr);
      g_print ("%s: %s\n", iface->name, addr);
      g_free (addr);
      nice_interface_free (iface);
    }

  g_slist_free (interfaces);
  return 0;
}

