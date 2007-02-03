
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

      g_print ("%s: %d.%d.%d.%d\n",
          iface->name,
          (iface->addr & 0xff000000) >> 24,
          (iface->addr & 0x00ff0000) >> 16,
          (iface->addr & 0x0000ff00) >>  8,
          (iface->addr & 0x000000ff));
      nice_interface_free (iface);
    }

  g_slist_free (interfaces);
  return 0;
}

