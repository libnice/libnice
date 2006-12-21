
#ifndef _LOCAL_H
#define _LOCAL_H

typedef guint32 addr_ipv4;

typedef struct _interface interface;

struct _interface
{
  gchar *name;
  addr_ipv4 addr;
};

interface *
interface_new ();

void
interface_free (interface *iface);

GSList *
list_local_interfaces ();

#endif /* _LOCAL_H */

