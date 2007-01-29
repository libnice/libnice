
#ifndef _LOCAL_H
#define _LOCAL_H

#include <glib.h>

G_BEGIN_DECLS

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

G_END_DECLS

#endif /* _LOCAL_H */

