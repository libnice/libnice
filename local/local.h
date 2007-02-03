
#ifndef _LOCAL_H
#define _LOCAL_H

#include <glib.h>

G_BEGIN_DECLS

typedef guint32 addr_ipv4;

typedef struct _NiceInterface NiceInterface;

struct _NiceInterface
{
  gchar *name;
  addr_ipv4 addr;
};

NiceInterface *
nice_interface_new ();

void
nice_interface_free (NiceInterface *iface);

GSList *
nice_list_local_interfaces ();

G_END_DECLS

#endif /* _LOCAL_H */

