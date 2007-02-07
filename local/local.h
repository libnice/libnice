
#ifndef _LOCAL_H
#define _LOCAL_H

#include <glib.h>

#include "address.h"

G_BEGIN_DECLS

typedef struct _NiceInterface NiceInterface;

struct _NiceInterface
{
  gchar *name;
  NiceAddress addr;
};

NiceInterface *
nice_interface_new ();

void
nice_interface_free (NiceInterface *iface);

GSList *
nice_list_local_interfaces ();

G_END_DECLS

#endif /* _LOCAL_H */

