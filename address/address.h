
#ifndef _ADDRESS_H
#define _ADDRESS_H

#include <glib.h>

G_BEGIN_DECLS

typedef enum
{
  NICE_ADDRESS_TYPE_IPV4,
  NICE_ADDRESS_TYPE_IPV6,
} NiceAddressType;

typedef struct _NiceAddress NiceAddress;

/* XXX: need access to fields to convert to sockaddr_in */
struct _NiceAddress
{
  NiceAddressType type;
  union
  {
    guint32 addr_ipv4;
    guchar addr_ipv6[16];
  };
  guint16 port;
};

NiceAddress *
nice_address_new (void);

void
nice_address_free (NiceAddress *addr);

NiceAddress *
nice_address_dup (NiceAddress *a);

void
nice_address_set_ipv4 (NiceAddress *addr, guint32 addr_ipv4);

void
nice_address_set_ipv6 (NiceAddress *addr, const gchar *addr_ipv6);

G_GNUC_WARN_UNUSED_RESULT
gboolean
nice_address_set_ipv4_from_string (NiceAddress *addr, const gchar *str);

gboolean
nice_address_equal (NiceAddress *a, NiceAddress *b);

gchar *
nice_address_to_string (NiceAddress *addr);

gboolean
nice_address_is_private (NiceAddress *a);

G_END_DECLS

#endif /* _ADDRESS_H */

