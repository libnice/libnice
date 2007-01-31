
#ifndef _ADDRESS_H
#define _ADDRESS_H

G_BEGIN_DECLS

typedef enum _NiceAddressType NiceAddressType;

enum _NiceAddressType
{
  NICE_ADDRESS_TYPE_IPV4,
  NICE_ADDRESS_TYPE_IPV6,
};

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
};

NiceAddress *
nice_address_new (void);
void
nice_address_free (NiceAddress *addr);
NiceAddress *
nice_address_dup (NiceAddress *a);
void
nice_address_set_ipv4 (NiceAddress *addr, guint32 addr_ipv4);
gboolean
nice_address_set_ipv4_from_string (NiceAddress *addr, gchar *str);
gboolean
nice_address_equal (NiceAddress *a, NiceAddress *b);
gchar *
nice_address_to_string (NiceAddress *addr);

G_END_DECLS

#endif /* _ADDRESS_H */

