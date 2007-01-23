
#ifndef _ADDRESS_H
#define _ADDRESS_H

typedef enum address_type AddressType;

enum address_type
{
  ADDRESS_TYPE_IPV4,
  ADDRESS_TYPE_IPV6,
};

typedef struct _address Address;

/* XXX: need access to fields to convert to sockaddr_in */
struct _address
{
  AddressType type;
  union
  {
    guint32 addr_ipv4;
    guchar addr_ipv6[16];
  };
};

Address *
address_new (void);
void
address_free (Address *addr);
Address *
address_dup (Address *a);
void
address_set_ipv4 (Address *addr, guint32 addr_ipv4);
gboolean
address_set_ipv4_from_string (Address *addr, gchar *str);
gboolean
address_equal (Address *a, Address *b);
gchar *
address_to_string (Address *addr);

#endif /* _ADDRESS_H */

