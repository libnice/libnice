
#include "stun.h"

#include <arpa/inet.h>
#include <string.h>

/* remove */
#include <stdio.h>

static StunAttribute *
stun_attribute_new (guint type)
{
  StunAttribute *attr = g_slice_alloc (sizeof (StunAttribute));

  attr->type = type;
  return attr;
}

StunAttribute *
stun_attribute_mapped_address_new (guint32 ip, guint16 port)
{
  StunAttribute *attr = stun_attribute_new (STUN_ATTRIBUTE_MAPPED_ADDRESS);

  attr->length = 8;
  attr->address.padding = 0;
  attr->address.af = 1;
  attr->address.ip = ip;
  attr->address.port = port;
  return attr;
}

void
stun_attribute_free (StunAttribute *attr)
{
  g_slice_free (StunAttribute, attr);
}

StunAttribute *
stun_attribute_unpack (guint length, const gchar *s)
{
  StunAttribute *attr;

  g_assert (length);
  attr = stun_attribute_new (ntohs (*(guint16 *)s));

  switch (attr->type)
    {
      case STUN_ATTRIBUTE_MAPPED_ADDRESS:
        attr->address.af = (guint8) s[5];
        g_assert (attr->address.af == 1);
        attr->address.port = ntohs (*(guint16 *)(s + 6));
        attr->address.ip = ntohl (*(guint32 *)(s + 8));
        break;
      default:
        break;
    }

  return attr;
}

guint
stun_attribute_pack (StunAttribute *attr, gchar **packed)
{
  switch (attr->type)
    {
      case STUN_ATTRIBUTE_MAPPED_ADDRESS:
        {
          StunAttribute *ret = g_malloc0 (sizeof (StunAttribute));

          ret->type = htons (attr->type);
          ret->length = htons (8);
          ret->address.af = attr->address.af;
          ret->address.port = htons (attr->address.port);
          ret->address.ip = htonl (attr->address.ip);
          *packed = (gchar *) ret;
          return 12;
        }
      default:
        return 0;
  }
}

gchar *
stun_attribute_dump (StunAttribute *attr)
{
  switch (attr->type)
    {
      case STUN_ATTRIBUTE_MAPPED_ADDRESS:
        return g_strdup_printf (
          "MAPPED-ADDRESS %d.%d.%d.%d:%d",
            (attr->address.ip & 0xff000000) >> 24,
            (attr->address.ip & 0x00ff0000) >> 16,
            (attr->address.ip & 0x0000ff00) >>  8,
            (attr->address.ip & 0x000000ff) >>  0,
            attr->address.port);
      default:
        return g_strdup_printf ("UNKNOWN (%d)", attr->type);
    }
}

void
stun_message_init (StunMessage *msg, guint type)
{
  msg->type = type;
}

StunMessage *
stun_message_new (guint type)
{
  StunMessage *msg = g_slice_alloc0 (sizeof (StunMessage));

  stun_message_init (msg, type);
  return msg;
}

StunMessage *
stun_message_binding_request_new ()
{
  return stun_message_new (STUN_MESSAGE_BINDING_REQUEST);
}

void
stun_message_free (StunMessage *msg)
{
  StunAttribute **attr;

  if (msg->attributes)
    {
      for (attr = msg->attributes; *attr; attr++)
        stun_attribute_free (*attr);

      g_free (msg->attributes);
    }

  g_slice_free (StunMessage, msg);
}

StunMessage *
stun_message_unpack (guint length, gchar *s)
{
  guint attr_length;
  guint n_attributes = 0;
  guint i;
  guint offset;
  StunAttribute *attr;
  StunMessage *msg = stun_message_new (STUN_MESSAGE_BINDING_REQUEST);

  /* message header is 20 bytes */

  g_assert (length >= 20);

  /* unpack the header */

  msg->type = ntohs (*(guint16 *)(s + 0));
  memcpy (msg->transaction_id, s + 4, 16);

  /* count the number of attributes */

  for (offset = 20; offset < length; offset += attr_length + 4)
    {
      attr_length = ntohs (*(guint16 *)(s + offset + 2));
      n_attributes++;
    }

  /* allocate memory for the attribute list and terminate it */

  msg->attributes = g_malloc0 ((n_attributes + 1) * sizeof (StunAttribute *));
  msg->attributes[n_attributes] = NULL;

  /* unpack attributes */

  for (i = 0, offset = 20; i < n_attributes; i++, offset += attr_length + 4)
    {
      attr_length = ntohs (*(guint16 *)(s + offset + 2));
      attr = msg->attributes[i] = stun_attribute_unpack (attr_length,
          s + offset);
    }

  return msg;
}

guint
stun_message_pack (StunMessage *msg, gchar **packed)
{
  GString *tmp = g_string_new ("");
  unsigned int packed_type;
  guint16 packed_length;
  guint length = 0;

  if (msg->attributes)
    {
      StunAttribute **attr;

      for (attr = msg->attributes; *attr; attr++)
        length += 4 + (*attr)->length;
    }

  packed_type = htons (msg->type);
  packed_length = htons (length);

  g_string_append_printf (tmp, "%c%c%c%c",
    ((gchar *) &packed_type)[0],
    ((gchar *) &packed_type)[1],
    ((gchar *) &packed_length)[0],
    ((gchar *) &packed_length)[1]);
  g_string_append_len (tmp, msg->transaction_id, 16);

  if (msg->attributes)
    {
      StunAttribute **attr;

      for (attr = msg->attributes; *attr; attr++)
        {
          gchar *attr_packed;
          guint attr_length = stun_attribute_pack (*attr, &attr_packed);
          g_string_append_len (tmp, attr_packed, attr_length);
          g_free (attr_packed);
        }
    }

  *packed = g_string_free (tmp, FALSE);
  return length + 20;
}

gchar *
stun_message_dump (StunMessage *msg)
{
  StunAttribute **attr;
  GString *tmp = g_string_new ("");
  const gchar *name;

  switch (msg->type) {
    case STUN_MESSAGE_BINDING_REQUEST:
      name = "BINDING-REQUEST";
      break;
    case STUN_MESSAGE_BINDING_RESPONSE:
      name = "BINDING-RESPONSE";
      break;
    default:
      return NULL;
  }

  g_string_printf (tmp,
    "%s %08x:%08x:%08x:%08x",
      name,
      *(guint32 *)(msg->transaction_id),
      *(guint32 *)(msg->transaction_id + 4),
      *(guint32 *)(msg->transaction_id + 8),
      *(guint32 *)(msg->transaction_id + 12));

  if (msg->attributes)
    for (attr = msg->attributes; *attr; attr++)
      {
          gchar *dump = stun_attribute_dump (*attr);
          g_string_append_printf (tmp, "\n  %s", dump);
          g_free (dump);
      }

  return g_string_free (tmp, FALSE);
}

