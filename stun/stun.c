
#include <string.h>

#include <arpa/inet.h>

#include "stun.h"

/* round up to multiple of 4 */
G_GNUC_CONST
static guint
ceil4 (guint n)
{
  if (n % 4 == 0)
    return n;
  else
    return n + 4 - (n % 4);
}

G_GNUC_WARN_UNUSED_RESULT
static StunAttribute *
stun_attribute_new (guint type)
{
  StunAttribute *attr = g_slice_new0 (StunAttribute);

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

StunAttribute *
stun_attribute_username_new (const gchar *username)
{
  StunAttribute *attr;

  attr = stun_attribute_new (STUN_ATTRIBUTE_USERNAME);
  g_assert (strlen (username) < sizeof (attr->username));
  attr->length = strlen (username);
  strcpy (attr->username, username);
  return attr;
}

void
stun_attribute_free (StunAttribute *attr)
{
  g_slice_free (StunAttribute, attr);
}

G_GNUC_WARN_UNUSED_RESULT
static gboolean
_stun_attribute_unpack (StunAttribute *attr, guint length, const gchar *s)
{
  guint type;

  if (length < 4)
    /* must start with 16 bit type, 16 bit length */
    return FALSE;

  type = ntohs (*(guint16 *) s);

  switch (type)
    {
      case STUN_ATTRIBUTE_MAPPED_ADDRESS:
        if (length != 12)
          return FALSE;

        attr->address.af = (guint8) s[5];
        g_assert (attr->address.af == 1);
        attr->address.port = ntohs (*(guint16 *)(s + 6));
        attr->address.ip = ntohl (*(guint32 *)(s + 8));
        break;

      case STUN_ATTRIBUTE_USERNAME:
      case STUN_ATTRIBUTE_PASSWORD:
        if (length - 4 > sizeof (attr->username) / sizeof (gchar))
          return FALSE;

        attr->length = length - 4;

        if (type == STUN_ATTRIBUTE_USERNAME)
          memcpy (attr->username, s + 4, attr->length);
        else
          memcpy (attr->password, s + 4, attr->length);
        break;

      default:
        /* unknown attribute; we can only unpack the type */
        break;
    }

  attr->type = type;
  return TRUE;
}

StunAttribute *
stun_attribute_unpack (guint length, const gchar *s)
{
  StunAttribute *attr;

  attr = stun_attribute_new (0);

  if (_stun_attribute_unpack (attr, length, s))
    return attr;

  stun_attribute_free (attr);
  return NULL;
}

guint
stun_attribute_pack (StunAttribute *attr, gchar **packed)
{
  switch (attr->type)
    {
      case STUN_ATTRIBUTE_MAPPED_ADDRESS:
        {
          if (packed != NULL)
            {
              StunAttribute *ret = g_malloc0 (sizeof (StunAttribute));

              ret->type = htons (attr->type);
              ret->length = htons (8);
              ret->address.af = attr->address.af;
              ret->address.port = htons (attr->address.port);
              ret->address.ip = htonl (attr->address.ip);
              *packed = (gchar *) ret;
            }

          return 12;
        }

      case STUN_ATTRIBUTE_USERNAME:
        {
          if (packed != NULL)
            {
              StunAttribute *ret = g_malloc0 (sizeof (StunAttribute));

              ret->type = htons (attr->type);
              ret->length = htons (attr->length);
              memcpy (ret->username, attr->username, attr->length);
              *packed = (gchar *) ret;
            }

          return ceil4 (4 + attr->length);
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
      case STUN_ATTRIBUTE_USERNAME:
        return g_strdup_printf (
          "USERNAME \"%*s\"", attr->length, attr->username);
      default:
        return g_strdup_printf ("UNKNOWN (%d)", attr->type);
    }
}

void
stun_message_init (StunMessage *msg, guint type, const gchar *id)
{
  msg->type = type;

  if (id != NULL)
    memcpy (msg->transaction_id, id, 16);
}

StunMessage *
stun_message_new (guint type, const gchar *id, guint n_attributes)
{
  StunMessage *msg = g_slice_new0 (StunMessage);

  stun_message_init (msg, type, id);

  if (n_attributes != 0)
    msg->attributes = g_malloc0 (
        (n_attributes + 1) * sizeof (StunAttribute *));

  return msg;
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
stun_message_unpack (guint length, const gchar *s)
{
  guint attr_length;
  guint n_attributes = 0;
  guint i;
  guint offset;
  StunAttribute *attr;
  StunMessage *msg;

  /* message header is 20 bytes */

  if (length < 20)
    return NULL;

  /* count the number of attributes */

  for (offset = 20; offset < length; offset += attr_length)
    {
      attr_length = ceil4 (4 + ntohs (*(guint16 *)(s + offset + 2)));
      n_attributes++;
    }

  /* create message structure */

  msg = stun_message_new (ntohs (*(guint16 *) s), s + 4, n_attributes);

  /* unpack attributes */

  for (i = 0, offset = 20; i < n_attributes; i++, offset += attr_length)
    {
      attr_length = 4 + ntohs (*(guint16 *)(s + offset + 2));
      attr = msg->attributes[i] = stun_attribute_unpack (attr_length,
          s + offset);
      attr_length = ceil4 (attr_length);
    }

  return msg;
}

guint
stun_message_pack (StunMessage *msg, gchar **packed)
{
  gchar *tmp;
  guint length = 0;

  if (msg->attributes)
    {
      StunAttribute **attr;

      for (attr = msg->attributes; *attr; attr++)
        length += stun_attribute_pack (*attr, NULL);
    }

  g_assert (length % 4 == 0);
  tmp = g_malloc0 (length + 20);
  *(guint16 *) (tmp + 0) = htons (msg->type);
  *(guint16 *) (tmp + 2) = htons (length);
  memcpy (tmp + 4, msg->transaction_id, 16);

  if (msg->attributes)
    {
      StunAttribute **attr;
      gchar *pos = tmp + 20;

      for (attr = msg->attributes; *attr; attr++)
        {
          gchar *attr_packed;
          guint attr_length = stun_attribute_pack (*attr, &attr_packed);
          memcpy (pos, attr_packed, attr_length);
          g_free (attr_packed);
          pos += attr_length;
        }
    }

  *packed = tmp;
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
    case STUN_MESSAGE_BINDING_ERROR_RESPONSE:
      name = "BINDING-ERROR-RESPONSE";
      break;
    default:
      name = "(UNKNOWN)";
  }

  g_string_printf (tmp,
    "%s %08x:%08x:%08x:%08x\n",
      name,
      ntohl (*(guint32 *)(msg->transaction_id)),
      ntohl (*(guint32 *)(msg->transaction_id + 4)),
      ntohl (*(guint32 *)(msg->transaction_id + 8)),
      ntohl (*(guint32 *)(msg->transaction_id + 12)));

  if (msg->attributes)
    for (attr = msg->attributes; *attr; attr++)
      {
          gchar *dump = stun_attribute_dump (*attr);
          g_string_append_printf (tmp, "  %s\n", dump);
          g_free (dump);
      }

  return g_string_free (tmp, FALSE);
}

