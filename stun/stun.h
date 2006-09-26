
#ifndef __STUN_H__
#define __STUN_H__

#include <glib.h>

typedef enum {
  STUN_MESSAGE_BINDING_REQUEST              = 0x001,
  STUN_MESSAGE_BINDING_RESPONSE             = 0x101,
  STUN_MESSAGE_BINDING_ERROR_RESPONSE       = 0x111,
  STUN_MESSAGE_SHARED_SECRET_REQUEST        = 0x002,
  STUN_MESSAGE_SHARED_SECRET_RESPONSE       = 0x102,
  STUN_MESSAGE_SHARED_SECRET_ERROR_RESPONSE = 0x112
} StunMessageType;

typedef enum {
  STUN_ATTRIBUTE_MAPPED_ADDRESS     = 0x1,
  STUN_ATTRIBUTE_RESPONSE_ADDRESS   = 0x2,
  STUN_ATTRIBUTE_CHANGE_REQUEST     = 0x3,
  STUN_ATTRIBUTE_CHANGED_ADDRESS    = 0x4,
  STUN_ATTRIBUTE_SOURCE_ADDRESS     = 0x5,
  STUN_ATTRIBUTE_USERNAME           = 0x6,
  STUN_ATTRIBUTE_PASSWORD           = 0x7,
  STUN_ATTRIBUTE_MESSAGE_INTEGRITY  = 0x8,
  STUN_ATTRIBUTE_ERROR_CODE         = 0x9,
  STUN_ATTRIBUTE_UNKNOWN_ATTRIBUTES = 0xa,
  STUN_ATTRIBUTE_REFLECTED_FROM     = 0xb
} StunAttributeType;

typedef struct _StunAttributeAddress StunAttributeAddress;

struct _StunAttributeAddress {
  guint8 padding;
  guint8 af;
  guint16 port;
  guint32 ip;
};

typedef struct _StunAttribute StunAttribute;

struct _StunAttribute {
  guint16 type;
  guint16 length;
  StunAttributeAddress address;
};

typedef struct _StunMessage StunMessage;

struct _StunMessage {
  guint16 type;
  gchar transaction_id[16];
  StunAttribute **attributes;
};

StunAttribute *
stun_attribute_mapped_address_new(guint32 ip_address, guint16 port);
void
stun_attribute_free(StunAttribute *attr);
guint
stun_attribute_pack(StunAttribute *attr, gchar **ret);
gchar *
stun_attribute_dump(StunAttribute *attr);
StunAttribute *
stun_attribute_unpack(guint length, const gchar *s);

StunMessage *
stun_message_binding_request_new();
void
stun_message_free(StunMessage *msg);
guint
stun_message_pack(StunMessage *msg, gchar **packed);
gchar *
stun_message_dump (StunMessage *msg);
StunMessage *
stun_message_unpack(guint length, gchar *s);

#endif /* __STUN_H__ */

