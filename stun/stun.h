/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2006, 2007 Collabora Ltd.
 *  Contact: Dafydd Harries
 * (C) 2006, 2007 Nokia Corporation. All rights reserved.
 *  Contact: Kai Vehmanen
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is the Nice GLib ICE library.
 *
 * The Initial Developers of the Original Code are Collabora Ltd and Nokia
 * Corporation. All Rights Reserved.
 *
 * Contributors:
 *   Dafydd Harries, Collabora Ltd.
 *
 * Alternatively, the contents of this file may be used under the terms of the
 * the GNU Lesser General Public License Version 2.1 (the "LGPL"), in which
 * case the provisions of LGPL are applicable instead of those above. If you
 * wish to allow use of your version of this file only under the terms of the
 * LGPL and not to allow others to use your version of this file under the
 * MPL, indicate your decision by deleting the provisions above and replace
 * them with the notice and other provisions required by the LGPL. If you do
 * not delete the provisions above, a recipient may use your version of this
 * file under either the MPL or the LGPL.
 */

#ifndef __STUN_H__
#define __STUN_H__

#include <glib.h>

G_BEGIN_DECLS

typedef enum
{
  STUN_MESSAGE_BINDING_REQUEST              = 0x001,
  STUN_MESSAGE_BINDING_RESPONSE             = 0x101,
  STUN_MESSAGE_BINDING_ERROR_RESPONSE       = 0x111,
  STUN_MESSAGE_SHARED_SECRET_REQUEST        = 0x002,
  STUN_MESSAGE_SHARED_SECRET_RESPONSE       = 0x102,
  STUN_MESSAGE_SHARED_SECRET_ERROR_RESPONSE = 0x112
} StunMessageType;

/* a = defined by RFC 3489
 * b = defined by RFC 3489bis
 * c = defined by draft-ietf-behave-turn-02
 */

typedef enum
{
  // mandatory parameters (<= 0x7fff)
  STUN_ATTRIBUTE_MAPPED_ADDRESS       = 0x0001, // ab
  STUN_ATTRIBUTE_RESPONSE_ADDRESS     = 0x0002, // a
  STUN_ATTRIBUTE_CHANGE_REQUEST       = 0x0003, // a
  STUN_ATTRIBUTE_CHANGED_ADDRESS      = 0x0004, // a
  STUN_ATTRIBUTE_SOURCE_ADDRESS       = 0x0005, // a
  STUN_ATTRIBUTE_USERNAME             = 0x0006, // ab
  STUN_ATTRIBUTE_PASSWORD             = 0x0007, // ab
  STUN_ATTRIBUTE_MESSAGE_INTEGRITY    = 0x0008, // ab
  STUN_ATTRIBUTE_ERROR_CODE           = 0x0009, // ab
  STUN_ATTRIBUTE_UNKNOWN_ATTRIBUTES   = 0x000a, // ab
  STUN_ATTRIBUTE_REFLECTED_FROM       = 0x000b, // a
  STUN_ATTRIBUTE_REALM                = 0x0014, //  b
  STUN_ATTRIBUTE_NONCE                = 0x0015, //  b
  STUN_ATTRIBUTE_LIFETIME             = 0x000D, //   c
  STUN_ATTRIBUTE_BANDWIDTH            = 0x0010, //   c
  STUN_ATTRIBUTE_REMOTE_ADDRESS       = 0x0012, //   c
  STUN_ATTRIBUTE_DATA                 = 0x0013, //   c
  STUN_ATTRIBUTE_RELAY_ADDRESS        = 0x0016, //   c
  STUN_ATTRIBUTE_REQUESTED_PORT_PROPS = 0x0018, //   c
  STUN_ATTRIBUTE_REQUESTED_TRANSPORT  = 0x0019, //   c
  STUN_ATTRIBUTE_REQUESTED_IP         = 0x0022, //   c
  STUN_ATTRIBUTE_TIMER_VAL            = 0x0021, //   c
  // optional parameters (> 0x7fff)
  STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS   = 0x8020, //  b
  STUN_ATTRIBUTE_FINGERPRINT          = 0x8023, //  b
  STUN_ATTRIBUTE_SERVER               = 0x8022, //  b
  SUTN_ATTRIBUTE_ALTERNATE_SERVER     = 0x8023, //  b
  STUN_ATTRIBUTE_REFRESH_INTERVAL     = 0x8024, //  b
} StunAttributeType;

typedef struct _StunAttribute StunAttribute;

struct _StunAttribute {
  guint16 type;
  guint16 length;
  union {
    struct {
      guint8 padding;
      guint8 af;
      guint16 port;
      guint32 ip;
    } address;
    gchar username[128];
    gchar password[128];
  };
};

typedef struct _StunMessage StunMessage;

struct _StunMessage {
  guint16 type;
  gchar transaction_id[16];
  StunAttribute **attributes;
};

G_GNUC_WARN_UNUSED_RESULT
StunAttribute *
stun_attribute_mapped_address_new (guint32 ip_address, guint16 port);

StunAttribute *
stun_attribute_username_new (const gchar *username);

void
stun_attribute_free (StunAttribute *attr);

G_GNUC_WARN_UNUSED_RESULT
guint
stun_attribute_pack (StunAttribute *attr, gchar **ret);

G_GNUC_WARN_UNUSED_RESULT
gchar *
stun_attribute_dump (StunAttribute *attr);

G_GNUC_WARN_UNUSED_RESULT
StunAttribute *
stun_attribute_unpack (guint length, const gchar *s);

void
stun_message_init (StunMessage *msg, guint type, const gchar *id);

G_GNUC_WARN_UNUSED_RESULT
StunMessage *
stun_message_new (guint type, const gchar *id, guint n_attributes);

void
stun_message_free (StunMessage *msg);
G_GNUC_WARN_UNUSED_RESULT

guint
stun_message_pack (StunMessage *msg, gchar **packed);
G_GNUC_WARN_UNUSED_RESULT

gchar *
stun_message_dump (StunMessage *msg);
G_GNUC_WARN_UNUSED_RESULT

StunMessage *
stun_message_unpack (guint length, const gchar *s);

StunAttribute *
stun_message_find_attribute (StunMessage *msg, StunAttributeType type);

G_END_DECLS

#endif /* __STUN_H__ */

