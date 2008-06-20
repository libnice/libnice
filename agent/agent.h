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
 *   Kai Vehmanen, Nokia
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

#ifndef _AGENT_H
#define _AGENT_H

#include <glib-object.h>

#include "udp.h"
#include "address.h"
#include "candidate.h"
#include "random.h"


G_BEGIN_DECLS

#define NICE_TYPE_AGENT nice_agent_get_type()

#define NICE_AGENT(obj) \
  (G_TYPE_CHECK_INSTANCE_CAST ((obj), \
  NICE_TYPE_AGENT, NiceAgent))

#define NICE_AGENT_CLASS(klass) \
  (G_TYPE_CHECK_CLASS_CAST ((klass), \
  NICE_TYPE_AGENT, NiceAgentClass))

#define NICE_IS_AGENT(obj) \
  (G_TYPE_CHECK_INSTANCE_TYPE ((obj), \
  NICE_TYPE_AGENT))

#define NICE_IS_AGENT_CLASS(klass) \
  (G_TYPE_CHECK_CLASS_TYPE ((klass), \
  NICE_TYPE_AGENT))

#define NICE_AGENT_GET_CLASS(obj) \
  (G_TYPE_INSTANCE_GET_CLASS ((obj), \
  NICE_TYPE_AGENT, NiceAgentClass))

/** 
 * A hard limit for number for remote candidates. This
 * limit is enforced to protect against malevolent remote 
 * clients.
 */
#define NICE_AGENT_MAX_REMOTE_CANDIDATES    25

typedef enum
{
  NICE_COMPONENT_STATE_DISCONNECTED, /* no activity scheduled */
  NICE_COMPONENT_STATE_GATHERING,    /* gathering local candidates */
  NICE_COMPONENT_STATE_CONNECTING,   /* establishing connectivity */
  NICE_COMPONENT_STATE_CONNECTED,    /* at least one working candidate pair */
  NICE_COMPONENT_STATE_READY,        /* ICE concluded, candidate pair
					selection is now final */
  NICE_COMPONENT_STATE_FAILED,       /* connectivity checks have been completed,
					but connectivity was not established */
  NICE_COMPONENT_STATE_LAST
} NiceComponentState;

typedef enum
{
  NICE_COMPONENT_TYPE_RTP = 1,
  NICE_COMPONENT_TYPE_RTCP = 2
} NiceComponentType;

typedef enum
{
  NICE_COMPATIBILITY_ID19 = 0,
  NICE_COMPATIBILITY_GOOGLE,
  NICE_COMPATIBILITY_MSN,
  NICE_COMPATIBILITY_LAST = NICE_COMPATIBILITY_MSN
} NiceCompatibility;

typedef struct _NiceAgent NiceAgent;

typedef void (*NiceAgentRecvFunc) (
  NiceAgent *agent, guint stream_id, guint component_id, guint len,
  gchar *buf, gpointer user_data);


typedef struct _NiceAgentClass NiceAgentClass;

struct _NiceAgentClass
{
  GObjectClass parent_class;
};


GType nice_agent_get_type (void);

NiceAgent *
nice_agent_new (NiceUDPSocketFactory *factory,
    GMainContext *ctx, NiceCompatibility compat);

gboolean
nice_agent_add_local_address (NiceAgent *agent, NiceAddress *addr);

guint
nice_agent_add_stream (
  NiceAgent *agent,
  guint n_components);

void
nice_agent_remove_stream (
  NiceAgent *agent,
  guint stream_id);

void
nice_agent_gather_candidates (
  NiceAgent *agent,
  guint stream_id);

gboolean
nice_agent_set_remote_credentials (
  NiceAgent *agent,
  guint stream_id,
  const gchar *ufrag, const gchar *pwd);

gboolean
nice_agent_get_local_credentials (
  NiceAgent *agent,
  guint stream_id,
  const gchar **ufrag, const gchar **pwd);

gboolean
nice_agent_add_remote_candidate (
  NiceAgent *agent,
  guint stream_id,
  guint component_id,
  NiceCandidateType type,
  NiceAddress *addr,
  const gchar *username,
  const gchar *password);

int
nice_agent_set_remote_candidates (
  NiceAgent *agent,
  guint stream_id,
  guint component_id,
  const GSList *candidates);

guint
nice_agent_recv (
  NiceAgent *agent,
  guint stream_id,
  guint component_id,
  guint buf_len,
  gchar *buf);

guint
nice_agent_recv_sock (
  NiceAgent *agent,
  guint stream_id,
  guint component_id,
  guint sock,
  guint buf_len,
  gchar *buf);

GSList *
nice_agent_poll_read (
  NiceAgent *agent,
  GSList *other_fds,
  NiceAgentRecvFunc func,
  gpointer data);

gint
nice_agent_send (
  NiceAgent *agent,
  guint stream_id,
  guint component_id,
  guint len,
  const gchar *buf);

GSList *
nice_agent_get_local_candidates (
  NiceAgent *agent,
  guint stream_id,
  guint component_id);

GSList *
nice_agent_get_remote_candidates (
  NiceAgent *agent,
  guint stream_id,
  guint component_id);

gboolean 
nice_agent_restart (
  NiceAgent *agent);

gboolean
nice_agent_attach_recv (
  NiceAgent *agent,
  guint stream_id,
  guint component_id,
  GMainContext *ctx,
  NiceAgentRecvFunc func,
  gpointer data);

gboolean 
nice_agent_set_selected_pair (
  NiceAgent *agent,
  guint stream_id,
  guint component_id,
  const gchar *lfoundation,
  const gchar *rfoundation);

G_END_DECLS

#endif /* _AGENT_H */

