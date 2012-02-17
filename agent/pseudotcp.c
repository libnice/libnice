/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2010 Collabora Ltd.
 *  Contact: Youness Alaoui

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
 *   Youness Alaoui, Collabora Ltd.
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

/* Reproducing license from libjingle for copied code */

/*
 * libjingle
 * Copyright 2004--2005, Google Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  1. Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *  3. The name of the author may not be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
 * EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include <glib.h>

#ifndef G_OS_WIN32
#  include <arpa/inet.h>
#endif

#include "pseudotcp.h"

G_DEFINE_TYPE (PseudoTcpSocket, pseudo_tcp_socket, G_TYPE_OBJECT);


//////////////////////////////////////////////////////////////////////
// Network Constants
//////////////////////////////////////////////////////////////////////

// Standard MTUs
const guint16 PACKET_MAXIMUMS[] = {
  65535,    // Theoretical maximum, Hyperchannel
  32000,    // Nothing
  17914,    // 16Mb IBM Token Ring
  8166,   // IEEE 802.4
  //4464,   // IEEE 802.5 (4Mb max)
  4352,   // FDDI
  //2048,   // Wideband Network
  2002,   // IEEE 802.5 (4Mb recommended)
  //1536,   // Expermental Ethernet Networks
  //1500,   // Ethernet, Point-to-Point (default)
  1492,   // IEEE 802.3
  1006,   // SLIP, ARPANET
  //576,    // X.25 Networks
  //544,    // DEC IP Portal
  //512,    // NETBIOS
  508,    // IEEE 802/Source-Rt Bridge, ARCNET
  296,    // Point-to-Point (low delay)
  //68,     // Official minimum
  0,      // End of list marker
};

#define MAX_PACKET 65535
// Note: we removed lowest level because packet overhead was larger!
#define MIN_PACKET 296

// (+ up to 40 bytes of options?)
#define IP_HEADER_SIZE 20
#define ICMP_HEADER_SIZE 8
#define UDP_HEADER_SIZE 8
// TODO: Make JINGLE_HEADER_SIZE transparent to this code?
// when relay framing is in use
#define JINGLE_HEADER_SIZE 64

//////////////////////////////////////////////////////////////////////
// Global Constants and Functions
//////////////////////////////////////////////////////////////////////
//
//    0                   1                   2                   3
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  0 |                      Conversation Number                      |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  4 |                        Sequence Number                        |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  8 |                     Acknowledgment Number                     |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |               |   |U|A|P|R|S|F|                               |
// 12 |    Control    |   |R|C|S|S|Y|I|            Window             |
//    |               |   |G|K|H|T|N|N|                               |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 16 |                       Timestamp sending                       |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 20 |                      Timestamp receiving                      |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 24 |                             data                              |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//////////////////////////////////////////////////////////////////////

#define MAX_SEQ 0xFFFFFFFF
#define HEADER_SIZE 24

#define PACKET_OVERHEAD (HEADER_SIZE + UDP_HEADER_SIZE + \
      IP_HEADER_SIZE + JINGLE_HEADER_SIZE)

// MIN_RTO = 250 ms (RFC1122, Sec 4.2.3.1 "fractions of a second")
#define MIN_RTO      250
#define DEF_RTO     3000 /* 3 seconds (RFC1122, Sec 4.2.3.1) */
#define MAX_RTO    60000 /* 60 seconds */
#define ACK_DELAY    100 /* 100 milliseconds */

/*
#define FLAG_FIN 0x01
#define FLAG_SYN 0x02
#define FLAG_ACK 0x10
*/

#define FLAG_CTL 0x02
#define FLAG_RST 0x04

#define CTL_CONNECT  0
//#define CTL_REDIRECT  1
#define CTL_EXTRA 255


#define CTRL_BOUND 0x80000000

// If there are no pending clocks, wake up every 4 seconds
#define DEFAULT_TIMEOUT 4000
// If the connection is closed, once per minute
#define CLOSED_TIMEOUT (60 * 1000)

//////////////////////////////////////////////////////////////////////
// Helper Functions
//////////////////////////////////////////////////////////////////////
#ifndef G_OS_WIN32
#  define min(first, second) ((first) < (second) ? (first) : (second))
#  define max(first, second) ((first) > (second) ? (first) : (second))
#endif

static guint32
bound(guint32 lower, guint32 middle, guint32 upper)
{
   return min (max (lower, middle), upper);
}

static guint32
get_current_time(void)
{
  GTimeVal tv;
  g_get_current_time (&tv);
  return tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

static gboolean
time_is_between(guint32 later, guint32 middle, guint32 earlier)
{
  if (earlier <= later) {
    return ((earlier <= middle) && (middle <= later));
  } else {
    return !((later < middle) && (middle < earlier));
  }
}

static gint32
time_diff(guint32 later, guint32 earlier)
{
  guint32 LAST = 0xFFFFFFFF;
  guint32 HALF = 0x80000000;
  if (time_is_between(earlier + HALF, later, earlier)) {
    if (earlier <= later) {
      return (long)(later - earlier);
    } else {
      return (long)(later + (LAST - earlier) + 1);
    }
  } else {
    if (later <= earlier) {
      return -(long) (earlier - later);
    } else {
      return -(long)(earlier + (LAST - later) + 1);
    }
  }
}

//////////////////////////////////////////////////////////////////////
// PseudoTcp
//////////////////////////////////////////////////////////////////////

typedef enum {
  SD_NONE,
  SD_GRACEFUL,
  SD_FORCEFUL
} Shutdown;

typedef enum {
  sfNone,
  sfDelayedAck,
  sfImmediateAck
} SendFlags;

enum {
  // Note: can't go as high as 1024 * 64, because of uint16 precision
  kRcvBufSize = 1024 * 60,
  // Note: send buffer should be larger to make sure we can always fill the
  // receiver window
  kSndBufSize = 1024 * 90
};

typedef struct {
  guint32 conv, seq, ack;
  guint8 flags;
  guint16 wnd;
  const gchar * data;
  guint32 len;
  guint32 tsval, tsecr;
} Segment;

typedef struct {
  guint32 seq, len;
  guint8 xmit;
  gboolean bCtrl;
} SSegment;

typedef struct {
  guint32 seq, len;
} RSegment;


struct _PseudoTcpSocketPrivate {
  PseudoTcpCallbacks callbacks;

  Shutdown shutdown;
  gint error;

  // TCB data
  PseudoTcpState state;
  guint32 conv;
  gboolean bReadEnable, bWriteEnable, bOutgoing;
  guint32 last_traffic;

  // Incoming data
  GList *rlist;
  gchar rbuf[kRcvBufSize];
  guint32 rcv_nxt, rcv_wnd, rlen, lastrecv;

  // Outgoing data
  GList *slist;
  gchar sbuf[kSndBufSize];
  guint32 snd_nxt, snd_wnd, slen, lastsend, snd_una;
  // Maximum segment size, estimated protocol level, largest segment sent
  guint32 mss, msslevel, largest, mtu_advise;
  // Retransmit timer
  guint32 rto_base;

  // Timestamp tracking
  guint32 ts_recent, ts_lastack;

  // Round-trip calculation
  guint32 rx_rttvar, rx_srtt, rx_rto;

  // Congestion avoidance, Fast retransmit/recovery, Delayed ACKs
  guint32 ssthresh, cwnd;
  guint8 dup_acks;
  guint32 recover;
  guint32 t_ack;

};


/* properties */
enum
{
  PROP_CONVERSATION = 1,
  PROP_CALLBACKS,
  PROP_STATE,
  LAST_PROPERTY
};


static void pseudo_tcp_socket_get_property (GObject *object, guint property_id,
    GValue *value,  GParamSpec *pspec);
static void pseudo_tcp_socket_set_property (GObject *object, guint property_id,
    const GValue *value, GParamSpec *pspec);
static void pseudo_tcp_socket_finalize (GObject *object);


static guint32 queue(PseudoTcpSocket *self, const gchar * data,
    guint32 len, gboolean bCtrl);
static PseudoTcpWriteResult packet(PseudoTcpSocket *self, guint32 seq,
    guint8 flags, const gchar * data, guint32 len);
static gboolean parse(PseudoTcpSocket *self,
    const guint8 * buffer, guint32 size);
static gboolean process(PseudoTcpSocket *self, Segment *seg);
static gboolean transmit(PseudoTcpSocket *self, const GList *seg, guint32 now);
static void attempt_send(PseudoTcpSocket *self, SendFlags sflags);
static void closedown(PseudoTcpSocket *self, guint32 err);
static void adjustMTU(PseudoTcpSocket *self);


// The following logging is for detailed (packet-level) pseudotcp analysis only.
static PseudoTcpDebugLevel debug_level = PSEUDO_TCP_DEBUG_NONE;

#ifndef _MSC_VER
#define DEBUG(level, fmt, ...) \
  if (debug_level >= level) \
    g_debug ("PseudoTcpSocket %p: " fmt, self, ## __VA_ARGS__)
#else
/* HACK ALERT: To avoid Visual Studio compiler error due to the following bug
 * https://connect.microsoft.com/VisualStudio/feedback/details/604348/-va-args-support-has-an-error
 * we need to expand the g_debug macro and use g_log directly
 */
#define DEBUG(level, fmt, ...) \
  if (debug_level >= level) \
    g_log (G_LOG_DOMAIN, G_LOG_LEVEL_DEBUG, "PseudoTcpSocket %p: " fmt, \
        self, ## __VA_ARGS__)
#endif

void
pseudo_tcp_set_debug_level (PseudoTcpDebugLevel level)
{
  debug_level = level;
}

static void
pseudo_tcp_socket_class_init (PseudoTcpSocketClass *cls)
{
  GObjectClass *object_class = G_OBJECT_CLASS (cls);

  object_class->get_property = pseudo_tcp_socket_get_property;
  object_class->set_property = pseudo_tcp_socket_set_property;
  object_class->finalize = pseudo_tcp_socket_finalize;

  g_object_class_install_property (object_class, PROP_CONVERSATION,
      g_param_spec_uint ("conversation", "TCP Conversation ID",
          "The TCP Conversation ID",
          0, G_MAXUINT32, 0,
          G_PARAM_CONSTRUCT_ONLY | G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

  g_object_class_install_property (object_class, PROP_CALLBACKS,
      g_param_spec_pointer ("callbacks", "PseudoTcp socket callbacks",
          "Structure with the callbacks to call when PseudoTcp events happen",
          G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

  g_object_class_install_property (object_class, PROP_STATE,
      g_param_spec_uint ("state", "PseudoTcp State",
          "The current state (enum PseudoTcpState) of the PseudoTcp socket",
          TCP_LISTEN, TCP_CLOSED, TCP_LISTEN,
          G_PARAM_READABLE | G_PARAM_STATIC_STRINGS));

}


static void
pseudo_tcp_socket_get_property (GObject *object,
                                  guint property_id,
                                  GValue *value,
                                  GParamSpec *pspec)
{
  PseudoTcpSocket *self = PSEUDO_TCP_SOCKET (object);

  switch (property_id) {
    case PROP_CONVERSATION:
      g_value_set_uint (value, self->priv->conv);
      break;
    case PROP_CALLBACKS:
      g_value_set_pointer (value, (gpointer) &self->priv->callbacks);
      break;
    case PROP_STATE:
      g_value_set_uint (value, self->priv->state);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
      break;
  }
}

static void
pseudo_tcp_socket_set_property (GObject *object,
                                  guint property_id,
                                  const GValue *value,
                                  GParamSpec *pspec)
{
  PseudoTcpSocket *self = PSEUDO_TCP_SOCKET (object);

  switch (property_id) {
    case PROP_CONVERSATION:
      self->priv->conv = g_value_get_uint (value);
      break;
    case PROP_CALLBACKS:
      {
        PseudoTcpCallbacks *c = g_value_get_pointer (value);
        self->priv->callbacks = *c;
      }
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
      break;
  }
}

static void
pseudo_tcp_socket_finalize (GObject *object)
{
  PseudoTcpSocket *self = PSEUDO_TCP_SOCKET (object);
  PseudoTcpSocketPrivate *priv = self->priv;
  GList *i;

  if (priv == NULL)
    return;

  for (i = priv->slist; i; i = i->next) {
    SSegment *sseg = i->data;
    g_slice_free (SSegment, sseg);
  }
  for (i = priv->rlist; i; i = i->next) {
    RSegment *rseg = i->data;
    g_slice_free (RSegment, rseg);
  }
  g_list_free (priv->slist);
  priv->slist = NULL;
  g_list_free (priv->rlist);
  priv->rlist = NULL;

  g_free (priv);
  self->priv = NULL;

  if (G_OBJECT_CLASS (pseudo_tcp_socket_parent_class)->finalize)
    G_OBJECT_CLASS (pseudo_tcp_socket_parent_class)->finalize (object);
}


static void
pseudo_tcp_socket_init (PseudoTcpSocket *obj)
{
  /* Use g_new0, and do not use g_object_set_private because the size of
   * our private data is too big (150KB+) and the g_slice_allow cannot allocate
   * it. So we handle the private ourselves */
  PseudoTcpSocketPrivate *priv = g_new0 (PseudoTcpSocketPrivate, 1);
  guint32 now = get_current_time();

  obj->priv = priv;

  priv->shutdown = SD_NONE;
  priv->error = 0;

  priv->state = TCP_LISTEN;
  priv->conv = 0;
  priv->rcv_wnd = sizeof(priv->rbuf);
  priv->snd_nxt = priv->slen = 0;
  priv->snd_wnd = 1;
  priv->snd_una = priv->rcv_nxt = priv->rlen = 0;
  priv->bReadEnable = TRUE;
  priv->bWriteEnable = FALSE;
  priv->t_ack = 0;

  priv->msslevel = 0;
  priv->largest = 0;
  priv->mss = MIN_PACKET - PACKET_OVERHEAD;
  priv->mtu_advise = MAX_PACKET;

  priv->rto_base = 0;

  priv->cwnd = 2 * priv->mss;
  priv->ssthresh = sizeof(priv->rbuf);
  priv->lastrecv = priv->lastsend = priv->last_traffic = now;
  priv->bOutgoing = FALSE;

  priv->dup_acks = 0;
  priv->recover = 0;

  priv->ts_recent = priv->ts_lastack = 0;

  priv->rx_rto = DEF_RTO;
  priv->rx_srtt = priv->rx_rttvar = 0;
}

PseudoTcpSocket *pseudo_tcp_socket_new (guint32 conversation,
    PseudoTcpCallbacks *callbacks)
{

  return g_object_new (PSEUDO_TCP_SOCKET_TYPE,
      "conversation", conversation,
      "callbacks", callbacks,
      NULL);
}

gboolean
pseudo_tcp_socket_connect(PseudoTcpSocket *self)
{
  PseudoTcpSocketPrivate *priv = self->priv;
  gchar buffer[1];

  if (priv->state != TCP_LISTEN) {
    priv->error = EINVAL;
    return FALSE;
  }

  priv->state = TCP_SYN_SENT;
  DEBUG (PSEUDO_TCP_DEBUG_NORMAL, "State: TCP_SYN_SENT");

  buffer[0] = CTL_CONNECT;
  queue(self, buffer, 1, TRUE);
  attempt_send(self, sfNone);

  return TRUE;
}

void
pseudo_tcp_socket_notify_mtu(PseudoTcpSocket *self, guint16 mtu)
{
  PseudoTcpSocketPrivate *priv = self->priv;
  priv->mtu_advise = mtu;
  if (priv->state == TCP_ESTABLISHED) {
    adjustMTU(self);
  }
}

void
pseudo_tcp_socket_notify_clock(PseudoTcpSocket *self)
{
  PseudoTcpSocketPrivate *priv = self->priv;
  guint32 now = get_current_time ();

  if (priv->state == TCP_CLOSED)
    return;

  // Check if it's time to retransmit a segment
  if (priv->rto_base &&
      (time_diff(priv->rto_base + priv->rx_rto, now) <= 0)) {
    if (g_list_length (priv->slist) == 0) {
      g_assert_not_reached ();
    } else {
      // Note: (priv->slist.front().xmit == 0)) {
      // retransmit segments
      guint32 nInFlight;
      guint32 rto_limit;

      DEBUG (PSEUDO_TCP_DEBUG_NORMAL, "timeout retransmit (rto: %d) "
          "(rto_base: %d) (now: %d) (dup_acks: %d)",
          priv->rx_rto, priv->rto_base, now, (guint) priv->dup_acks);

      if (!transmit(self, priv->slist, now)) {
        closedown(self, ECONNABORTED);
        return;
      }

      nInFlight = priv->snd_nxt - priv->snd_una;
      priv->ssthresh = max(nInFlight / 2, 2 * priv->mss);
      //LOG(LS_INFO) << "priv->ssthresh: " << priv->ssthresh << "  nInFlight: " << nInFlight << "  priv->mss: " << priv->mss;
      priv->cwnd = priv->mss;

      // Back off retransmit timer.  Note: the limit is lower when connecting.
      rto_limit = (priv->state < TCP_ESTABLISHED) ? DEF_RTO : MAX_RTO;
      priv->rx_rto = min(rto_limit, priv->rx_rto * 2);
      priv->rto_base = now;
    }
  }

  // Check if it's time to probe closed windows
  if ((priv->snd_wnd == 0)
        && (time_diff(priv->lastsend + priv->rx_rto, now) <= 0)) {
    if (time_diff(now, priv->lastrecv) >= 15000) {
      closedown(self, ECONNABORTED);
      return;
    }

    // probe the window
    packet(self, priv->snd_nxt - 1, 0, 0, 0);
    priv->lastsend = now;

    // back off retransmit timer
    priv->rx_rto = min(MAX_RTO, priv->rx_rto * 2);
  }

  // Check if it's time to send delayed acks
  if (priv->t_ack && (time_diff(priv->t_ack + ACK_DELAY, now) <= 0)) {
    packet(self, priv->snd_nxt, 0, 0, 0);
  }

}

gboolean
pseudo_tcp_socket_notify_packet(PseudoTcpSocket *self,
    const gchar * buffer, guint32 len)
{
  if (len > MAX_PACKET) {
    //LOG_F(WARNING) << "packet too large";
    return FALSE;
  }
  return parse(self, (guint8 *) buffer, len);
}

gboolean
pseudo_tcp_socket_get_next_clock(PseudoTcpSocket *self, long *timeout)
{
  PseudoTcpSocketPrivate *priv = self->priv;
  guint32 now = get_current_time ();

  if (priv->shutdown == SD_FORCEFUL)
    return FALSE;

  if ((priv->shutdown == SD_GRACEFUL)
      && ((priv->state != TCP_ESTABLISHED)
          || ((priv->slen == 0) && (priv->t_ack == 0)))) {
    return FALSE;
  }

  if (priv->state == TCP_CLOSED) {
    *timeout = CLOSED_TIMEOUT;
    return TRUE;
  }

  *timeout = DEFAULT_TIMEOUT;

  if (priv->t_ack) {
    *timeout = min(*timeout, time_diff(priv->t_ack + ACK_DELAY, now));
  }
  if (priv->rto_base) {
    *timeout = min(*timeout, time_diff(priv->rto_base + priv->rx_rto, now));
  }
  if (priv->snd_wnd == 0) {
    *timeout = min(*timeout, time_diff(priv->lastsend + priv->rx_rto, now));
  }

  return TRUE;
}


gint
pseudo_tcp_socket_recv(PseudoTcpSocket *self, char * buffer, size_t len)
{
  PseudoTcpSocketPrivate *priv = self->priv;
  guint32 read;

  if (priv->state != TCP_ESTABLISHED) {
    priv->error = ENOTCONN;
    return -1;
  }

  if (priv->rlen == 0) {
    priv->bReadEnable = TRUE;
    priv->error = EWOULDBLOCK;
    return -1;
  }

  read = min((guint32) len, priv->rlen);
  memcpy(buffer, priv->rbuf, read);
  priv->rlen -= read;

  /* !?! until we create a circular buffer, we need to move all of the rest
     of the buffer up! */
  memmove(priv->rbuf, priv->rbuf + read, sizeof(priv->rbuf) - read);

  if ((sizeof(priv->rbuf) - priv->rlen - priv->rcv_wnd)
      >= min(sizeof(priv->rbuf) / 2, priv->mss)) {
    // !?! Not sure about this was closed business
    gboolean bWasClosed = (priv->rcv_wnd == 0);

    priv->rcv_wnd = sizeof(priv->rbuf) - priv->rlen;

    if (bWasClosed) {
      attempt_send(self, sfImmediateAck);
    }
  }

  return read;
}

gint
pseudo_tcp_socket_send(PseudoTcpSocket *self, const char * buffer, guint32 len)
{
  PseudoTcpSocketPrivate *priv = self->priv;
  gint written;

  if (priv->state != TCP_ESTABLISHED) {
    priv->error = ENOTCONN;
    return -1;
  }

  if (priv->slen == sizeof(priv->sbuf)) {
    priv->bWriteEnable = TRUE;
    priv->error = EWOULDBLOCK;
    return -1;
  }

  written = queue(self, buffer, len, FALSE);
  attempt_send(self, sfNone);

  if (written > 0 && (guint32)written < len) {
    priv->bWriteEnable = TRUE;
  }

  return written;
}

void
pseudo_tcp_socket_close(PseudoTcpSocket *self, gboolean force)
{
  PseudoTcpSocketPrivate *priv = self->priv;
  //nice_agent ("Closing socket %p : %d", sock, force?"true":"false");
  priv->shutdown = force ? SD_FORCEFUL : SD_GRACEFUL;
}

int
pseudo_tcp_socket_get_error(PseudoTcpSocket *self)
{
  PseudoTcpSocketPrivate *priv = self->priv;
  return priv->error;
}

//
// Internal Implementation
//

static guint32
queue(PseudoTcpSocket *self, const gchar * data, guint32 len, gboolean bCtrl)
{
  PseudoTcpSocketPrivate *priv = self->priv;

  if (len > sizeof(priv->sbuf) - priv->slen) {
    g_assert(!bCtrl);
    len = sizeof(priv->sbuf) - priv->slen;
  }

  // We can concatenate data if the last segment is the same type
  // (control v. regular data), and has not been transmitted yet
  if (g_list_length (priv->slist) > 0 &&
      (((SSegment *)g_list_last (priv->slist)->data)->bCtrl == bCtrl) &&
      (((SSegment *)g_list_last (priv->slist)->data)->xmit == 0)) {
    ((SSegment *)g_list_last (priv->slist)->data)->len += len;
  } else {
    SSegment *sseg = g_slice_new0 (SSegment);
    sseg->seq = priv->snd_una + priv->slen;
    sseg->len = len;
    sseg->bCtrl = bCtrl;
    priv->slist = g_list_append (priv->slist, sseg);
  }

  memcpy(priv->sbuf + priv->slen, data, len);
  priv->slen += len;
  //LOG(LS_INFO) << "PseudoTcp::queue - priv->slen = " << priv->slen;
  return len;
}

static PseudoTcpWriteResult
packet(PseudoTcpSocket *self, guint32 seq, guint8 flags,
    const gchar * data, guint32 len)
{
  PseudoTcpSocketPrivate *priv = self->priv;
  guint32 now = get_current_time();
  guint8 buffer[MAX_PACKET];
  PseudoTcpWriteResult wres = WR_SUCCESS;

  g_assert(HEADER_SIZE + len <= MAX_PACKET);

  *((guint32 *) buffer) = htonl(priv->conv);
  *((guint32 *) (buffer + 4)) = htonl(seq);
  *((guint32 *) (buffer + 8)) = htonl(priv->rcv_nxt);
  buffer[12] = 0;
  buffer[13] = flags;
  *((guint16 *) (buffer + 14)) = htons((guint16)priv->rcv_wnd);

  // Timestamp computations
  *((guint32 *) (buffer + 16)) = htonl(now);
  *((guint32 *) (buffer + 20)) = htonl(priv->ts_recent);
  priv->ts_lastack = priv->rcv_nxt;

  if (data != NULL)
    memcpy(buffer + HEADER_SIZE, data, len);

  DEBUG (PSEUDO_TCP_DEBUG_VERBOSE, "<-- <CONV=%d><FLG=%d><SEQ=%d:%d><ACK=%d>"
      "<WND=%d><TS=%d><TSR=%d><LEN=%d>",
      priv->conv, (unsigned)flags, seq, seq + len, priv->rcv_nxt, priv->rcv_wnd,
      now % 10000, priv->ts_recent % 10000, len);

  wres = priv->callbacks.WritePacket(self, (gchar *) buffer, len + HEADER_SIZE,
                                     priv->callbacks.user_data);
  /* Note: When data is NULL, this is an ACK packet.  We don't read the
     return value for those, and thus we won't retry.  So go ahead and treat
     the packet as a success (basically simulate as if it were dropped),
     which will prevent our timers from being messed up. */
  if ((wres != WR_SUCCESS) && (NULL != data))
    return wres;

  priv->t_ack = 0;
  if (len > 0) {
    priv->lastsend = now;
  }
  priv->last_traffic = now;
  priv->bOutgoing = TRUE;

  return WR_SUCCESS;
}

static gboolean
parse(PseudoTcpSocket *self, const guint8 * buffer, guint32 size)
{
  Segment seg;

  if (size < 12)
    return FALSE;

  seg.conv = ntohl(*(guint32 *)buffer);
  seg.seq = ntohl(*(guint32 *)(buffer + 4));
  seg.ack = ntohl(*(guint32 *)(buffer + 8));
  seg.flags = buffer[13];
  seg.wnd = ntohs(*(guint16 *)(buffer + 14));

  seg.tsval = ntohl(*(guint32 *)(buffer + 16));
  seg.tsecr = ntohl(*(guint32 *)(buffer + 20));

  seg.data = ((gchar *)buffer) + HEADER_SIZE;
  seg.len = size - HEADER_SIZE;

  DEBUG (PSEUDO_TCP_DEBUG_VERBOSE, "--> <CONV=%d><FLG=%d><SEQ=%d:%d><ACK=%d>"
      "<WND=%d><TS=%d><TSR=%d><LEN=%d>",
      seg.conv, (unsigned)seg.flags, seg.seq, seg.seq + seg.len, seg.ack,
      seg.wnd, seg.tsval % 10000, seg.tsecr % 10000, seg.len);

  return process(self, &seg);
}


static gboolean
process(PseudoTcpSocket *self, Segment *seg)
{
  PseudoTcpSocketPrivate *priv = self->priv;
  guint32 now;
  SendFlags sflags = sfNone;
  gboolean bIgnoreData;
  gboolean bNewData;
  gboolean bConnect = FALSE;

  /* If this is the wrong conversation, send a reset!?!
     (with the correct conversation?) */
  if (seg->conv != priv->conv) {
    //if ((seg->flags & FLAG_RST) == 0) {
    //  packet(sock, tcb, seg->ack, 0, FLAG_RST, 0, 0);
    //}
    DEBUG (PSEUDO_TCP_DEBUG_NORMAL, "wrong conversation");
    return FALSE;
  }

  now = get_current_time();
  priv->last_traffic = priv->lastrecv = now;
  priv->bOutgoing = FALSE;

  if (priv->state == TCP_CLOSED) {
    // !?! send reset?
    DEBUG (PSEUDO_TCP_DEBUG_NORMAL, "closed");
    return FALSE;
  }

  // Check if this is a reset segment
  if (seg->flags & FLAG_RST) {
    closedown(self, ECONNRESET);
    return FALSE;
  }

  // Check for control data
  bConnect = FALSE;
  if (seg->flags & FLAG_CTL) {
    if (seg->len == 0) {
      DEBUG (PSEUDO_TCP_DEBUG_NORMAL, "Missing control code");
      return FALSE;
    } else if (seg->data[0] == CTL_CONNECT) {
      bConnect = TRUE;
      if (priv->state == TCP_LISTEN) {
        char buffer[1];
        priv->state = TCP_SYN_RECEIVED;
        buffer[0] = CTL_CONNECT;
        queue(self, buffer, 1, TRUE);
      } else if (priv->state == TCP_SYN_SENT) {
        priv->state = TCP_ESTABLISHED;
        DEBUG (PSEUDO_TCP_DEBUG_NORMAL, "State: TCP_ESTABLISHED");
        adjustMTU(self);
        if (priv->callbacks.PseudoTcpOpened)
          priv->callbacks.PseudoTcpOpened(self, priv->callbacks.user_data);

      }
    } else {
      DEBUG (PSEUDO_TCP_DEBUG_NORMAL, "Unknown control code: %d", seg->data[0]);
      return FALSE;
    }
  }

  // Update timestamp
  if ((seg->seq <= priv->ts_lastack) &&
      (priv->ts_lastack < seg->seq + seg->len)) {
    priv->ts_recent = seg->tsval;
  }

  // Check if this is a valuable ack
  if ((seg->ack > priv->snd_una) && (seg->ack <= priv->snd_nxt)) {
    guint32 nAcked;
    guint32 nFree;
    guint32 kIdealRefillSize;

    // Calculate round-trip time
    if (seg->tsecr) {
      long rtt = time_diff(now, seg->tsecr);
      if (rtt >= 0) {
        if (priv->rx_srtt == 0) {
          priv->rx_srtt = rtt;
          priv->rx_rttvar = rtt / 2;
        } else {
          priv->rx_rttvar = (3 * priv->rx_rttvar +
              abs((long)(rtt - priv->rx_srtt))) / 4;
          priv->rx_srtt = (7 * priv->rx_srtt + rtt) / 8;
        }
        priv->rx_rto = bound(MIN_RTO,
            priv->rx_srtt + max(1LU, 4 * priv->rx_rttvar), MAX_RTO);

        DEBUG (PSEUDO_TCP_DEBUG_VERBOSE, "rtt: %ld   srtt: %d  rto: %d",
                rtt, priv->rx_srtt, priv->rx_rto);
      } else {
        g_assert_not_reached ();
      }
    }

    priv->snd_wnd = seg->wnd;

    nAcked = seg->ack - priv->snd_una;
    priv->snd_una = seg->ack;

    priv->rto_base = (priv->snd_una == priv->snd_nxt) ? 0 : now;

    priv->slen -= nAcked;
    memmove(priv->sbuf, priv->sbuf + nAcked, priv->slen);
    //LOG(LS_INFO) << "PseudoTcp::process - priv->slen = " << priv->slen;

    for (nFree = nAcked; nFree > 0; ) {
      SSegment *data;

      g_assert(priv->slist != NULL);
      data = (SSegment *) (priv->slist->data);

      if (nFree < data->len) {
        data->len -= nFree;
        nFree = 0;
      } else {
        if (data->len > priv->largest) {
          priv->largest = data->len;
        }
        nFree -= data->len;
        g_slice_free (SSegment, priv->slist->data);
        priv->slist = g_list_delete_link (priv->slist, priv->slist);
      }
    }

    if (priv->dup_acks >= 3) {
      if (priv->snd_una >= priv->recover) { // NewReno
        guint32 nInFlight = priv->snd_nxt - priv->snd_una;
        // (Fast Retransmit)
        priv->cwnd = min(priv->ssthresh, nInFlight + priv->mss);
        DEBUG (PSEUDO_TCP_DEBUG_NORMAL, "exit recovery");
        priv->dup_acks = 0;
      } else {
        DEBUG (PSEUDO_TCP_DEBUG_NORMAL, "recovery retransmit");
        if (!transmit(self, priv->slist, now)) {
          closedown(self, ECONNABORTED);
          return FALSE;
        }
        priv->cwnd += priv->mss - min(nAcked, priv->cwnd);
      }
    } else {
      priv->dup_acks = 0;
      // Slow start, congestion avoidance
      if (priv->cwnd < priv->ssthresh) {
        priv->cwnd += priv->mss;
      } else {
        priv->cwnd += max(1LU, priv->mss * priv->mss / priv->cwnd);
      }
    }

    // !?! A bit hacky
    if ((priv->state == TCP_SYN_RECEIVED) && !bConnect) {
      priv->state = TCP_ESTABLISHED;
      DEBUG (PSEUDO_TCP_DEBUG_NORMAL, "State: TCP_ESTABLISHED");
      adjustMTU(self);
      if (priv->callbacks.PseudoTcpOpened)
        priv->callbacks.PseudoTcpOpened(self, priv->callbacks.user_data);
    }

    // If we make room in the send queue, notify the user
    // The goal it to make sure we always have at least enough data to fill the
    // window.  We'd like to notify the app when we are halfway to that point.
    kIdealRefillSize = (sizeof(priv->sbuf) + sizeof(priv->rbuf)) / 2;
    if (priv->bWriteEnable && (priv->slen < kIdealRefillSize)) {
      priv->bWriteEnable = FALSE;
      if (priv->callbacks.PseudoTcpWritable)
        priv->callbacks.PseudoTcpWritable(self, priv->callbacks.user_data);
    }
  } else if (seg->ack == priv->snd_una) {
    /* !?! Note, tcp says don't do this... but otherwise how does a
       closed window become open? */
    priv->snd_wnd = seg->wnd;

    // Check duplicate acks
    if (seg->len > 0) {
      // it's a dup ack, but with a data payload, so don't modify priv->dup_acks
    } else if (priv->snd_una != priv->snd_nxt) {
      guint32 nInFlight;

      priv->dup_acks += 1;
      if (priv->dup_acks == 3) { // (Fast Retransmit)
        DEBUG (PSEUDO_TCP_DEBUG_NORMAL, "enter recovery");
        DEBUG (PSEUDO_TCP_DEBUG_NORMAL, "recovery retransmit");
        if (!transmit(self, priv->slist, now)) {
          closedown(self, ECONNABORTED);
          return FALSE;
        }
        priv->recover = priv->snd_nxt;
        nInFlight = priv->snd_nxt - priv->snd_una;
        priv->ssthresh = max(nInFlight / 2, 2 * priv->mss);
        //LOG(LS_INFO) << "priv->ssthresh: " << priv->ssthresh << "  nInFlight: " << nInFlight << "  priv->mss: " << priv->mss;
        priv->cwnd = priv->ssthresh + 3 * priv->mss;
      } else if (priv->dup_acks > 3) {
        priv->cwnd += priv->mss;
      }
    } else {
      priv->dup_acks = 0;
    }
  }

  /* Conditions where acks must be sent:
   * 1) Segment is too old (they missed an ACK) (immediately)
   * 2) Segment is too new (we missed a segment) (immediately)
   * 3) Segment has data (so we need to ACK!) (delayed)
   * ... so the only time we don't need to ACK, is an empty segment
   * that points to rcv_nxt!
   */

  if (seg->seq != priv->rcv_nxt) {
    sflags = sfImmediateAck; // (Fast Recovery)
  } else if (seg->len != 0) {
    sflags = sfDelayedAck;
  }
  if (sflags == sfImmediateAck) {
    if (seg->seq > priv->rcv_nxt) {
      DEBUG (PSEUDO_TCP_DEBUG_NORMAL, "too new");
    } else if (seg->seq + seg->len <= priv->rcv_nxt) {
      DEBUG (PSEUDO_TCP_DEBUG_NORMAL, "too old");
    }
  }

  // Adjust the incoming segment to fit our receive buffer
  if (seg->seq < priv->rcv_nxt) {
    guint32 nAdjust = priv->rcv_nxt - seg->seq;
    if (nAdjust < seg->len) {
      seg->seq += nAdjust;
      seg->data += nAdjust;
      seg->len -= nAdjust;
    } else {
      seg->len = 0;
    }
  }
  if ((seg->seq + seg->len - priv->rcv_nxt) >
      (sizeof(priv->rbuf) - priv->rlen)) {
    guint32 nAdjust = seg->seq + seg->len - priv->rcv_nxt -
        (sizeof(priv->rbuf) - priv->rlen);
    if (nAdjust < seg->len) {
      seg->len -= nAdjust;
    } else {
      seg->len = 0;
    }
  }

  bIgnoreData = (seg->flags & FLAG_CTL) || (priv->shutdown != SD_NONE);
  bNewData = FALSE;

  if (seg->len > 0) {
    if (bIgnoreData) {
      if (seg->seq == priv->rcv_nxt) {
        priv->rcv_nxt += seg->len;
      }
    } else {
      guint32 nOffset = seg->seq - priv->rcv_nxt;
      memcpy(priv->rbuf + priv->rlen + nOffset, seg->data, seg->len);
      if (seg->seq == priv->rcv_nxt) {
        GList *iter = NULL;

        priv->rlen += seg->len;
        priv->rcv_nxt += seg->len;
        priv->rcv_wnd -= seg->len;
        bNewData = TRUE;

        iter = priv->rlist;
        while (iter && (((RSegment *)iter->data)->seq <= priv->rcv_nxt)) {
          RSegment *data = (RSegment *)(iter->data);
          if (data->seq + data->len > priv->rcv_nxt) {
            guint32 nAdjust = (data->seq + data->len) - priv->rcv_nxt;
            sflags = sfImmediateAck; // (Fast Recovery)
            DEBUG (PSEUDO_TCP_DEBUG_NORMAL, "Recovered %d bytes (%d -> %d)",
                nAdjust, priv->rcv_nxt, priv->rcv_nxt + nAdjust);
            priv->rlen += nAdjust;
            priv->rcv_nxt += nAdjust;
            priv->rcv_wnd -= nAdjust;
          }
          g_slice_free (RSegment, priv->rlist->data);
          priv->rlist = g_list_delete_link (priv->rlist, priv->rlist);
          iter = priv->rlist;
        }
      } else {
        GList *iter = NULL;
        RSegment *rseg = g_slice_new0 (RSegment);

        DEBUG (PSEUDO_TCP_DEBUG_NORMAL, "Saving %d bytes (%d -> %d)",
            seg->len, seg->seq, seg->seq + seg->len);
        rseg->seq = seg->seq;
        rseg->len = seg->len;
        iter = priv->rlist;
        while (iter && (((RSegment*)iter->data)->seq < rseg->seq)) {
          iter = g_list_next (iter);
        }
        priv->rlist = g_list_insert_before(priv->rlist, iter, rseg);
      }
    }
  }

  attempt_send(self, sflags);

  // If we have new data, notify the user
  if (bNewData && priv->bReadEnable) {
    priv->bReadEnable = FALSE;
    if (priv->callbacks.PseudoTcpReadable)
      priv->callbacks.PseudoTcpReadable(self, priv->callbacks.user_data);
  }

  return TRUE;
}

static gboolean
transmit(PseudoTcpSocket *self, const GList *seg, guint32 now)
{
  PseudoTcpSocketPrivate *priv = self->priv;
  SSegment *segment = (SSegment*)(seg->data);
  guint32 nTransmit = min(segment->len, priv->mss);

  if (segment->xmit >= ((priv->state == TCP_ESTABLISHED) ? 15 : 30)) {
    DEBUG (PSEUDO_TCP_DEBUG_NORMAL, "too many retransmits");
    return FALSE;
  }

  while (TRUE) {
    guint32 seq = segment->seq;
    guint8 flags = (segment->bCtrl ? FLAG_CTL : 0);
    const gchar * buffer = priv->sbuf + (segment->seq - priv->snd_una);
    PseudoTcpWriteResult wres = packet(self, seq, flags, buffer, nTransmit);

    if (wres == WR_SUCCESS)
      break;

    if (wres == WR_FAIL) {
      DEBUG (PSEUDO_TCP_DEBUG_NORMAL, "packet failed");
      return FALSE;
    }

    g_assert(wres == WR_TOO_LARGE);

    while (TRUE) {
      if (PACKET_MAXIMUMS[priv->msslevel + 1] == 0) {
        DEBUG (PSEUDO_TCP_DEBUG_NORMAL, "MTU too small");
        return FALSE;
      }
      /* !?! We need to break up all outstanding and pending packets
         and then retransmit!?! */

      priv->mss = PACKET_MAXIMUMS[++priv->msslevel] - PACKET_OVERHEAD;
      // I added this... haven't researched actual formula
      priv->cwnd = 2 * priv->mss;

      if (priv->mss < nTransmit) {
        nTransmit = priv->mss;
        break;
      }
    }
    DEBUG (PSEUDO_TCP_DEBUG_NORMAL, "Adjusting mss to %d bytes ", priv->mss);
  }

  if (nTransmit < segment->len) {
    SSegment *subseg = g_slice_new0 (SSegment);
    subseg->seq = segment->seq + nTransmit;
    subseg->len = segment->len - nTransmit;
    subseg->bCtrl = segment->bCtrl;
    subseg->xmit = segment->xmit;

    DEBUG (PSEUDO_TCP_DEBUG_NORMAL, "mss reduced to %d", priv->mss);

    segment->len = nTransmit;
    priv->slist = g_list_insert_before(priv->slist, seg->next, subseg);
  }

  if (segment->xmit == 0) {
    priv->snd_nxt += segment->len;
  }
  segment->xmit += 1;

  if (priv->rto_base == 0) {
    priv->rto_base = now;
  }

  return TRUE;
}

static void
attempt_send(PseudoTcpSocket *self, SendFlags sflags)
{
  PseudoTcpSocketPrivate *priv = self->priv;
  guint32 now = get_current_time();
  gboolean bFirst = TRUE;

  if (time_diff(now, priv->lastsend) > (long) priv->rx_rto) {
    priv->cwnd = priv->mss;
  }


  while (TRUE) {
    guint32 cwnd;
    guint32 nWindow;
    guint32 nInFlight;
    guint32 nUseable;
    guint32 nAvailable;
    GList *iter;

    cwnd = priv->cwnd;
    if ((priv->dup_acks == 1) || (priv->dup_acks == 2)) { // Limited Transmit
      cwnd += priv->dup_acks * priv->mss;
    }
    nWindow = min(priv->snd_wnd, cwnd);
    nInFlight = priv->snd_nxt - priv->snd_una;
    nUseable = (nInFlight < nWindow) ? (nWindow - nInFlight) : 0;
    nAvailable = min(priv->slen - nInFlight, priv->mss);

    if (nAvailable > nUseable) {
      if (nUseable * 4 < nWindow) {
        // RFC 813 - avoid SWS
        nAvailable = 0;
      } else {
        nAvailable = nUseable;
      }
    }

    if (bFirst) {
      bFirst = FALSE;
      DEBUG (PSEUDO_TCP_DEBUG_VERBOSE, "[cwnd: %d  nWindow: %d  nInFlight: %d "
          "nAvailable: %d nQueued: %d  nEmpty: %" G_GSIZE_FORMAT
          "  ssthresh: %d]",
          priv->cwnd, nWindow, nInFlight, nAvailable, priv->slen - nInFlight,
          sizeof(priv->sbuf) - priv->slen, priv->ssthresh);
    }

    if (nAvailable == 0) {
      if (sflags == sfNone)
        return;

      // If this is an immediate ack, or the second delayed ack
      if ((sflags == sfImmediateAck) || priv->t_ack) {
        packet(self, priv->snd_nxt, 0, 0, 0);
      } else {
        priv->t_ack = get_current_time();
      }
      return;
    }

    // Nagle algorithm
    if ((priv->snd_nxt > priv->snd_una) && (nAvailable < priv->mss))  {
      return;
    }

    // Find the next segment to transmit
    iter = priv->slist;
    while (((SSegment*)iter->data)->xmit > 0) {
      iter = g_list_next (iter);
      g_assert(iter);
    }

    // If the segment is too large, break it into two
    if (((SSegment*)iter->data)->len > nAvailable) {
      SSegment *subseg = g_slice_new0 (SSegment);
      subseg->seq = ((SSegment*)iter->data)->seq + nAvailable;
      subseg->len = ((SSegment*)iter->data)->len - nAvailable;
      subseg->bCtrl = ((SSegment*)iter->data)->bCtrl;

      ((SSegment*)iter->data)->len = nAvailable;
      priv->slist = g_list_insert_before(priv->slist, iter->next, subseg);
    }

    if (!transmit(self, iter, now)) {
      DEBUG (PSEUDO_TCP_DEBUG_NORMAL, "transmit failed");
      // TODO: consider closing socket
      return;
    }

    sflags = sfNone;
  }
}

static void
closedown(PseudoTcpSocket *self, guint32 err)
{
  PseudoTcpSocketPrivate *priv = self->priv;
  priv->slen = 0;

  DEBUG (PSEUDO_TCP_DEBUG_NORMAL, "State: TCP_CLOSED");
  priv->state = TCP_CLOSED;
  if (priv->callbacks.PseudoTcpClosed)
    priv->callbacks.PseudoTcpClosed(self, err, priv->callbacks.user_data);
}

static void
adjustMTU(PseudoTcpSocket *self)
{
  PseudoTcpSocketPrivate *priv = self->priv;

  // Determine our current mss level, so that we can adjust appropriately later
  for (priv->msslevel = 0;
       PACKET_MAXIMUMS[priv->msslevel + 1] > 0;
       ++priv->msslevel) {
    if (((guint16)PACKET_MAXIMUMS[priv->msslevel]) <= priv->mtu_advise) {
      break;
    }
  }
  priv->mss = priv->mtu_advise - PACKET_OVERHEAD;
  // !?! Should we reset priv->largest here?
  DEBUG (PSEUDO_TCP_DEBUG_NORMAL, "Adjusting mss to %d bytes", priv->mss);
  // Enforce minimums on ssthresh and cwnd
  priv->ssthresh = max(priv->ssthresh, 2 * priv->mss);
  priv->cwnd = max(priv->cwnd, priv->mss);
}
