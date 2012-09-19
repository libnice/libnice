/*
 * This file is part of the Nice GLib ICE library.
 *
 * Unit test for ICE in dribble mode (adding remote candidates while gathering
 * local candidates).
 *
 * (C) 2012 Collabora Ltd.
 *  Contact: Rohan Garg
 *           Youness Alaoui
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
 * Corporation.
 *
 * Contributors:
 *   Rohan Garg
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

#include <glib.h>
#include <glib-object.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>

#include "stunagent.h"
#include "agent-priv.h"
#include "agent.h"

#define IPPORT_STUN 3456
#define USE_UPNP 0
#define LEFT_AGENT GINT_TO_POINTER(1)
#define RIGHT_AGENT GINT_TO_POINTER(2)

#if !GLIB_CHECK_VERSION(2,31,8)
  static GMutex *stun_mutex_ptr = NULL;
  static GCond *stun_signal_ptr = NULL;
  static GMutex *stun_thread_mutex_ptr = NULL;
  static GCond *stun_thread_signal_ptr = NULL
#else
  static GMutex stun_mutex;
  static GMutex *stun_mutex_ptr = &stun_mutex;
  static GCond stun_signal;
  static GCond *stun_signal_ptr = &stun_signal;
  static GMutex stun_thread_mutex;
  static GMutex *stun_thread_mutex_ptr = &stun_thread_mutex;
  static GCond stun_thread_signal;
  static GCond *stun_thread_signal_ptr = &stun_thread_signal;
#endif

static GMainLoop *global_mainloop;
static NiceComponentState global_lagent_state = NICE_COMPONENT_STATE_LAST;
static NiceComponentState global_ragent_state = NICE_COMPONENT_STATE_LAST;
static gboolean exit_stun_thread = FALSE;
static gboolean lagent_candidate_gathering_done = FALSE;
static gboolean ragent_candidate_gathering_done = FALSE;
static guint global_ls_id, global_rs_id;
static gboolean data_received = FALSE;
static gboolean drop_stun_packets = FALSE;

static const uint16_t known_attributes[] =  {
  0
};

/*
 * Creates a listening socket
 */
static int listen_socket (unsigned int port)
{
  struct sockaddr_in addr;
  int fd = socket (AF_INET, SOCK_DGRAM, IPPROTO_UDP);

  if (fd == -1) {
    perror ("Error opening IP port");
    return -1;
  }

  memset (&addr, 0, sizeof (addr));
  addr.sin_family = AF_INET;
  inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
  addr.sin_port = htons(port);

  if (bind (fd, (struct sockaddr *)&addr, sizeof (struct sockaddr_in))) {
    perror ("Error opening IP port");
    goto error;
  }

  return fd;

error:
  close (fd);
  return -1;
}

static int dgram_process (int sock, StunAgent *oldagent, StunAgent *newagent)
{
  struct sockaddr_storage addr;
  socklen_t addr_len;
  uint8_t buf[STUN_MAX_MESSAGE_SIZE];
  size_t buf_len = 0;
  size_t len = 0;
  StunMessage request;
  StunMessage response;
  StunValidationStatus validation;
  StunAgent *agent = NULL;
  gint ret;

  addr_len = sizeof (struct sockaddr_in);

recv_packet:
  len = recvfrom (sock, buf, sizeof(buf), 0,
      (struct sockaddr *)&addr, &addr_len);

  if (drop_stun_packets) {
    g_debug ("Dropping STUN packet as requested");
    return -1;
  }

  if (len == (size_t)-1) {
    return -1;
  }

  validation = stun_agent_validate (newagent, &request, buf, len, NULL, 0);

  if (validation == STUN_VALIDATION_SUCCESS) {
    agent = newagent;
  } else {
    validation = stun_agent_validate (oldagent, &request, buf, len, NULL, 0);
    agent = oldagent;
  }

  /* Unknown attributes */
  if (validation == STUN_VALIDATION_UNKNOWN_REQUEST_ATTRIBUTE) {
    buf_len = stun_agent_build_unknown_attributes_error (agent, &response, buf,
        sizeof (buf), &request);
    goto send_buf;
  }

  /* Mal-formatted packets */
  if (validation != STUN_VALIDATION_SUCCESS ||
      stun_message_get_class (&request) != STUN_REQUEST) {
    goto recv_packet;
  }

  switch (stun_message_get_method (&request)) {
    case STUN_BINDING:
      stun_agent_init_response (agent, &response, buf, sizeof (buf), &request);
      if (stun_message_has_cookie (&request))
        stun_message_append_xor_addr (&response,
            STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS,
            (struct sockaddr *)&addr, addr_len);
      else
         stun_message_append_addr (&response, STUN_ATTRIBUTE_MAPPED_ADDRESS,
             (struct sockaddr *)&addr, addr_len);
      break;

    default:
      if (!stun_agent_init_error (agent, &response, buf, sizeof (buf),
              &request, STUN_ERROR_BAD_REQUEST)) {
        g_debug ("STUN error message not initialized properly");
        g_assert_not_reached();
      }
  }

  buf_len = stun_agent_finish_message (agent, &response, NULL, 0);

send_buf:
  g_main_loop_quit (global_mainloop);
  g_debug ("Ready to send a STUN response");
  g_assert (g_mutex_trylock (stun_mutex_ptr));
  while (global_lagent_state < NICE_COMPONENT_STATE_CONNECTING) {
    g_debug ("Waiting for signal. State is %d", global_lagent_state);
    g_cond_wait (stun_signal_ptr, stun_mutex_ptr);
  }
  g_mutex_unlock (stun_mutex_ptr);
  len = sendto (sock, buf, buf_len, 0,
      (struct sockaddr *)&addr, addr_len);
  g_debug ("STUN response sent");
  drop_stun_packets = TRUE;
  ret = (len < buf_len) ? -1 : 0;
  return ret;
}


static gpointer stun_thread_func (const gpointer user_data)
{
  StunAgent oldagent;
  StunAgent newagent;
  int sock;
  int exit_code = -1;

  sock = listen_socket (IPPORT_STUN);

  if (sock == -1) {
    g_assert_not_reached ();
  }

  g_mutex_lock (stun_thread_mutex_ptr);
  g_cond_signal (stun_thread_signal_ptr);
  g_mutex_unlock (stun_thread_mutex_ptr);

  stun_agent_init (&oldagent, known_attributes,
      STUN_COMPATIBILITY_RFC3489, 0);
  stun_agent_init (&newagent, known_attributes,
      STUN_COMPATIBILITY_RFC5389, STUN_AGENT_USAGE_USE_FINGERPRINT);

  while (!exit_stun_thread) {
    g_debug ("Ready to process next datagram");
    dgram_process (sock, &oldagent, &newagent);
  }

  exit_code = close (sock);
  g_thread_exit (GINT_TO_POINTER (exit_code));
  return NULL;
}

static void set_credentials (NiceAgent *lagent, guint lstream,
    NiceAgent *ragent, guint rstream)
{
  gchar *ufrag = NULL, *password = NULL;

  nice_agent_get_local_credentials (lagent, lstream, &ufrag, &password);
  nice_agent_set_remote_credentials (ragent, rstream, ufrag, password);

  g_free (ufrag);
  g_free (password);

  nice_agent_get_local_credentials (ragent, rstream, &ufrag, &password);
  nice_agent_set_remote_credentials (lagent, lstream, ufrag, password);

  g_free (ufrag);
  g_free (password);
}

static void cb_candidate_gathering_done(NiceAgent *agent, guint stream_id, gpointer data)
{
  g_debug ("test-dribblemode:%s: %p", G_STRFUNC, data);

  if (GPOINTER_TO_UINT(data) == 1) {
    g_debug ("lagent finished gathering candidates");
    lagent_candidate_gathering_done = TRUE;
  } else if (GPOINTER_TO_UINT(data) == 2) {
    g_debug ("ragent finished gathering candidates");
    ragent_candidate_gathering_done = TRUE;
  }
  g_main_loop_quit(global_mainloop);
}

static void cb_nice_recv (NiceAgent *agent, guint stream_id, guint component_id, guint len, gchar *buf, gpointer user_data)
{
  gint ret;

  g_debug ("test-dribblemode:%s: %p", G_STRFUNC, user_data);

  ret = strncmp ("0000", buf, 4);
  if (ret == 0) {
    ret = strncmp ("00001234567812345678", buf, 16);
    g_assert (ret == 0);

    g_debug ("test-dribblemode:%s: ragent recieved %d bytes : quit mainloop",
             G_STRFUNC, len);
    data_received = TRUE;
    g_main_loop_quit (global_mainloop);
  }
}

static void cb_component_state_changed (NiceAgent *agent, guint stream_id, guint component_id, guint state, gpointer data)
{
  gint ret;

  g_debug ("test-dribblemode:%s: %p", G_STRFUNC, data);

  if(GPOINTER_TO_UINT(data) == 1) {
    global_lagent_state = state;
    g_debug ("lagent state is %d", state);
  } else if (GPOINTER_TO_UINT(data) == 2) {
    g_debug ("ragent state is %d", state);
    global_ragent_state = state;
  }

  if (GPOINTER_TO_UINT(data) == 1 && state == NICE_COMPONENT_STATE_FAILED) {
    g_debug ("Signalling STUN response since connchecks failed");
    g_mutex_lock (stun_mutex_ptr);
    g_cond_signal (stun_signal_ptr);
    g_mutex_unlock (stun_mutex_ptr);
    g_main_loop_quit (global_mainloop);
  }

  if(GPOINTER_TO_UINT(data) == 1 && state == NICE_COMPONENT_STATE_READY) {
    /* note: test payload send and receive */
    ret = nice_agent_send (agent, stream_id, component_id,
                           20, "00001234567812345678");
    g_debug ("Sent %d bytes", ret);
    g_assert (ret == 20);
  }
}

static void swap_candidates(NiceAgent *local, guint local_id, NiceAgent *remote, guint remote_id, gboolean signal_stun_reply)
{
  GSList *cands = NULL;

  g_debug ("test-dribblemode:%s", G_STRFUNC);
  cands = nice_agent_get_local_candidates(local, local_id,
                                          NICE_COMPONENT_TYPE_RTP);
  g_assert(nice_agent_set_remote_candidates(remote, remote_id,
                                            NICE_COMPONENT_TYPE_RTP, cands));

  if (signal_stun_reply) {
    g_mutex_lock (stun_mutex_ptr);
    g_cond_signal (stun_signal_ptr);
    g_mutex_unlock (stun_mutex_ptr);
  }

  g_slist_free_full (cands, (GDestroyNotify) nice_candidate_free);
}

static void cb_agent_new_candidate(NiceAgent *agent, guint stream_id, guint component_id, gchar *foundation, gpointer user_data)
{
  NiceAgent *other = g_object_get_data (G_OBJECT (agent), "other-agent");
  GSList *cands = nice_agent_get_local_candidates (agent, stream_id,
                                                   component_id);
  GSList *i = NULL;
  GSList *remote_cands = NULL;
  NiceCandidate* temp;
  gpointer tmp;
  guint id;

  g_debug ("test-dribblemode:%s: %p", G_STRFUNC, user_data);

  tmp = g_object_get_data (G_OBJECT (other), "id");
  id = GPOINTER_TO_UINT (tmp);

  for (i = cands; i; i = i->next) {
    temp = (NiceCandidate*) i->data;
    if (g_strcmp0(temp->foundation, foundation) == 0) {
      g_debug ("Adding new local candidate to other agent's connchecks");
      remote_cands = g_slist_prepend (remote_cands, nice_candidate_copy(temp));
      g_assert (nice_agent_set_remote_candidates (other, id,
                                                  NICE_COMPONENT_TYPE_RTP,
                                                  remote_cands));
    }
  }

  g_slist_free_full (remote_cands, (GDestroyNotify) nice_candidate_free);
  g_slist_free_full (cands, (GDestroyNotify) nice_candidate_free);

}

static void add_bad_candidate (NiceAgent *agent, guint stream_id, NiceCandidate *cand)
{
  NiceAddress bad_addr;
  GSList *cand_list = NULL;

  g_assert (nice_address_set_from_string (&bad_addr, "172.1.0.1"));

  cand = nice_candidate_new (NICE_CANDIDATE_TYPE_HOST);
  cand->stream_id = stream_id;
  cand->component_id = NICE_COMPONENT_TYPE_RTP;
  cand->addr = bad_addr;

  nice_agent_get_local_credentials (agent, stream_id,
                                    &cand->username, &cand->password);
  cand_list = g_slist_prepend (cand_list, cand);

  g_debug ("Adding buggy candidate to the agent %p", agent);
  g_assert (nice_agent_set_remote_candidates (agent, stream_id,
                                    NICE_COMPONENT_TYPE_RTP,
                                    cand_list));

  g_slist_free_full (cand_list, (GDestroyNotify) nice_candidate_free);

}

static void init_test(NiceAgent *lagent, NiceAgent *ragent, gboolean connect_new_candidate_signal)
{
  global_lagent_state = NICE_COMPONENT_STATE_DISCONNECTED;
  global_ragent_state = NICE_COMPONENT_STATE_DISCONNECTED;

  lagent_candidate_gathering_done = FALSE;
  ragent_candidate_gathering_done = FALSE;

  global_ls_id = nice_agent_add_stream (lagent, 1);
  global_rs_id = nice_agent_add_stream (ragent, 1);

  g_assert (global_ls_id > 0);
  g_assert (global_rs_id > 0);

  g_debug ("lagent stream is : %d and ragent stream is %d",
           global_ls_id,
           global_rs_id);

  g_object_set_data (G_OBJECT (lagent), "id", GUINT_TO_POINTER (global_ls_id));
  g_object_set_data (G_OBJECT (ragent), "id", GUINT_TO_POINTER (global_rs_id));

  if (connect_new_candidate_signal) {
    g_signal_connect (G_OBJECT(lagent), "new-candidate",
                      G_CALLBACK(cb_agent_new_candidate), LEFT_AGENT);
    g_signal_connect (G_OBJECT(ragent), "new-candidate",
                      G_CALLBACK(cb_agent_new_candidate), RIGHT_AGENT);
  } else {
    g_signal_handlers_disconnect_by_func (G_OBJECT(lagent), cb_agent_new_candidate,
                                 LEFT_AGENT);
    g_signal_handlers_disconnect_by_func (G_OBJECT(ragent), cb_agent_new_candidate,
                                 RIGHT_AGENT);
  }

  data_received = FALSE;

  nice_agent_attach_recv (lagent, global_ls_id, NICE_COMPONENT_TYPE_RTP,
                   g_main_loop_get_context(global_mainloop),
                   cb_nice_recv, LEFT_AGENT);
  nice_agent_attach_recv (ragent, global_rs_id, NICE_COMPONENT_TYPE_RTP,
                   g_main_loop_get_context(global_mainloop),
                   cb_nice_recv, RIGHT_AGENT);
}

static void cleanup(NiceAgent *lagent,  NiceAgent *ragent)
{
  g_debug ("Cleaning up");
  drop_stun_packets = FALSE;
  nice_agent_remove_stream (lagent, global_ls_id);
  nice_agent_remove_stream (ragent, global_rs_id);
}

static void standard_test(NiceAgent *lagent, NiceAgent *ragent)
{
  g_debug ("test-dribblemode:%s", G_STRFUNC);

  init_test (lagent, ragent, FALSE);

  nice_agent_gather_candidates (lagent, global_ls_id);
  g_main_loop_run (global_mainloop);
  g_assert (global_lagent_state == NICE_COMPONENT_STATE_GATHERING &&
            !lagent_candidate_gathering_done);

  nice_agent_gather_candidates (ragent, global_rs_id);
  if (!ragent_candidate_gathering_done) {
    g_main_loop_run (global_mainloop);
    g_assert (ragent_candidate_gathering_done);
  }

  set_credentials (lagent, global_ls_id, ragent, global_rs_id);

  g_debug ("Setting local candidates of ragent as remote candidates of lagent");
  swap_candidates (ragent, global_rs_id,
                   lagent, global_ls_id,
                   TRUE);

  g_main_loop_run (global_mainloop);
  g_assert (global_lagent_state >= NICE_COMPONENT_STATE_CONNECTED &&
            data_received);

  g_debug ("Setting local candidates of lagent as remote candidates of ragent");
  swap_candidates (lagent, global_ls_id,
                   ragent, global_rs_id,
                   FALSE);
  g_main_loop_run (global_mainloop);

  g_assert (lagent_candidate_gathering_done);

  g_assert (global_lagent_state == NICE_COMPONENT_STATE_READY);
  g_assert (global_ragent_state >= NICE_COMPONENT_STATE_CONNECTED);

  cleanup (lagent, ragent);
}

static void bad_credentials_test(NiceAgent *lagent, NiceAgent *ragent)
{
  g_debug ("test-dribblemode:%s", G_STRFUNC);

  init_test (lagent, ragent, FALSE);

  nice_agent_set_remote_credentials (lagent, global_ls_id,
                                     "wrong", "wrong");
  nice_agent_set_remote_credentials (ragent, global_rs_id,
                                     "wrong2", "wrong2");

  nice_agent_gather_candidates (lagent, global_ls_id);
  g_main_loop_run (global_mainloop);
  g_assert (global_lagent_state == NICE_COMPONENT_STATE_GATHERING &&
            !lagent_candidate_gathering_done);

  nice_agent_gather_candidates (ragent, global_rs_id);
  if (!ragent_candidate_gathering_done) {
    g_main_loop_run (global_mainloop);
    g_assert (ragent_candidate_gathering_done);
  }

  swap_candidates (ragent, global_rs_id,
                   lagent, global_ls_id,
                   FALSE);
  g_main_loop_run (global_mainloop);
  g_assert (global_lagent_state == NICE_COMPONENT_STATE_FAILED);

  // Set the correct credentials and swap candidates
  set_credentials (lagent, global_ls_id, ragent, global_rs_id);
  swap_candidates (ragent, global_rs_id,
                   lagent, global_ls_id,
                   FALSE);

  swap_candidates (lagent, global_ls_id,
                   ragent, global_rs_id,
                   FALSE);

  g_main_loop_run (global_mainloop);

  g_assert (data_received);
  g_assert (global_lagent_state == NICE_COMPONENT_STATE_READY);
  g_assert (global_ragent_state >= NICE_COMPONENT_STATE_CONNECTED);

  // Wait for lagent to finish gathering candidates
  g_main_loop_run (global_mainloop);
  g_assert (lagent_candidate_gathering_done);

  cleanup (lagent, ragent);
}

static void bad_candidate_test(NiceAgent *lagent,NiceAgent *ragent)
{
  NiceCandidate *cand =  NULL;

  g_debug ("test-dribblemode:%s", G_STRFUNC);

  init_test (lagent, ragent, FALSE);

  nice_agent_gather_candidates (lagent, global_ls_id);
  g_main_loop_run (global_mainloop);
  g_assert (global_lagent_state == NICE_COMPONENT_STATE_GATHERING &&
            !lagent_candidate_gathering_done);

  nice_agent_gather_candidates (ragent, global_rs_id);
  if (!ragent_candidate_gathering_done) {
    g_main_loop_run (global_mainloop);
    g_assert (ragent_candidate_gathering_done);
  }

  add_bad_candidate (lagent, global_ls_id, cand);

  // lagent will finish candidate gathering causing this mainloop to quit
  g_main_loop_run (global_mainloop);

  // connchecks will fail causing this mainloop to quit
  g_main_loop_run (global_mainloop);

  g_assert (global_lagent_state == NICE_COMPONENT_STATE_FAILED &&
            !data_received);
  set_credentials (lagent, global_ls_id, ragent, global_rs_id);

  swap_candidates (ragent, global_rs_id,
                   lagent, global_ls_id,
                   FALSE);

  swap_candidates (lagent, global_ls_id,
                   ragent, global_rs_id,
                   FALSE);

  g_main_loop_run (global_mainloop);

  g_assert (lagent_candidate_gathering_done);

  g_assert (global_lagent_state == NICE_COMPONENT_STATE_READY);
  g_assert (global_ragent_state >= NICE_COMPONENT_STATE_CONNECTED);

  cleanup (lagent, ragent);
}

static void new_candidate_test(NiceAgent *lagent, NiceAgent *ragent)
{
  g_debug ("test-dribblemode:%s", G_STRFUNC);

  init_test (lagent, ragent, TRUE);
  set_credentials (lagent, global_ls_id, ragent, global_rs_id);

  nice_agent_gather_candidates (lagent, global_ls_id);
  g_main_loop_run (global_mainloop);
  g_assert (global_lagent_state == NICE_COMPONENT_STATE_GATHERING &&
            !lagent_candidate_gathering_done);

  nice_agent_gather_candidates (ragent, global_rs_id);
  if (!ragent_candidate_gathering_done) {
    g_main_loop_run (global_mainloop);
  }

  // Wait for data
  g_main_loop_run (global_mainloop);
  g_assert (data_received);

  // Data arrived, signal STUN thread to send STUN response
  g_mutex_lock (stun_mutex_ptr);
  g_cond_signal (stun_signal_ptr);
  g_mutex_unlock (stun_mutex_ptr);

  // Wait for lagent to finish gathering candidates
  g_main_loop_run (global_mainloop);

  g_assert (lagent_candidate_gathering_done);
  g_assert (ragent_candidate_gathering_done);

  g_assert (global_lagent_state == NICE_COMPONENT_STATE_READY);
  g_assert (global_ragent_state >= NICE_COMPONENT_STATE_CONNECTED);

  cleanup (lagent, ragent);
}

static void send_dummy_data(void)
{
  int sockfd = listen_socket (4567);
  struct sockaddr_in addr;

  memset (&addr, 0, sizeof (addr));
  addr.sin_family = AF_INET;
  inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
  addr.sin_port = htons (IPPORT_STUN);

  g_debug ("Sending dummy data to close STUN thread");
  sendto (sockfd, "close socket", 12, 0,
          (struct sockaddr *)&addr, sizeof (addr));
}

int main(void)
{
  NiceAgent *lagent = NULL, *ragent = NULL;
  GThread *stun_thread = NULL;
  NiceAddress baseaddr;

  g_type_init();

  global_mainloop = g_main_loop_new (NULL, FALSE);

#if !GLIB_CHECK_VERSION(2,31,8)
  g_thread_init (NULL);
  stun_thread = g_thread_create (stun_thread_func,
                                 global_mainloop,
                                 TRUE, NULL);
 stun_mutex_ptr = g_mutex_new ();
 stun_signal_ptr = g_cond_new ();
#else
  stun_thread = g_thread_new ("listen for STUN requests",
                              stun_thread_func, NULL);
#endif

  // Once the the thread is forked, we want to listen for a signal 
  // that the socket was opened successfully
  g_mutex_lock (stun_thread_mutex_ptr);
  g_cond_wait (stun_thread_signal_ptr, stun_thread_mutex_ptr); 

  lagent = nice_agent_new (g_main_loop_get_context (global_mainloop),
      NICE_COMPATIBILITY_RFC5245);
  ragent = nice_agent_new (g_main_loop_get_context (global_mainloop),
      NICE_COMPATIBILITY_RFC5245);

  g_object_set (G_OBJECT (lagent), "controlling-mode", TRUE, NULL);
  g_object_set (G_OBJECT (ragent), "controlling-mode", FALSE, NULL);

  g_object_set (G_OBJECT (lagent), "upnp", USE_UPNP, NULL);
  g_object_set (G_OBJECT (ragent), "upnp", USE_UPNP, NULL);

  g_object_set (G_OBJECT (lagent), "stun-server", "127.0.0.1", NULL);
  g_object_set (G_OBJECT (lagent), "stun-server-port", IPPORT_STUN, NULL);

  g_object_set_data (G_OBJECT (lagent), "other-agent", ragent);
  g_object_set_data (G_OBJECT (ragent), "other-agent", lagent);

  g_assert (nice_address_set_from_string (&baseaddr, "127.0.0.1"));
  nice_agent_add_local_address (lagent, &baseaddr);
  nice_agent_add_local_address (ragent, &baseaddr);

  g_signal_connect(G_OBJECT(lagent), "candidate-gathering-done",
                   G_CALLBACK(cb_candidate_gathering_done), LEFT_AGENT);
  g_signal_connect(G_OBJECT(ragent), "candidate-gathering-done",
                   G_CALLBACK(cb_candidate_gathering_done), RIGHT_AGENT);
  g_signal_connect(G_OBJECT(lagent), "component-state-changed",
                   G_CALLBACK(cb_component_state_changed), LEFT_AGENT);
  g_signal_connect(G_OBJECT(ragent), "component-state-changed",
                   G_CALLBACK(cb_component_state_changed), RIGHT_AGENT);

  standard_test (lagent, ragent);
  bad_credentials_test (lagent, ragent);
  bad_candidate_test (lagent, ragent);
  new_candidate_test (lagent, ragent);

  // Do this to make sure the STUN thread exits
  exit_stun_thread = TRUE;
  drop_stun_packets = TRUE;
  send_dummy_data ();

  g_object_unref (lagent);
  g_object_unref (ragent);

  g_thread_join (stun_thread);
#if !GLIB_CHECK_VERSION(2,31,8)
  g_mutex_free (stun_mutex_ptr);
  g_cond_free (stun_signal_ptr);
#endif
  g_main_loop_unref (global_mainloop);

  return 0;
}
