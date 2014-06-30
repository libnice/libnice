/*
 * Copyright 2013 University of Chicago
 *  Contact: Bryce Allen
 * Copyright 2013 Collabora Ltd.
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

/*
 * Example using libnice to negotiate a UDP connection between two clients,
 * possibly on the same network or behind different NATs and/or stateful
 * firewalls.
 *
 * Build:
 *   gcc -o sdp-example sdp-example.c `pkg-config --cflags --libs nice`
 *
 * Run two clients, one controlling and one controlled:
 *   sdp-example 0 $(host -4 -t A stun.stunprotocol.org | awk '{ print $4 }')
 *   sdp-example 1 $(host -4 -t A stun.stunprotocol.org | awk '{ print $4 }')
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>

#include <agent.h>

static GMainLoop *gloop;
static gchar *stun_addr = NULL;
static guint stun_port;
static gboolean controlling;
static gboolean exit_thread, candidate_gathering_done, negotiation_done;
static GMutex gather_mutex, negotiate_mutex;
static GCond gather_cond, negotiate_cond;

static const gchar *state_name[] = {"disconnected", "gathering", "connecting",
                                    "connected", "ready", "failed"};

static void cb_candidate_gathering_done(NiceAgent *agent, guint stream_id,
    gpointer data);
static void cb_component_state_changed(NiceAgent *agent, guint stream_id,
    guint component_id, guint state,
    gpointer data);
static void cb_nice_recv(NiceAgent *agent, guint stream_id, guint component_id,
    guint len, gchar *buf, gpointer data);

static void * example_thread(void *data);

int
main(int argc, char *argv[])
{
  GThread *gexamplethread;

  // Parse arguments
  if (argc > 4 || argc < 2 || argv[1][1] != '\0') {
    fprintf(stderr, "Usage: %s 0|1 stun_addr [stun_port]\n", argv[0]);
    return EXIT_FAILURE;
  }
  controlling = argv[1][0] - '0';
  if (controlling != 0 && controlling != 1) {
    fprintf(stderr, "Usage: %s 0|1 stun_addr [stun_port]\n", argv[0]);
    return EXIT_FAILURE;
  }

  if (argc > 2) {
    stun_addr = argv[2];
    if (argc > 3)
      stun_port = atoi(argv[3]);
    else
      stun_port = 3478;

    g_debug("Using stun server '[%s]:%u'\n", stun_addr, stun_port);
  }

#if !GLIB_CHECK_VERSION(2, 36, 0)
  g_type_init();
#endif

  gloop = g_main_loop_new(NULL, FALSE);

  // Run the mainloop and the example thread
  exit_thread = FALSE;
  gexamplethread = g_thread_new("example thread", &example_thread, NULL);
  g_main_loop_run (gloop);
  exit_thread = TRUE;

  g_thread_join (gexamplethread);
  g_main_loop_unref(gloop);

  return EXIT_SUCCESS;
}

static void *
example_thread(void *data)
{
  NiceAgent *agent;
  GIOChannel* io_stdin;
  guint stream_id;
  gchar *line = NULL;
  gchar *sdp, *sdp64;

  io_stdin = g_io_channel_unix_new(fileno(stdin));
  g_io_channel_set_flags (io_stdin, G_IO_FLAG_NONBLOCK, NULL);

  // Create the nice agent
  agent = nice_agent_new(g_main_loop_get_context (gloop),
      NICE_COMPATIBILITY_RFC5245);
  if (agent == NULL)
    g_error("Failed to create agent");

  // Set the STUN settings and controlling mode
  if (stun_addr) {
    g_object_set(agent, "stun-server", stun_addr, NULL);
    g_object_set(agent, "stun-server-port", stun_port, NULL);
  }
  g_object_set(agent, "controlling-mode", controlling, NULL);

  // Connect to the signals
  g_signal_connect(agent, "candidate-gathering-done",
      G_CALLBACK(cb_candidate_gathering_done), NULL);
  g_signal_connect(agent, "component-state-changed",
      G_CALLBACK(cb_component_state_changed), NULL);

  // Create a new stream with one component
  stream_id = nice_agent_add_stream(agent, 1);
  if (stream_id == 0)
    g_error("Failed to add stream");
  nice_agent_set_stream_name (agent, stream_id, "text");

  // Attach to the component to receive the data
  // Without this call, candidates cannot be gathered
  nice_agent_attach_recv(agent, stream_id, 1,
      g_main_loop_get_context (gloop), cb_nice_recv, NULL);

  // Start gathering local candidates
  if (!nice_agent_gather_candidates(agent, stream_id))
    g_error("Failed to start candidate gathering");

  g_debug("waiting for candidate-gathering-done signal...");

  g_mutex_lock(&gather_mutex);
  while (!exit_thread && !candidate_gathering_done)
    g_cond_wait(&gather_cond, &gather_mutex);
  g_mutex_unlock(&gather_mutex);
  if (exit_thread)
    goto end;

  // Candidate gathering is done. Send our local candidates on stdout
  sdp = nice_agent_generate_local_sdp (agent);
  printf("Generated SDP from agent :\n%s\n\n", sdp);
  printf("Copy the following line to remote client:\n");
  sdp64 = g_base64_encode ((const guchar *)sdp, strlen (sdp));
  printf("\n  %s\n", sdp64);
  g_free (sdp);
  g_free (sdp64);

  // Listen on stdin for the remote candidate list
  printf("Enter remote data (single line, no wrapping):\n");
  printf("> ");
  fflush (stdout);
  while (!exit_thread) {
    GIOStatus s = g_io_channel_read_line (io_stdin, &line, NULL, NULL, NULL);
    if (s == G_IO_STATUS_NORMAL) {
      gsize sdp_len;

      sdp = (gchar *) g_base64_decode (line, &sdp_len);
      // Parse remote candidate list and set it on the agent
      if (sdp && nice_agent_parse_remote_sdp (agent, sdp) > 0) {
        g_free (sdp);
        g_free (line);
        break;
      } else {
        fprintf(stderr, "ERROR: failed to parse remote data\n");
        printf("Enter remote data (single line, no wrapping):\n");
        printf("> ");
        fflush (stdout);
      }
      g_free (sdp);
      g_free (line);
    } else if (s == G_IO_STATUS_AGAIN) {
      usleep (100000);
    }
  }

  g_debug("waiting for state READY or FAILED signal...");
  g_mutex_lock(&negotiate_mutex);
  while (!exit_thread && !negotiation_done)
    g_cond_wait(&negotiate_cond, &negotiate_mutex);
  g_mutex_unlock(&negotiate_mutex);
  if (exit_thread)
    goto end;

  // Listen to stdin and send data written to it
  printf("\nSend lines to remote (Ctrl-D to quit):\n");
  printf("> ");
  fflush (stdout);
  while (!exit_thread) {
    GIOStatus s = g_io_channel_read_line (io_stdin, &line, NULL, NULL, NULL);

    if (s == G_IO_STATUS_NORMAL) {
      nice_agent_send(agent, stream_id, 1, strlen(line), line);
      g_free (line);
      printf("> ");
      fflush (stdout);
    } else if (s == G_IO_STATUS_AGAIN) {
      usleep (100000);
    } else {
      // Ctrl-D was pressed.
      nice_agent_send(agent, stream_id, 1, 1, "\0");
      break;
    }
  }

end:
  g_object_unref(agent);
  g_io_channel_unref (io_stdin);
  g_main_loop_quit (gloop);

  return NULL;
}

static void
cb_candidate_gathering_done(NiceAgent *agent, guint stream_id,
    gpointer data)
{
  g_debug("SIGNAL candidate gathering done\n");

  g_mutex_lock(&gather_mutex);
  candidate_gathering_done = TRUE;
  g_cond_signal(&gather_cond);
  g_mutex_unlock(&gather_mutex);
}

static void
cb_component_state_changed(NiceAgent *agent, guint stream_id,
    guint component_id, guint state,
    gpointer data)
{
  g_debug("SIGNAL: state changed %d %d %s[%d]\n",
      stream_id, component_id, state_name[state], state);

  if (state == NICE_COMPONENT_STATE_READY) {
    g_mutex_lock(&negotiate_mutex);
    negotiation_done = TRUE;
    g_cond_signal(&negotiate_cond);
    g_mutex_unlock(&negotiate_mutex);
  } else if (state == NICE_COMPONENT_STATE_FAILED) {
    g_main_loop_quit (gloop);
  }
}

static void
cb_nice_recv(NiceAgent *agent, guint stream_id, guint component_id,
    guint len, gchar *buf, gpointer data)
{
  if (len == 1 && buf[0] == '\0')
    g_main_loop_quit (gloop);

  printf("%.*s", len, buf);
  fflush(stdout);
}
