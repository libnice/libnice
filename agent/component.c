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

/**
 * @file component.c
 * @brief ICE component functions
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include "component.h"

Component *
component_new (
  G_GNUC_UNUSED
  guint id)
{
  Component *component;

  component = g_slice_new0 (Component);
  component->id = id;
  return component;
}


void
component_free (Component *cmp)
{
  GSList *i;

  for (i = cmp->local_candidates; i; i = i->next) {
    NiceCandidate *candidate = i->data;
    nice_candidate_free (candidate);
  }

  for (i = cmp->remote_candidates; i; i = i->next) {
    NiceCandidate *candidate = i->data;
    nice_candidate_free (candidate);
  }

  for (i = cmp->sockets; i; i = i->next) {
    NiceUDPSocket *udpsocket = i->data;
    nice_udp_socket_close (udpsocket);
  }

  for (i = cmp->gsources; i; i = i->next) {
    GSource *source = i->data;
    g_source_destroy (source);
  }

  g_slist_free (cmp->gsources),
    cmp->gsources = NULL;

  g_slist_free (cmp->local_candidates);
  g_slist_free (cmp->remote_candidates);
  g_slist_free (cmp->sockets);
  g_slice_free (Component, cmp);
}

/**
 * Returns a component UDP socket struct that uses handle 'fd'.
 *
 * Note: there might be multiple sockets using the same
 *       handle.
 */
NiceUDPSocket *
component_find_udp_socket_by_fd (Component *component, guint fd)
{
  GSList *i;

  /* XXX: this won't work anymore, a single fd may be used
  *       by multiple candidates */
  
  for (i = component->sockets; i; i = i->next)
    {
      NiceUDPSocket *sockptr = i->data;

      if (sockptr->fileno == fd)
        return sockptr;
    }

  return NULL;
}
