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

#include "random.h"
#include "random-glib.h"

static NiceRNG * (*nice_rng_new_func) (void) = NULL;

NiceRNG *
nice_rng_new (void)
{
  if (nice_rng_new_func == NULL)
    return nice_rng_glib_new ();
  else
    return nice_rng_new_func ();
}

void
nice_rng_set_new_func (NiceRNG * (*func) (void))
{
  nice_rng_new_func = func;
}

void
nice_rng_free (NiceRNG *rng)
{
  rng->free (rng);
}

void
nice_rng_generate_bytes (NiceRNG *rng, guint len, gchar *buf)
{
  rng->generate_bytes (rng, len, buf);
}

guint
nice_rng_generate_int (NiceRNG *rng, guint low, guint high)
{
  return rng->generate_int (rng, low, high);
}

void
nice_rng_generate_bytes_print (NiceRNG *rng, guint len, gchar *buf)
{
  guint i;
  const gchar *chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "01234567890";

  for (i = 0; i < len; i++)
    buf[i] = chars[nice_rng_generate_int (rng, 0, 62)];
}

