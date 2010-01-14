/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2006-2007 Collabora Ltd.
 *  Contact: Dafydd Harries
 * (C) 2006-2007 Nokia Corporation. All rights reserved.
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
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <string.h>

#include "random-glib.h"

int
main (void)
{
  NiceRNG *rng;
  const int rngsize = 256;
  gchar buf[rngsize];

  buf[rngsize - 1] = '\0';

  nice_rng_set_new_func (nice_rng_glib_new_predictable);
  rng = nice_rng_new ();

  nice_rng_generate_bytes_print (rng, rngsize - 1, buf);
  /* g_debug ("%s", buf); */
  g_assert (0 == strcmp (buf, "sv1AD7DnJTVykXGYYM6BmnXuYRlZNIJUzQzF+PvASjYxzdTTOngBJ5/gfK0Xj+Ly3ciAAk1Fmo0RPEpq6f4BBnp5jm3LuSbAOj1M5qULEGEv/0DMk0oOPUj6XPN1VwxFpjAfFeAxykiwdDiqNwnVJ/AKyr6/X7C5i+je7DSujURybOp6BkKWroLCzQg2AmTuqz48oNeY9CDeirNwoITfIaC40Ds9OgEDtL8WN5tL4QYdVuZQ85219Thogk775GV"));

  nice_rng_generate_bytes (rng, 4, buf);
  buf[4] = 0;
  g_assert (0 == strcmp (buf, "\x1f\x0d\x47\xb8"));

  nice_rng_free (rng);
  return 0;
}

