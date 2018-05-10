/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2008 Collabora Ltd. All rights reserved.
 *  Contact: Youness Alaoui
 * (C) 2008 Nokia Corporation. All rights reserved.
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
# include <config.h>
#endif

#include "rand.h"


#ifdef _WIN32

#include <windows.h>
#include <wincrypt.h>

void nice_RAND_nonce (uint8_t *dst, int len)
{
  HCRYPTPROV hCryptProv;
  LPCSTR container = "Libnice key container";

  if(!CryptAcquireContext(&hCryptProv, container, NULL, PROV_RSA_FULL, 0)) {
    /* non existing container. try to create a new one */
    // I hope this cast here doesn't cause issues
    // gcc was complaining about comparing signed and unsigned values
    if (GetLastError() == (DWORD) NTE_BAD_KEYSET) {
      if(!CryptAcquireContext(&hCryptProv, container, NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET)) {
        return;
      }
    }
    return;
  }

  CryptGenRandom (hCryptProv, len, dst);

  CryptReleaseContext(hCryptProv,0);
}
#else

#ifdef HAVE_OPENSSL

#include <openssl/rand.h>

void nice_RAND_nonce (uint8_t *dst, int len)
{
  RAND_bytes (dst, len);
}

#else

#include <sys/types.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

void nice_RAND_nonce (uint8_t *dst, int len)
{
  gnutls_rnd (GNUTLS_RND_NONCE, dst, len);
}

#endif /* HAVE_OPENSSL */

#endif /* _WIN32 */
