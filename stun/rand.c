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

void nice_RAND_bytes (uint8_t *dst, int len)
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

/* ------------- Start original implementation. ----------------- */
/* http://www.math.sci.hiroshima-u.ac.jp/~m-mat/MT/MT2002/emt19937ar.html */

/*
   A C-program for MT19937, with initialization improved 2002/1/26.
   Coded by Takuji Nishimura and Makoto Matsumoto.

   Before using, initialize the state by using init_genrand(seed)
   or init_by_array(init_key, key_length).

   Copyright (C) 1997 - 2002, Makoto Matsumoto and Takuji Nishimura,
   All rights reserved

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions
   are met:

     1. Redistributions of source code must retain the above copyright
        notice, this list of conditions and the following disclaimer.

     2. Redistributions in binary form must reproduce the above copyright
        notice, this list of conditions and the following disclaimer in the
        documentation and/or other materials provided with the distribution.

     3. The names of its contributors may not be used to endorse or promote
        products derived from this software without specific prior written
        permission.

   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
   A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR
   CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
   EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
   PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
   PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
   LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
   NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
   SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


   Any feedback is very welcome.
   http://www.math.sci.hiroshima-u.ac.jp/~m-mat/MT/emt.html
   email: m-mat @ math.sci.hiroshima-u.ac.jp (remove space)
*/

/* Period parameters */
#define N 624
#define M 397
#define MATRIX_A 0x9908b0dfUL   /* constant vector a */
#define UPPER_MASK 0x80000000UL /* most significant w-r bits */
#define LOWER_MASK 0x7fffffffUL /* least significant r bits */

static unsigned long mt[N]; /* the array for the state vector  */
static int mti=N+1; /* mti==N+1 means mt[N] is not initialized */

/* initializes mt[N] with a seed */
static void init_genrand(unsigned long s)
{
  mt[0]= s & 0xffffffffUL;
  for (mti=1; mti<N; mti++) {
    mt[mti] = (1812433253UL * (mt[mti-1] ^ (mt[mti-1] >> 30)) + mti);
    /* See Knuth TAOCP Vol2. 3rd Ed. P.106 for multiplier. */
    /* In the previous versions, MSBs of the seed affect   */
    /* only MSBs of the array mt[].                        */
    /* 2002/01/09 modified by Makoto Matsumoto             */
    mt[mti] &= 0xffffffffUL;
    /* for >32 bit machines */
  }
}

/* initialize by an array with array-length */
/* init_key is the array for initializing keys */
/* key_length is its length */
/* slight change for C++, 2004/2/26 */
static void init_by_array(unsigned long init_key[], int key_length)
{
  int i, j, k;
  init_genrand(19650218UL);
  i=1; j=0;
  k = (N>key_length ? N : key_length);
  for (; k; k--) {
    mt[i] = (mt[i] ^ ((mt[i-1] ^ (mt[i-1] >> 30)) * 1664525UL))
        + init_key[j] + j; /* non linear */
    mt[i] &= 0xffffffffUL; /* for WORDSIZE > 32 machines */
    i++; j++;
    if (i>=N) { mt[0] = mt[N-1]; i=1; }
    if (j>=key_length) j=0;
  }
  for (k=N-1; k; k--) {
    mt[i] = (mt[i] ^ ((mt[i-1] ^ (mt[i-1] >> 30)) * 1566083941UL))
        - i; /* non linear */
    mt[i] &= 0xffffffffUL; /* for WORDSIZE > 32 machines */
    i++;
    if (i>=N) { mt[0] = mt[N-1]; i=1; }
  }

  mt[0] = 0x80000000UL; /* MSB is 1; assuring non-zero initial array */
}

/* generates a random number on [0,0xffffffff]-interval */
static unsigned long genrand_int32(void)
{
  unsigned long y;
  static unsigned long mag01[2]={0x0UL, MATRIX_A};
  /* mag01[x] = x * MATRIX_A  for x=0,1 */

  if (mti >= N) { /* generate N words at one time */
    int kk;

    if (mti == N+1)   /* if init_genrand() has not been called, */
      init_genrand(5489UL); /* a default initial seed is used */

    for (kk=0;kk<N-M;kk++) {
      y = (mt[kk]&UPPER_MASK)|(mt[kk+1]&LOWER_MASK);
      mt[kk] = mt[kk+M] ^ (y >> 1) ^ mag01[y & 0x1UL];
    }
    for (;kk<N-1;kk++) {
      y = (mt[kk]&UPPER_MASK)|(mt[kk+1]&LOWER_MASK);
      mt[kk] = mt[kk+(M-N)] ^ (y >> 1) ^ mag01[y & 0x1UL];
    }
    y = (mt[N-1]&UPPER_MASK)|(mt[0]&LOWER_MASK);
    mt[N-1] = mt[M-1] ^ (y >> 1) ^ mag01[y & 0x1UL];

    mti = 0;
  }

  y = mt[mti++];

  /* Tempering */
  y ^= (y >> 11);
  y ^= (y << 7) & 0x9d2c5680UL;
  y ^= (y << 15) & 0xefc60000UL;
  y ^= (y >> 18);

  return y;
}

/* These real versions are due to Isaku Wada, 2002/01/09 added */

/* ------------- End original implementation. ----------------- */

#include <stdio.h>
#include <time.h>

static int initialized = 0;

void nice_RAND_bytes (uint8_t *dst, int len)
{
  int i;

  if (!initialized) {
    /* Seed the generator with an array from /dev/urandom if available
       Otherwise use time() and clock() values */

    FILE *urandom = fopen( "/dev/urandom", "rb" );
    unsigned long init_key[10] = {};
    int key_length = 0;
    if (urandom) {
      while (fread(&init_key[key_length++], sizeof(unsigned long), 1,
              urandom) > 0 &&    key_length < 10);
      fclose(urandom);
    } else {
      time_t t = time (NULL);
      clock_t c = clock ();
      unsigned long cl = c;
      unsigned long tl = t;
      init_key[0] = *((unsigned long *) dst);
      init_key[1] = 0x6c69626e;
      init_key[2] = 0x69636500;
      init_key[3] = tl;
      init_key[4] = cl;
      key_length = 5;
    }
    init_by_array(init_key, key_length);
    initialized = 1;
  }

  for (i = 0; i < len; i++) {
    dst[i] = genrand_int32 () & 0xFF;
  }
}

#endif /* _WIN32 */
