/*
 * Dropbear SSH client implementation
 *
 * Copyright (c) 2002,2003 Matt Johnston
 * Copyright (c) 2004 by Mihnea Stoenescu
 * All rights reserved.
 *
 * Modified by Vladimir Oleynik (vodz) <dzo@simtreas.ru> (c) 2012 to be
 * used in busybox or stadalone bionic android-ndk applet.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE. */

/* LibTomMath, multiple-precision integer library -- Tom St Denis
 *
 * LibTomMath is a library that provides multiple-precision
 * integer arithmetic as well as number theoretic functionality.
 *
 * The library was designed directly after the MPI library by
 * Michael Fromberger but has been written from scratch with
 * additional optimizations in place.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 * Tom St Denis, tomstdenis@gmail.com, http://math.libtomcrypt.com
 */

/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 * Tom St Denis, tomstdenis@gmail.com, http://libtomcrypt.com
 */

/**
  Compliant base64 code donated by Wayne Scott (wscott@bitmover.com)
*/

#define DROPBEAR_VERSION "2012.55-vodz"
#define LOCAL_IDENT "SSH-2.0-dropbear_" DROPBEAR_VERSION
/* CRYPT version 1.16 */


/* use configuration data */

/* Use zlib */
#define DISABLE_ZLIB

/* Enable TCP Fowarding */
/* 'Local' is "-L" style (client listening port forwarded via server)
 * 'Remote' is "-R" style (server listening port forwarded via client) */
#define ENABLE_CLI_LOCALTCPFWD
#define ENABLE_CLI_REMOTETCPFWD

/* Enable Authentication Agent Forwarding */
#define ENABLE_CLI_AGENTFWD

/* Authentication Types - at least one required.
   RFC Draft requires pubkey auth, and recommends password */

/* Define this to allow logging in to accounts that have no password specified.
 * Public key logins are allowed for blank-password accounts regardless of this
 * setting.  PAM is not affected by this setting, it uses the normal pam.d
 * settings ('nullok' option) */
#define ENABLE_CLI_PASSWORD_AUTH
#define ENABLE_CLI_PUBKEY_AUTH
#define ENABLE_CLI_INTERACT_AUTH

/* Encryption - at least one required.
 * Protocol RFC requires 3DES and recommends AES128 for interoperability.
 * Including multiple keysize variants the same cipher
 * (eg AES256 as well as AES128) will result in a minimal size increase.*/
#define DROPBEAR_AES128
#define DROPBEAR_3DES
#define DROPBEAR_AES256
#define DROPBEAR_TWOFISH256
#define DROPBEAR_TWOFISH128

/* Enable "Counter Mode" for ciphers. This is more secure than normal
 * CBC mode against certain attacks. This adds around 1kB to binary
 * size and is recommended for most cases */
#define DROPBEAR_ENABLE_CTR_MODE

/* Message Integrity - at least one required.
 * Protocol RFC requires sha1 and recommends sha1-96.
 * sha1-96 may be of use for slow links, as it has a smaller overhead.
 *
 * Note: there's no point disabling sha1 to save space, since it's used
 * for the random number generator and public-key cryptography anyway.
 * Disabling it here will just stop it from being used as the integrity portion
 * of the ssh protocol.
 *
 * These hashes are also used for public key fingerprints in logs.
 * If you disable MD5, Dropbear will fall back to SHA1 fingerprints,
 * which are not the standard form. */
#define DROPBEAR_SHA1_HMAC
#define DROPBEAR_SHA1_96_HMAC
#define DROPBEAR_MD5_HMAC

/* Hostkey/public key algorithms - at least one required, these are used
 * for hostkey as well as for verifying signatures with pubkey auth.
 * Removing either of these won't save very much space.
 * SSH2 RFC Draft requires dss, recommends rsa */
#define DROPBEAR_RSA
#define DROPBEAR_DSS

/* RSA can be vulnerable to timing attacks which use the time required for
 * signing to guess the private key. Blinding avoids this attack, though makes
 * signing operations slightly slower. */
#define RSA_BLINDING

/* Define DSS_PROTOK to use PuTTY's method of generating the value k for dss,
 * rather than just from the random byte source. Undefining this will save you
 * ~4k in binary size with static uclibc, but your DSS hostkey could be exposed
 * if the random number source isn't good. It happened to Sony.
 * On systems with a decent random source this isn't required. */
/* #define DSS_PROTOK */

/* Set this if you want to use the LTC_SMALL_CODE option. This can save
several kB in binary size however will make the symmetrical ciphers and hashes
slower, perhaps by 50%. Recommended for small systems that aren't doing
much traffic. */
/*#define LTC_SMALL_CODE*/

/* disable all forms of ASM */
/* #define LTC_NO_ASM */

/* disable BSWAP on x86 */
/* #define LTC_NO_BSWAP */


/* Number of bits in a file offset, on hosts where this is settable. */
#define _FILE_OFFSET_BITS 64

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/param.h> /* required for BSD4_4 define */
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <termios.h>
#include <unistd.h>
#include <syslog.h>
#include <netdb.h>
#include <dirent.h>
#include <libgen.h>
#include <paths.h>
#include <netinet/in.h>
#include <arpa/inet.h>
/* netbsd 1.6 needs this to be included before netinet/ip.h for some
 * undocumented reason */
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <inttypes.h>
#include <netdb.h>


#ifndef DISABLE_ZLIB
#include <zlib.h>
#endif

#if defined(DROPBEAR_AES256) || defined(DROPBEAR_AES128)
#define DROPBEAR_AES
#endif

#if defined(DROPBEAR_TWOFISH256) || defined(DROPBEAR_TWOFISH128)
#define DROPBEAR_TWOFISH
#endif


/* max size of either a cipher/hash block or symmetric key [largest of the two] */
#define MAXBLOCKSIZE  128

/* error codes */
enum {
   CRYPT_OK=0,             /* Result OK */
   CRYPT_ERROR,            /* Generic Error */
   CRYPT_INVALID_KEYSIZE,  /* Invalid key size given */
   CRYPT_INVALID_ROUNDS,   /* Invalid number of rounds */
   CRYPT_BUFFER_OVERFLOW,  /* Not enough space for output */
   CRYPT_INVALID_PACKET,   /* Invalid input packet given */
   CRYPT_INVALID_CIPHER,   /* Invalid cipher specified */
   CRYPT_MEM,              /* Out of memory */
   CRYPT_INVALID_ARG,      /* Generic invalid argument */
};

/* this is the "32-bit at least" data type
 * Re-define it to suit your platform but it must be at least 32-bits
 */
#if defined(__x86_64__) || (defined(__sparc__) && defined(__arch64__))
   typedef unsigned ulong32;
#else
   typedef unsigned long ulong32;
#endif

/* Controls endianess and size of registers.  Leave uncommented to get platform neutral [slower] code
 *
 * Note: in order to use the optimized macros your platform must support unaligned 32 and 64 bit read/writes.
 * The x86 platforms allow this but some others [ARM for instance] do not.  On those platforms you **MUST**
 * use the portable [slower] macros.
 */

/* detect x86-32 machines somewhat */
#if !defined(__STRICT_ANSI__) && (defined(INTEL_CC) || (defined(__GNUC__) && (defined(__DJGPP__) || defined(__CYGWIN__) || defined(__MINGW32__) || defined(__i386__))))
   #define ENDIAN_LITTLE
   #define ENDIAN_32BITWORD
   #define LTC_FAST
   #define LTC_FAST_TYPE    unsigned long
#endif

/* detects MIPS R5900 processors (PS2) */
#if (defined(__R5900) || defined(R5900) || defined(__R5900__)) && (defined(_mips) || defined(__mips__) || defined(mips))
   #define ENDIAN_LITTLE
   #define ENDIAN_64BITWORD
#endif

/* detect amd64 */
#if !defined(__STRICT_ANSI__) && defined(__x86_64__)
   #define ENDIAN_LITTLE
   #define ENDIAN_64BITWORD
   #define LTC_FAST
   #define LTC_FAST_TYPE    unsigned long
#endif

/* detect PPC32 */
#if !defined(__STRICT_ANSI__) && defined(LTC_PPC32)
   #define ENDIAN_BIG
   #define ENDIAN_32BITWORD
   #define LTC_FAST
   #define LTC_FAST_TYPE    unsigned long
#endif

/* detect sparc and sparc64 */
#if defined(__sparc__)
  #define ENDIAN_BIG
  #if defined(__arch64__)
    #define ENDIAN_64BITWORD
  #else
    #define ENDIAN_32BITWORD
  #endif
#endif


/* No asm is a quick way to disable anything "not portable" */
#ifdef LTC_NO_ASM
   #undef ENDIAN_LITTLE
   #undef ENDIAN_BIG
   #undef ENDIAN_32BITWORD
   #undef ENDIAN_64BITWORD
   #undef LTC_FAST
   #undef LTC_FAST_TYPE
	#define LTC_NO_BSWAP
#endif

#if (defined(ENDIAN_BIG) || defined(ENDIAN_LITTLE)) && !(defined(ENDIAN_32BITWORD) || defined(ENDIAN_64BITWORD))
    #error You must specify a word size as well as endianess in tomcrypt.h
#endif

#if !(defined(ENDIAN_BIG) || defined(ENDIAN_LITTLE))
   #define ENDIAN_NEUTRAL
#endif

#define CONST64(n) n ## ULL

/* ---- HELPER MACROS ---- */
#ifdef ENDIAN_NEUTRAL

#define STORE32L(x, y)                                                                     \
     { (y)[3] = (unsigned char)(((x)>>24)&255); (y)[2] = (unsigned char)(((x)>>16)&255);   \
       (y)[1] = (unsigned char)(((x)>>8)&255); (y)[0] = (unsigned char)((x)&255); }

#define LOAD32L(x, y)                            \
     { x = ((unsigned long)((y)[3] & 255)<<24) | \
	   ((unsigned long)((y)[2] & 255)<<16) | \
	   ((unsigned long)((y)[1] & 255)<<8)  | \
	   ((unsigned long)((y)[0] & 255)); }

#define STORE64L(x, y)                                                                     \
     { (y)[7] = (unsigned char)(((x)>>56)&255); (y)[6] = (unsigned char)(((x)>>48)&255);   \
       (y)[5] = (unsigned char)(((x)>>40)&255); (y)[4] = (unsigned char)(((x)>>32)&255);   \
       (y)[3] = (unsigned char)(((x)>>24)&255); (y)[2] = (unsigned char)(((x)>>16)&255);   \
       (y)[1] = (unsigned char)(((x)>>8)&255); (y)[0] = (unsigned char)((x)&255); }

#define LOAD64L(x, y)                                                       \
     { x = (((ulong64)((y)[7] & 255))<<56)|(((ulong64)((y)[6] & 255))<<48)| \
	   (((ulong64)((y)[5] & 255))<<40)|(((ulong64)((y)[4] & 255))<<32)| \
	   (((ulong64)((y)[3] & 255))<<24)|(((ulong64)((y)[2] & 255))<<16)| \
	   (((ulong64)((y)[1] & 255))<<8)|(((ulong64)((y)[0] & 255))); }

#define STORE32H(x, y)                                                                     \
     { (y)[0] = (unsigned char)(((x)>>24)&255); (y)[1] = (unsigned char)(((x)>>16)&255);   \
       (y)[2] = (unsigned char)(((x)>>8)&255); (y)[3] = (unsigned char)((x)&255); }

#define LOAD32H(x, y)                            \
     { x = ((unsigned long)((y)[0] & 255)<<24) | \
	   ((unsigned long)((y)[1] & 255)<<16) | \
	   ((unsigned long)((y)[2] & 255)<<8)  | \
	   ((unsigned long)((y)[3] & 255)); }

#define STORE64H(x, y)                                                                     \
   { (y)[0] = (unsigned char)(((x)>>56)&255); (y)[1] = (unsigned char)(((x)>>48)&255);     \
     (y)[2] = (unsigned char)(((x)>>40)&255); (y)[3] = (unsigned char)(((x)>>32)&255);     \
     (y)[4] = (unsigned char)(((x)>>24)&255); (y)[5] = (unsigned char)(((x)>>16)&255);     \
     (y)[6] = (unsigned char)(((x)>>8)&255); (y)[7] = (unsigned char)((x)&255); }

#define LOAD64H(x, y)                                                      \
   { x = (((ulong64)((y)[0] & 255))<<56)|(((ulong64)((y)[1] & 255))<<48) | \
	 (((ulong64)((y)[2] & 255))<<40)|(((ulong64)((y)[3] & 255))<<32) | \
	 (((ulong64)((y)[4] & 255))<<24)|(((ulong64)((y)[5] & 255))<<16) | \
	 (((ulong64)((y)[6] & 255))<<8)|(((ulong64)((y)[7] & 255))); }

#endif /* ENDIAN_NEUTRAL */

#ifdef ENDIAN_LITTLE

#if !defined(LTC_NO_BSWAP) && (defined(INTEL_CC) || (defined(__GNUC__) && (defined(__DJGPP__) || defined(__CYGWIN__) || defined(__MINGW32__) || defined(__i386__) || defined(__x86_64__))))

#define STORE32H(x, y)           \
asm __volatile__ (               \
   "bswapl %0     \n\t"          \
   "movl   %0,(%1)\n\t"          \
   "bswapl %0     \n\t"          \
      ::"r"(x), "r"(y));

#define LOAD32H(x, y)          \
asm __volatile__ (             \
   "movl (%1),%0\n\t"          \
   "bswapl %0\n\t"             \
   :"=r"(x): "r"(y));

#else

#define STORE32H(x, y)                                                                     \
     { (y)[0] = (unsigned char)(((x)>>24)&255); (y)[1] = (unsigned char)(((x)>>16)&255);   \
       (y)[2] = (unsigned char)(((x)>>8)&255); (y)[3] = (unsigned char)((x)&255); }

#define LOAD32H(x, y)                            \
     { x = ((unsigned long)((y)[0] & 255)<<24) | \
	   ((unsigned long)((y)[1] & 255)<<16) | \
	   ((unsigned long)((y)[2] & 255)<<8)  | \
	   ((unsigned long)((y)[3] & 255)); }

#endif


/* x86_64 processor */
#if !defined(LTC_NO_BSWAP) && (defined(__GNUC__) && defined(__x86_64__))

#define STORE64H(x, y)           \
asm __volatile__ (               \
   "bswapq %0     \n\t"          \
   "movq   %0,(%1)\n\t"          \
   "bswapq %0     \n\t"          \
      ::"r"(x), "r"(y));

#define LOAD64H(x, y)          \
asm __volatile__ (             \
   "movq (%1),%0\n\t"          \
   "bswapq %0\n\t"             \
   :"=r"(x): "r"(y));

#else

#define STORE64H(x, y)                                                                     \
   { (y)[0] = (unsigned char)(((x)>>56)&255); (y)[1] = (unsigned char)(((x)>>48)&255);     \
     (y)[2] = (unsigned char)(((x)>>40)&255); (y)[3] = (unsigned char)(((x)>>32)&255);     \
     (y)[4] = (unsigned char)(((x)>>24)&255); (y)[5] = (unsigned char)(((x)>>16)&255);     \
     (y)[6] = (unsigned char)(((x)>>8)&255); (y)[7] = (unsigned char)((x)&255); }

#define LOAD64H(x, y)                                                      \
   { x = (((ulong64)((y)[0] & 255))<<56)|(((ulong64)((y)[1] & 255))<<48) | \
	 (((ulong64)((y)[2] & 255))<<40)|(((ulong64)((y)[3] & 255))<<32) | \
	 (((ulong64)((y)[4] & 255))<<24)|(((ulong64)((y)[5] & 255))<<16) | \
	 (((ulong64)((y)[6] & 255))<<8)|(((ulong64)((y)[7] & 255))); }

#endif

#ifdef ENDIAN_32BITWORD

#define STORE32L(x, y)        \
     { ulong32  __t = (x); memcpy(y, &__t, 4); }

#define LOAD32L(x, y)         \
     memcpy(&(x), y, 4);

#define STORE64L(x, y)                                                                     \
     { (y)[7] = (unsigned char)(((x)>>56)&255); (y)[6] = (unsigned char)(((x)>>48)&255);   \
       (y)[5] = (unsigned char)(((x)>>40)&255); (y)[4] = (unsigned char)(((x)>>32)&255);   \
       (y)[3] = (unsigned char)(((x)>>24)&255); (y)[2] = (unsigned char)(((x)>>16)&255);   \
       (y)[1] = (unsigned char)(((x)>>8)&255); (y)[0] = (unsigned char)((x)&255); }

#define LOAD64L(x, y)                                                       \
     { x = (((ulong64)((y)[7] & 255))<<56)|(((ulong64)((y)[6] & 255))<<48)| \
	   (((ulong64)((y)[5] & 255))<<40)|(((ulong64)((y)[4] & 255))<<32)| \
	   (((ulong64)((y)[3] & 255))<<24)|(((ulong64)((y)[2] & 255))<<16)| \
	   (((ulong64)((y)[1] & 255))<<8)|(((ulong64)((y)[0] & 255))); }

#else /* 64-bit words then  */

#define STORE32L(x, y)        \
     { ulong32 __t = (x); memcpy(y, &__t, 4); }

#define LOAD32L(x, y)         \
     { memcpy(&(x), y, 4); x &= 0xFFFFFFFF; }

#define STORE64L(x, y)        \
     { ulong64 __t = (x); memcpy(y, &__t, 8); }

#define LOAD64L(x, y)         \
    { memcpy(&(x), y, 8); }

#endif /* ENDIAN_64BITWORD */

#endif /* ENDIAN_LITTLE */

#ifdef ENDIAN_BIG
#define STORE32L(x, y)                                                                     \
     { (y)[3] = (unsigned char)(((x)>>24)&255); (y)[2] = (unsigned char)(((x)>>16)&255);   \
       (y)[1] = (unsigned char)(((x)>>8)&255); (y)[0] = (unsigned char)((x)&255); }

#define LOAD32L(x, y)                            \
     { x = ((unsigned long)((y)[3] & 255)<<24) | \
	   ((unsigned long)((y)[2] & 255)<<16) | \
	   ((unsigned long)((y)[1] & 255)<<8)  | \
	   ((unsigned long)((y)[0] & 255)); }

#define STORE64L(x, y)                                                                     \
   { (y)[7] = (unsigned char)(((x)>>56)&255); (y)[6] = (unsigned char)(((x)>>48)&255);     \
     (y)[5] = (unsigned char)(((x)>>40)&255); (y)[4] = (unsigned char)(((x)>>32)&255);     \
     (y)[3] = (unsigned char)(((x)>>24)&255); (y)[2] = (unsigned char)(((x)>>16)&255);     \
     (y)[1] = (unsigned char)(((x)>>8)&255); (y)[0] = (unsigned char)((x)&255); }

#define LOAD64L(x, y)                                                      \
   { x = (((ulong64)((y)[7] & 255))<<56)|(((ulong64)((y)[6] & 255))<<48) | \
	 (((ulong64)((y)[5] & 255))<<40)|(((ulong64)((y)[4] & 255))<<32) | \
	 (((ulong64)((y)[3] & 255))<<24)|(((ulong64)((y)[2] & 255))<<16) | \
	 (((ulong64)((y)[1] & 255))<<8)|(((ulong64)((y)[0] & 255))); }

#ifdef ENDIAN_32BITWORD

#define STORE32H(x, y)        \
     { ulong32 __t = (x); memcpy(y, &__t, 4); }

#define LOAD32H(x, y)         \
     memcpy(&(x), y, 4);

#define STORE64H(x, y)                                                                     \
     { (y)[0] = (unsigned char)(((x)>>56)&255); (y)[1] = (unsigned char)(((x)>>48)&255);   \
       (y)[2] = (unsigned char)(((x)>>40)&255); (y)[3] = (unsigned char)(((x)>>32)&255);   \
       (y)[4] = (unsigned char)(((x)>>24)&255); (y)[5] = (unsigned char)(((x)>>16)&255);   \
       (y)[6] = (unsigned char)(((x)>>8)&255);  (y)[7] = (unsigned char)((x)&255); }

#define LOAD64H(x, y)                                                       \
     { x = (((ulong64)((y)[0] & 255))<<56)|(((ulong64)((y)[1] & 255))<<48)| \
	   (((ulong64)((y)[2] & 255))<<40)|(((ulong64)((y)[3] & 255))<<32)| \
	   (((ulong64)((y)[4] & 255))<<24)|(((ulong64)((y)[5] & 255))<<16)| \
	   (((ulong64)((y)[6] & 255))<<8)| (((ulong64)((y)[7] & 255))); }

#else /* 64-bit words then  */

#define STORE32H(x, y)        \
     { ulong32 __t = (x); memcpy(y, &__t, 4); }

#define LOAD32H(x, y)         \
     { memcpy(&(x), y, 4); x &= 0xFFFFFFFF; }

#define STORE64H(x, y)        \
     { ulong64 __t = (x); memcpy(y, &__t, 8); }

#define LOAD64H(x, y)         \
    { memcpy(&(x), y, 8); }

#endif /* ENDIAN_64BITWORD */
#endif /* ENDIAN_BIG */

#define BSWAP(x)  ( ((x>>24)&0x000000FFUL) | ((x<<24)&0xFF000000UL)  | \
		    ((x>>8)&0x0000FF00UL)  | ((x<<8)&0x00FF0000UL) )


#if !defined(__STRICT_ANSI__) && defined(__GNUC__) && (defined(__i386__) || defined(__x86_64__)) && !defined(INTEL_CC) && !defined(LTC_NO_ASM)

static inline unsigned ROL(unsigned word, int i)
{
   asm ("roll %%cl,%0"
      :"=r" (word)
      :"0" (word),"c" (i));
   return word;
}

static inline unsigned ROR(unsigned word, int i)
{
   asm ("rorl %%cl,%0"
      :"=r" (word)
      :"0" (word),"c" (i));
   return word;
}

#define ROLc ROL
#define RORc ROR

#elif !defined(__STRICT_ANSI__) && defined(LTC_PPC32)

static inline unsigned ROL(unsigned word, int i)
{
   asm ("rotlw %0,%0,%2"
      :"=r" (word)
      :"0" (word),"r" (i));
   return word;
}

static inline unsigned ROR(unsigned word, int i)
{
   asm ("rotlw %0,%0,%2"
      :"=r" (word)
      :"0" (word),"r" (32-i));
   return word;
}

#define ROLc ROL
#define RORc ROR

#else

/* rotates the hard way */
#define ROL(x, y) ( (((unsigned long)(x)<<(unsigned long)((y)&31)) | (((unsigned long)(x)&0xFFFFFFFFUL)>>(unsigned long)(32-((y)&31)))) & 0xFFFFFFFFUL)
#define ROR(x, y) ( ((((unsigned long)(x)&0xFFFFFFFFUL)>>(unsigned long)((y)&31)) | ((unsigned long)(x)<<(unsigned long)(32-((y)&31)))) & 0xFFFFFFFFUL)
#define ROLc(x, y) ( (((unsigned long)(x)<<(unsigned long)((y)&31)) | (((unsigned long)(x)&0xFFFFFFFFUL)>>(unsigned long)(32-((y)&31)))) & 0xFFFFFFFFUL)
#define RORc(x, y) ( ((((unsigned long)(x)&0xFFFFFFFFUL)>>(unsigned long)((y)&31)) | ((unsigned long)(x)<<(unsigned long)(32-((y)&31)))) & 0xFFFFFFFFUL)

#endif


/* 64-bit Rotates */
#if !defined(__STRICT_ANSI__) && defined(__GNUC__) && defined(__x86_64__) && !defined(LTC_NO_ASM)

static inline unsigned long ROL64(unsigned long word, int i)
{
   asm("rolq %%cl,%0"
      :"=r" (word)
      :"0" (word),"c" (i));
   return word;
}

static inline unsigned long ROR64(unsigned long word, int i)
{
   asm("rorq %%cl,%0"
      :"=r" (word)
      :"0" (word),"c" (i));
   return word;
}

#define ROL64c ROL64
#define ROR64c ROR64

#else /* Not x86_64  */

#define ROL64(x, y) \
    ( (((x)<<((ulong64)(y)&63)) | \
      (((x)&CONST64(0xFFFFFFFFFFFFFFFF))>>((ulong64)64-((y)&63)))) & CONST64(0xFFFFFFFFFFFFFFFF))

#define ROR64(x, y) \
    ( ((((x)&CONST64(0xFFFFFFFFFFFFFFFF))>>((ulong64)(y)&CONST64(63))) | \
      ((x)<<((ulong64)(64-((y)&CONST64(63)))))) & CONST64(0xFFFFFFFFFFFFFFFF))

#define ROL64c(x, y) \
    ( (((x)<<((ulong64)(y)&63)) | \
      (((x)&CONST64(0xFFFFFFFFFFFFFFFF))>>((ulong64)64-((y)&63)))) & CONST64(0xFFFFFFFFFFFFFFFF))

#define ROR64c(x, y) \
    ( ((((x)&CONST64(0xFFFFFFFFFFFFFFFF))>>((ulong64)(y)&CONST64(63))) | \
      ((x)<<((ulong64)(64-((y)&CONST64(63)))))) & CONST64(0xFFFFFFFFFFFFFFFF))

#endif

#ifndef MAX
   #define MAX(x, y) ( ((x)>(y))?(x):(y) )
#endif

#ifndef MIN
   #define MIN(x, y) ( ((x)<(y))?(x):(y) )
#endif

#define byte(x, n) (((x) >> (8 * (n))) & 255)


typedef unsigned long long ulong64;

/* ---- SYMMETRIC KEY STUFF -----
 *
 * We put each of the ciphers scheduled keys in their own structs then we put all of
 * the key formats in one union.  This makes the function prototypes easier to use.
 */
#ifdef DROPBEAR_AES
struct rijndael_key {
   ulong32 eK[60], dK[60];
   int Nr;
};
#endif

#ifdef DROPBEAR_TWOFISH
   struct twofish_key {
      ulong32 K[40];
      unsigned char S[32], start;
   };
#endif

#ifdef DROPBEAR_3DES
struct des3_key {
    ulong32 ek[3][32], dk[3][32];
};
#endif

typedef union Symmetric_key {
#ifdef DROPBEAR_3DES
   struct des3_key des3;
#endif
#ifdef DROPBEAR_TWOFISH
   struct twofish_key  twofish;
#endif
#ifdef DROPBEAR_AES
   struct rijndael_key rijndael;
#endif
   void   *data;
} symmetric_key;

/** A block cipher CBC structure */
typedef struct {
   /** The index of the cipher chosen */
   int                 cipher,
   /** The block size of the given cipher */
		       blocklen;
   /** The current IV */
   unsigned char       IV[MAXBLOCKSIZE];
   /** The scheduled key */
   symmetric_key       key;
} symmetric_CBC;


#ifdef DROPBEAR_ENABLE_CTR_MODE
/** A block cipher CTR structure */
typedef struct {
   /** The index of the cipher chosen */
   int                 cipher,
   /** The block size of the given cipher */
		       blocklen,
   /** The padding offset */
		       padlen,
   /** The mode (endianess) of the CTR, 0==little, 1==big */
		       mode;
   /** The counter */
   unsigned char       ctr[MAXBLOCKSIZE],
   /** The pad used to encrypt/decrypt */
		       pad[MAXBLOCKSIZE];
   /** The scheduled key */
   symmetric_key       key;
} symmetric_CTR;
#endif


/** cipher descriptor table, last entry has "name == NULL" to mark the end of table */
struct ltc_cipher_descriptor {
   /** name of cipher */
   char *name;
   /** block size (octets) */
   int block_length;
   /** Setup the cipher
      @param key         The input symmetric key
      @param keylen      The length of the input key (octets)
      @param num_rounds  The requested number of rounds (0==default)
      @param skey        [out] The destination of the scheduled key
      @return CRYPT_OK if successful
   */
   int  (*setup)(const unsigned char *key, int keylen, int num_rounds, symmetric_key *skey);
   /** Encrypt a block
      @param pt      The plaintext
      @param ct      [out] The ciphertext
      @param skey    The scheduled key
      @return CRYPT_OK if successful
   */
   int (*ecb_encrypt)(const unsigned char *pt, unsigned char *ct, symmetric_key *skey);
   /** Decrypt a block
      @param ct      The ciphertext
      @param pt      [out] The plaintext
      @param skey    The scheduled key
      @return CRYPT_OK if successful
   */
   int (*ecb_decrypt)(const unsigned char *ct, unsigned char *pt, symmetric_key *skey);
};

#ifdef DROPBEAR_ENABLE_CTR_MODE
# define CTR_COUNTER_LITTLE_ENDIAN    0
# define CTR_COUNTER_BIG_ENDIAN       1
# define LTC_CTR_RFC3686              2
#endif


/* ---- HASH FUNCTIONS ---- */
struct sha1_state {
    ulong64 length;
    ulong32 state[5], curlen;
    unsigned char buf[64];
};

#ifdef DROPBEAR_MD5_HMAC
struct md5_state {
    ulong64 length;
    ulong32 state[4], curlen;
    unsigned char buf[64];
};
#endif

typedef union Hash_state {
    char dummy[1];
    struct sha1_state   sha1;
#ifdef DROPBEAR_MD5_HMAC
    struct md5_state    md5;
#endif
    void *data;
} hash_state;

/** hash descriptor */
struct ltc_hash_descriptor {
    /** name of hash */
    char *name;
    /** Size of digest in octets */
    unsigned long hashsize;
    /** Input block size in octets */
    unsigned long blocksize;

    /** Init a hash state
      @param hash   The hash to initialize
      @return CRYPT_OK if successful
    */
    int (*init)(hash_state *hash);
    /** Process a block of data
      @param hash   The hash state
      @param in     The data to hash
      @param inlen  The length of the data (octets)
      @return CRYPT_OK if successful
    */
    int (*process)(hash_state *hash, const unsigned char *in, unsigned long inlen);
    /** Produce the digest and store it
      @param hash   The hash state
      @param out    [out] The destination of the digest
      @return CRYPT_OK if successful
    */
    int (*done)(hash_state *hash, unsigned char *out);
};

typedef struct Hmac_state {
     hash_state     md;
     int            hash;
     hash_state     hashstate;
     unsigned char  *key;
} hmac_state;

/**
   Zero a block of memory, Tom St Denis
   @param out    The destination of the area to zero
   @param outlen The length of the area to zero (octets)
*/
static void zeromem(void *out, size_t outlen)
{
   unsigned char *mem = out;
   while (outlen-- > 0) {
      *mem++ = 0;
   }
}

/* descriptor table size */
#define TOMCRYPT_TAB_SIZE    4


/* AES implementation by Tom St Denis
 *
 * Derived from the Public Domain source code by

---
  * rijndael-alg-fst.c
  *
  * @version 3.0 (December 2000)
  *
  * Optimised ANSI C code for the Rijndael cipher (now AES)
  *
  * @author Vincent Rijmen <vincent.rijmen@esat.kuleuven.ac.be>
  * @author Antoon Bosselaers <antoon.bosselaers@esat.kuleuven.ac.be>
  * @author Paulo Barreto <paulo.barreto@terra.com.br>
---
 */

#ifdef DROPBEAR_AES

#include "aes_tables.c"

static ulong32 setup_mix(ulong32 temp)
{
   return (Te4_3[byte(temp, 2)]) ^
	  (Te4_2[byte(temp, 1)]) ^
	  (Te4_1[byte(temp, 0)]) ^
	  (Te4_0[byte(temp, 3)]);
}

#ifdef LTC_SMALL_CODE
static ulong32 setup_mix2(ulong32 temp)
{
   return Td0(255 & Te4[byte(temp, 3)]) ^
	  Td1(255 & Te4[byte(temp, 2)]) ^
	  Td2(255 & Te4[byte(temp, 1)]) ^
	  Td3(255 & Te4[byte(temp, 0)]);
}
#endif

 /**
    Initialize the AES (Rijndael) block cipher
    @param key The symmetric key you wish to pass
    @param keylen The key length in bytes
    @param num_rounds The number of rounds desired (0 for default)
    @param skey The key in as scheduled by this function.
    @return CRYPT_OK if successful
 */
static int rijndael_setup(const unsigned char *key, int keylen, int num_rounds, symmetric_key *skey)
{
    int i, j;
    ulong32 temp, *rk;
    ulong32 *rrk;

    if (keylen != 16 && keylen != 24 && keylen != 32)
       return CRYPT_INVALID_KEYSIZE;

    if (num_rounds != 0 && num_rounds != (10 + ((keylen/8)-2)*2))
       return CRYPT_INVALID_ROUNDS;

    skey->rijndael.Nr = 10 + ((keylen/8)-2)*2;

    /* setup the forward key */
    i                 = 0;
    rk                = skey->rijndael.eK;
    LOAD32H(rk[0], key     );
    LOAD32H(rk[1], key +  4);
    LOAD32H(rk[2], key +  8);
    LOAD32H(rk[3], key + 12);
    if (keylen == 16) {
	j = 44;
	for (;;) {
	    temp  = rk[3];
	    rk[4] = rk[0] ^ setup_mix(temp) ^ rcon[i];
	    rk[5] = rk[1] ^ rk[4];
	    rk[6] = rk[2] ^ rk[5];
	    rk[7] = rk[3] ^ rk[6];
	    if (++i == 10) {
	       break;
	    }
	    rk += 4;
	}
    } else if (keylen == 24) {
	j = 52;
	LOAD32H(rk[4], key + 16);
	LOAD32H(rk[5], key + 20);
	for (;;) {
	    temp = rk[5];
	    rk[ 6] = rk[ 0] ^ setup_mix(temp) ^ rcon[i];
	    rk[ 7] = rk[ 1] ^ rk[ 6];
	    rk[ 8] = rk[ 2] ^ rk[ 7];
	    rk[ 9] = rk[ 3] ^ rk[ 8];
	    if (++i == 8) {
		break;
	    }
	    rk[10] = rk[ 4] ^ rk[ 9];
	    rk[11] = rk[ 5] ^ rk[10];
	    rk += 6;
	}
    } else if (keylen == 32) {
	j = 60;
	LOAD32H(rk[4], key + 16);
	LOAD32H(rk[5], key + 20);
	LOAD32H(rk[6], key + 24);
	LOAD32H(rk[7], key + 28);
	for (;;) {
	    temp = rk[7];
	    rk[ 8] = rk[ 0] ^ setup_mix(temp) ^ rcon[i];
	    rk[ 9] = rk[ 1] ^ rk[ 8];
	    rk[10] = rk[ 2] ^ rk[ 9];
	    rk[11] = rk[ 3] ^ rk[10];
	    if (++i == 7) {
		break;
	    }
	    temp = rk[11];
	    rk[12] = rk[ 4] ^ setup_mix(RORc(temp, 8));
	    rk[13] = rk[ 5] ^ rk[12];
	    rk[14] = rk[ 6] ^ rk[13];
	    rk[15] = rk[ 7] ^ rk[14];
	    rk += 8;
	}
    } else {
       /* this can't happen */
       return CRYPT_ERROR;
    }

    /* setup the inverse key now */
    rk   = skey->rijndael.dK;
    rrk  = skey->rijndael.eK + j - 4;

    /* apply the inverse MixColumn transform to all round keys but the first and the last: */
    /* copy first */
    *rk++ = *rrk++;
    *rk++ = *rrk++;
    *rk++ = *rrk++;
    *rk   = *rrk;
    rk -= 3; rrk -= 3;

    for (i = 1; i < skey->rijndael.Nr; i++) {
	rrk -= 4;
	rk  += 4;
    #ifdef LTC_SMALL_CODE
	temp = rrk[0];
	rk[0] = setup_mix2(temp);
	temp = rrk[1];
	rk[1] = setup_mix2(temp);
	temp = rrk[2];
	rk[2] = setup_mix2(temp);
	temp = rrk[3];
	rk[3] = setup_mix2(temp);
     #else
	temp = rrk[0];
	rk[0] =
	    Tks0[byte(temp, 3)] ^
	    Tks1[byte(temp, 2)] ^
	    Tks2[byte(temp, 1)] ^
	    Tks3[byte(temp, 0)];
	temp = rrk[1];
	rk[1] =
	    Tks0[byte(temp, 3)] ^
	    Tks1[byte(temp, 2)] ^
	    Tks2[byte(temp, 1)] ^
	    Tks3[byte(temp, 0)];
	temp = rrk[2];
	rk[2] =
	    Tks0[byte(temp, 3)] ^
	    Tks1[byte(temp, 2)] ^
	    Tks2[byte(temp, 1)] ^
	    Tks3[byte(temp, 0)];
	temp = rrk[3];
	rk[3] =
	    Tks0[byte(temp, 3)] ^
	    Tks1[byte(temp, 2)] ^
	    Tks2[byte(temp, 1)] ^
	    Tks3[byte(temp, 0)];
      #endif

    }

    /* copy last */
    rrk -= 4;
    rk  += 4;
    *rk++ = *rrk++;
    *rk++ = *rrk++;
    *rk++ = *rrk++;
    *rk   = *rrk;

    return CRYPT_OK;
}

/**
  Encrypts a block of text with AES
  @param pt The input plaintext (16 bytes)
  @param ct The output ciphertext (16 bytes)
  @param skey The key as scheduled
  @return CRYPT_OK if successful
*/
static int rijndael_ecb_encrypt(const unsigned char *pt, unsigned char *ct, symmetric_key *skey)
{
    ulong32 s0, s1, s2, s3, t0, t1, t2, t3, *rk;
    int Nr, r;

    Nr = skey->rijndael.Nr;
    rk = skey->rijndael.eK;

    /*
     * map byte array block to cipher state
     * and add initial round key:
     */
    LOAD32H(s0, pt      ); s0 ^= rk[0];
    LOAD32H(s1, pt  +  4); s1 ^= rk[1];
    LOAD32H(s2, pt  +  8); s2 ^= rk[2];
    LOAD32H(s3, pt  + 12); s3 ^= rk[3];

#ifdef LTC_SMALL_CODE

    for (r = 0; ; r++) {
	rk += 4;
	t0 =
	    Te0(byte(s0, 3)) ^
	    Te1(byte(s1, 2)) ^
	    Te2(byte(s2, 1)) ^
	    Te3(byte(s3, 0)) ^
	    rk[0];
	t1 =
	    Te0(byte(s1, 3)) ^
	    Te1(byte(s2, 2)) ^
	    Te2(byte(s3, 1)) ^
	    Te3(byte(s0, 0)) ^
	    rk[1];
	t2 =
	    Te0(byte(s2, 3)) ^
	    Te1(byte(s3, 2)) ^
	    Te2(byte(s0, 1)) ^
	    Te3(byte(s1, 0)) ^
	    rk[2];
	t3 =
	    Te0(byte(s3, 3)) ^
	    Te1(byte(s0, 2)) ^
	    Te2(byte(s1, 1)) ^
	    Te3(byte(s2, 0)) ^
	    rk[3];
	if (r == Nr-2) {
	   break;
	}
	s0 = t0; s1 = t1; s2 = t2; s3 = t3;
    }
    rk += 4;

#else

    /*
     * Nr - 1 full rounds:
     */
    r = Nr >> 1;
    for (;;) {
	t0 =
	    Te0(byte(s0, 3)) ^
	    Te1(byte(s1, 2)) ^
	    Te2(byte(s2, 1)) ^
	    Te3(byte(s3, 0)) ^
	    rk[4];
	t1 =
	    Te0(byte(s1, 3)) ^
	    Te1(byte(s2, 2)) ^
	    Te2(byte(s3, 1)) ^
	    Te3(byte(s0, 0)) ^
	    rk[5];
	t2 =
	    Te0(byte(s2, 3)) ^
	    Te1(byte(s3, 2)) ^
	    Te2(byte(s0, 1)) ^
	    Te3(byte(s1, 0)) ^
	    rk[6];
	t3 =
	    Te0(byte(s3, 3)) ^
	    Te1(byte(s0, 2)) ^
	    Te2(byte(s1, 1)) ^
	    Te3(byte(s2, 0)) ^
	    rk[7];

	rk += 8;
	if (--r == 0) {
	    break;
	}

	s0 =
	    Te0(byte(t0, 3)) ^
	    Te1(byte(t1, 2)) ^
	    Te2(byte(t2, 1)) ^
	    Te3(byte(t3, 0)) ^
	    rk[0];
	s1 =
	    Te0(byte(t1, 3)) ^
	    Te1(byte(t2, 2)) ^
	    Te2(byte(t3, 1)) ^
	    Te3(byte(t0, 0)) ^
	    rk[1];
	s2 =
	    Te0(byte(t2, 3)) ^
	    Te1(byte(t3, 2)) ^
	    Te2(byte(t0, 1)) ^
	    Te3(byte(t1, 0)) ^
	    rk[2];
	s3 =
	    Te0(byte(t3, 3)) ^
	    Te1(byte(t0, 2)) ^
	    Te2(byte(t1, 1)) ^
	    Te3(byte(t2, 0)) ^
	    rk[3];
    }

#endif

    /*
     * apply last round and
     * map cipher state to byte array block:
     */
    s0 =
	(Te4_3[byte(t0, 3)]) ^
	(Te4_2[byte(t1, 2)]) ^
	(Te4_1[byte(t2, 1)]) ^
	(Te4_0[byte(t3, 0)]) ^
	rk[0];
    STORE32H(s0, ct);
    s1 =
	(Te4_3[byte(t1, 3)]) ^
	(Te4_2[byte(t2, 2)]) ^
	(Te4_1[byte(t3, 1)]) ^
	(Te4_0[byte(t0, 0)]) ^
	rk[1];
    STORE32H(s1, ct+4);
    s2 =
	(Te4_3[byte(t2, 3)]) ^
	(Te4_2[byte(t3, 2)]) ^
	(Te4_1[byte(t0, 1)]) ^
	(Te4_0[byte(t1, 0)]) ^
	rk[2];
    STORE32H(s2, ct+8);
    s3 =
	(Te4_3[byte(t3, 3)]) ^
	(Te4_2[byte(t0, 2)]) ^
	(Te4_1[byte(t1, 1)]) ^
	(Te4_0[byte(t2, 0)]) ^
	rk[3];
    STORE32H(s3, ct+12);

    return CRYPT_OK;
}

/**
  Decrypts a block of text with AES
  @param ct The input ciphertext (16 bytes)
  @param pt The output plaintext (16 bytes)
  @param skey The key as scheduled
  @return CRYPT_OK if successful
*/
static int rijndael_ecb_decrypt(const unsigned char *ct, unsigned char *pt, symmetric_key *skey)
{
    ulong32 s0, s1, s2, s3, t0, t1, t2, t3, *rk;
    int Nr, r;

    Nr = skey->rijndael.Nr;
    rk = skey->rijndael.dK;

    /*
     * map byte array block to cipher state
     * and add initial round key:
     */
    LOAD32H(s0, ct      ); s0 ^= rk[0];
    LOAD32H(s1, ct  +  4); s1 ^= rk[1];
    LOAD32H(s2, ct  +  8); s2 ^= rk[2];
    LOAD32H(s3, ct  + 12); s3 ^= rk[3];

#ifdef LTC_SMALL_CODE
    for (r = 0; ; r++) {
	rk += 4;
	t0 =
	    Td0(byte(s0, 3)) ^
	    Td1(byte(s3, 2)) ^
	    Td2(byte(s2, 1)) ^
	    Td3(byte(s1, 0)) ^
	    rk[0];
	t1 =
	    Td0(byte(s1, 3)) ^
	    Td1(byte(s0, 2)) ^
	    Td2(byte(s3, 1)) ^
	    Td3(byte(s2, 0)) ^
	    rk[1];
	t2 =
	    Td0(byte(s2, 3)) ^
	    Td1(byte(s1, 2)) ^
	    Td2(byte(s0, 1)) ^
	    Td3(byte(s3, 0)) ^
	    rk[2];
	t3 =
	    Td0(byte(s3, 3)) ^
	    Td1(byte(s2, 2)) ^
	    Td2(byte(s1, 1)) ^
	    Td3(byte(s0, 0)) ^
	    rk[3];
	if (r == Nr-2) {
	   break;
	}
	s0 = t0; s1 = t1; s2 = t2; s3 = t3;
    }
    rk += 4;

#else

    /*
     * Nr - 1 full rounds:
     */
    r = Nr >> 1;
    for (;;) {

	t0 =
	    Td0(byte(s0, 3)) ^
	    Td1(byte(s3, 2)) ^
	    Td2(byte(s2, 1)) ^
	    Td3(byte(s1, 0)) ^
	    rk[4];
	t1 =
	    Td0(byte(s1, 3)) ^
	    Td1(byte(s0, 2)) ^
	    Td2(byte(s3, 1)) ^
	    Td3(byte(s2, 0)) ^
	    rk[5];
	t2 =
	    Td0(byte(s2, 3)) ^
	    Td1(byte(s1, 2)) ^
	    Td2(byte(s0, 1)) ^
	    Td3(byte(s3, 0)) ^
	    rk[6];
	t3 =
	    Td0(byte(s3, 3)) ^
	    Td1(byte(s2, 2)) ^
	    Td2(byte(s1, 1)) ^
	    Td3(byte(s0, 0)) ^
	    rk[7];

	rk += 8;
	if (--r == 0) {
	    break;
	}


	s0 =
	    Td0(byte(t0, 3)) ^
	    Td1(byte(t3, 2)) ^
	    Td2(byte(t2, 1)) ^
	    Td3(byte(t1, 0)) ^
	    rk[0];
	s1 =
	    Td0(byte(t1, 3)) ^
	    Td1(byte(t0, 2)) ^
	    Td2(byte(t3, 1)) ^
	    Td3(byte(t2, 0)) ^
	    rk[1];
	s2 =
	    Td0(byte(t2, 3)) ^
	    Td1(byte(t1, 2)) ^
	    Td2(byte(t0, 1)) ^
	    Td3(byte(t3, 0)) ^
	    rk[2];
	s3 =
	    Td0(byte(t3, 3)) ^
	    Td1(byte(t2, 2)) ^
	    Td2(byte(t1, 1)) ^
	    Td3(byte(t0, 0)) ^
	    rk[3];
    }
#endif

    /*
     * apply last round and
     * map cipher state to byte array block:
     */
    s0 =
	(Td4[byte(t0, 3)] & 0xff000000) ^
	(Td4[byte(t3, 2)] & 0x00ff0000) ^
	(Td4[byte(t2, 1)] & 0x0000ff00) ^
	(Td4[byte(t1, 0)] & 0x000000ff) ^
	rk[0];
    STORE32H(s0, pt);
    s1 =
	(Td4[byte(t1, 3)] & 0xff000000) ^
	(Td4[byte(t0, 2)] & 0x00ff0000) ^
	(Td4[byte(t3, 1)] & 0x0000ff00) ^
	(Td4[byte(t2, 0)] & 0x000000ff) ^
	rk[1];
    STORE32H(s1, pt+4);
    s2 =
	(Td4[byte(t2, 3)] & 0xff000000) ^
	(Td4[byte(t1, 2)] & 0x00ff0000) ^
	(Td4[byte(t0, 1)] & 0x0000ff00) ^
	(Td4[byte(t3, 0)] & 0x000000ff) ^
	rk[2];
    STORE32H(s2, pt+8);
    s3 =
	(Td4[byte(t3, 3)] & 0xff000000) ^
	(Td4[byte(t2, 2)] & 0x00ff0000) ^
	(Td4[byte(t1, 1)] & 0x0000ff00) ^
	(Td4[byte(t0, 0)] & 0x000000ff) ^
	rk[3];
    STORE32H(s3, pt+12);

    return CRYPT_OK;
}


static const struct ltc_cipher_descriptor aes_desc =
{
    "aes", 16,
    rijndael_setup, rijndael_ecb_encrypt, rijndael_ecb_decrypt,
};


#endif

/* base64 routine */
static const unsigned char map[256] = {
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
255, 255, 255, 255, 255, 255, 255,  62, 255, 255, 255,  63,
 52,  53,  54,  55,  56,  57,  58,  59,  60,  61, 255, 255,
255, 254, 255, 255, 255,   0,   1,   2,   3,   4,   5,   6,
  7,   8,   9,  10,  11,  12,  13,  14,  15,  16,  17,  18,
 19,  20,  21,  22,  23,  24,  25, 255, 255, 255, 255, 255,
255,  26,  27,  28,  29,  30,  31,  32,  33,  34,  35,  36,
 37,  38,  39,  40,  41,  42,  43,  44,  45,  46,  47,  48,
 49,  50,  51, 255, 255, 255, 255, 255, 255, 255, 255, 255,
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
255, 255, 255, 255 };

/**
   base64 decode a block of memory
   @param in       The base64 data to decode
   @param inlen    The length of the base64 data
   @param out      [out] The destination of the binary decoded data
   @param outlen   [in/out] The max size and resulting size of the decoded data
   @return CRYPT_OK if successful
*/
static int base64_decode(const unsigned char *in,  unsigned long inlen,
			unsigned char *out, unsigned long *outlen)
{
   unsigned long t, x, y, z;
   unsigned char c;
   int           g;

   g = 3;
   for (x = y = z = t = 0; x < inlen; x++) {
       c = map[in[x]&0xFF];
       if (c == 255) continue;
       /* the final = symbols are read and used to trim the remaining bytes */
       if (c == 254) {
	  c = 0;
	  /* prevent g < 0 which would potentially allow an overflow later */
	  if (--g < 0)
	     return CRYPT_INVALID_PACKET;
       } else if (g != 3) {
	  /* we only allow = to be at the end */
	  return CRYPT_INVALID_PACKET;
       }

       t = (t<<6)|c;

       if (++y == 4) {
	  if (z + g > *outlen)
	     return CRYPT_BUFFER_OVERFLOW;
	  out[z++] = (unsigned char)((t>>16)&255);
	  if (g > 1) out[z++] = (unsigned char)((t>>8)&255);
	  if (g > 2) out[z++] = (unsigned char)(t&255);
	  y = t = 0;
       }
   }
   if (y != 0)
       return CRYPT_INVALID_PACKET;
   *outlen = z;
   return CRYPT_OK;
}


/**
  Compliant base64 encoder donated by Wayne Scott (wscott@bitmover.com)
*/
static const char * const codes =
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
   base64 Encode a buffer (NUL terminated)
   @param in      The input buffer to encode
   @param inlen   The length of the input buffer
   @param out     [out] The destination of the base64 encoded data
   @param outlen  [in/out] The max size and resulting size
   @return CRYPT_OK if successful
*/
static int base64_encode(const unsigned char *in,  unsigned long inlen,
			unsigned char *out, unsigned long *outlen)
{
   unsigned long i, len2, leven;
   unsigned char *p;

   /* valid output size ? */
   len2 = 4 * ((inlen + 2) / 3);
   if (*outlen < len2 + 1) {
      *outlen = len2 + 1;
      return CRYPT_BUFFER_OVERFLOW;
   }
   p = out;
   leven = 3*(inlen / 3);
   for (i = 0; i < leven; i += 3) {
       *p++ = codes[(in[0] >> 2) & 0x3F];
       *p++ = codes[(((in[0] & 3) << 4) + (in[1] >> 4)) & 0x3F];
       *p++ = codes[(((in[1] & 0xf) << 2) + (in[2] >> 6)) & 0x3F];
       *p++ = codes[in[2] & 0x3F];
       in += 3;
   }
   /* Pad it if necessary...  */
   if (i < inlen) {
       unsigned a = in[0];
       unsigned b = (i+1 < inlen) ? in[1] : 0;

       *p++ = codes[(a >> 2) & 0x3F];
       *p++ = codes[(((a & 3) << 4) + (b >> 4)) & 0x3F];
       *p++ = (i+1 < inlen) ? codes[(((b & 0xf) << 2)) & 0x3F] : '=';
       *p++ = '=';
   }

   /* append a NULL byte */
   *p = '\0';

   /* return ok */
   *outlen = p - out;
   return CRYPT_OK;
}


/**
  DES code submitted by Dobes Vandermeer
*/

#define EN0 0
#define DE1 1

#include "des_tables.c"

static void cookey(const ulong32 *raw1, ulong32 *keyout);

static void deskey(const unsigned char *key, short edf, ulong32 *keyout)
{
    ulong32 i, j, l, m, n, kn[32];
    unsigned char pc1m[56], pcr[56];

    for (j=0; j < 56; j++) {
	l = (ulong32)pc1[j];
	m = l & 7;
	pc1m[j] = (unsigned char)((key[l >> 3U] & bytebit[m]) == bytebit[m] ? 1 : 0);
    }

    for (i=0; i < 16; i++) {
	if (edf == DE1) {
	   m = (15 - i) << 1;
	} else {
	   m = i << 1;
	}
	n = m + 1;
	kn[m] = kn[n] = 0L;
	for (j=0; j < 28; j++) {
	    l = j + (ulong32)totrot[i];
	    if (l < 28) {
	       pcr[j] = pc1m[l];
	    } else {
	       pcr[j] = pc1m[l - 28];
	    }
	}
	for (/*j = 28*/; j < 56; j++) {
	    l = j + (ulong32)totrot[i];
	    if (l < 56) {
	       pcr[j] = pc1m[l];
	    } else {
	       pcr[j] = pc1m[l - 28];
	    }
	}
	for (j=0; j < 24; j++)  {
	    if ((int)pcr[(int)pc2[j]] != 0) {
	       kn[m] |= bigbyte[j];
	    }
	    if ((int)pcr[(int)pc2[j+24]] != 0) {
	       kn[n] |= bigbyte[j];
	    }
	}
    }

    cookey(kn, keyout);
}

static void cookey(const ulong32 *raw1, ulong32 *keyout)
{
    ulong32 *cook;
    const ulong32 *raw0;
    ulong32 dough[32];
    int i;

    cook = dough;
    for(i=0; i < 16; i++, raw1++)
    {
	raw0 = raw1++;
	*cook    = (*raw0 & 0x00fc0000L) << 6;
	*cook   |= (*raw0 & 0x00000fc0L) << 10;
	*cook   |= (*raw1 & 0x00fc0000L) >> 10;
	*cook++ |= (*raw1 & 0x00000fc0L) >> 6;
	*cook    = (*raw0 & 0x0003f000L) << 12;
	*cook   |= (*raw0 & 0x0000003fL) << 16;
	*cook   |= (*raw1 & 0x0003f000L) >> 4;
	*cook++ |= (*raw1 & 0x0000003fL);
    }

    memcpy(keyout, dough, sizeof dough);
}

static void desfunc(ulong32 *block, const ulong32 *keys)
{
    ulong32 work, right, leftt;
    int cur_round;

    leftt = block[0];
    right = block[1];

#ifdef LTC_SMALL_CODE
    work = ((leftt >> 4)  ^ right) & 0x0f0f0f0fL;
    right ^= work;
    leftt ^= (work << 4);

    work = ((leftt >> 16) ^ right) & 0x0000ffffL;
    right ^= work;
    leftt ^= (work << 16);

    work = ((right >> 2)  ^ leftt) & 0x33333333L;
    leftt ^= work;
    right ^= (work << 2);

    work = ((right >> 8)  ^ leftt) & 0x00ff00ffL;
    leftt ^= work;
    right ^= (work << 8);

    right = ROLc(right, 1);
    work = (leftt ^ right) & 0xaaaaaaaaL;

    leftt ^= work;
    right ^= work;
    leftt = ROLc(leftt, 1);
#else
   {
      ulong64 tmp;
      tmp = des_ip[0][byte(leftt, 0)] ^
	    des_ip[1][byte(leftt, 1)] ^
	    des_ip[2][byte(leftt, 2)] ^
	    des_ip[3][byte(leftt, 3)] ^
	    des_ip[4][byte(right, 0)] ^
	    des_ip[5][byte(right, 1)] ^
	    des_ip[6][byte(right, 2)] ^
	    des_ip[7][byte(right, 3)];
      leftt = (ulong32)(tmp >> 32);
      right = (ulong32)(tmp & 0xFFFFFFFFUL);
   }
#endif

    for (cur_round = 0; cur_round < 8; cur_round++) {
	work  = RORc(right, 4) ^ *keys++;
	leftt ^= SP7[work        & 0x3fL]
	      ^ SP5[(work >>  8) & 0x3fL]
	      ^ SP3[(work >> 16) & 0x3fL]
	      ^ SP1[(work >> 24) & 0x3fL];
	work  = right ^ *keys++;
	leftt ^= SP8[ work        & 0x3fL]
	      ^  SP6[(work >>  8) & 0x3fL]
	      ^  SP4[(work >> 16) & 0x3fL]
	      ^  SP2[(work >> 24) & 0x3fL];

	work = RORc(leftt, 4) ^ *keys++;
	right ^= SP7[ work        & 0x3fL]
	      ^  SP5[(work >>  8) & 0x3fL]
	      ^  SP3[(work >> 16) & 0x3fL]
	      ^  SP1[(work >> 24) & 0x3fL];
	work  = leftt ^ *keys++;
	right ^= SP8[ work        & 0x3fL]
	      ^  SP6[(work >>  8) & 0x3fL]
	      ^  SP4[(work >> 16) & 0x3fL]
	      ^  SP2[(work >> 24) & 0x3fL];
    }

#ifdef LTC_SMALL_CODE
    right = RORc(right, 1);
    work = (leftt ^ right) & 0xaaaaaaaaL;
    leftt ^= work;
    right ^= work;
    leftt = RORc(leftt, 1);
    work = ((leftt >> 8) ^ right) & 0x00ff00ffL;
    right ^= work;
    leftt ^= (work << 8);
    /* -- */
    work = ((leftt >> 2) ^ right) & 0x33333333L;
    right ^= work;
    leftt ^= (work << 2);
    work = ((right >> 16) ^ leftt) & 0x0000ffffL;
    leftt ^= work;
    right ^= (work << 16);
    work = ((right >> 4) ^ leftt) & 0x0f0f0f0fL;
    leftt ^= work;
    right ^= (work << 4);
#else
   {
      ulong64 tmp;
      tmp = des_fp[0][byte(leftt, 0)] ^
	    des_fp[1][byte(leftt, 1)] ^
	    des_fp[2][byte(leftt, 2)] ^
	    des_fp[3][byte(leftt, 3)] ^
	    des_fp[4][byte(right, 0)] ^
	    des_fp[5][byte(right, 1)] ^
	    des_fp[6][byte(right, 2)] ^
	    des_fp[7][byte(right, 3)];
      leftt = (ulong32)(tmp >> 32);
      right = (ulong32)(tmp & 0xFFFFFFFFUL);
   }
#endif

    block[0] = right;
    block[1] = leftt;
}

 /**
    Initialize the 3DES-EDE block cipher
    @param key The symmetric key you wish to pass
    @param keylen The key length in bytes
    @param num_rounds The number of rounds desired (0 for default)
    @param skey The key in as scheduled by this function.
    @return CRYPT_OK if successful
 */
static int des3_setup(const unsigned char *key, int keylen, int num_rounds, symmetric_key *skey)
{
    if(num_rounds != 0 && num_rounds != 16)
	return CRYPT_INVALID_ROUNDS;

    if (keylen != 24)
	return CRYPT_INVALID_KEYSIZE;

    deskey(key,    EN0, skey->des3.ek[0]);
    deskey(key+8,  DE1, skey->des3.ek[1]);
    deskey(key+16, EN0, skey->des3.ek[2]);

    deskey(key,    DE1, skey->des3.dk[2]);
    deskey(key+8,  EN0, skey->des3.dk[1]);
    deskey(key+16, DE1, skey->des3.dk[0]);

    return CRYPT_OK;
}

/**
  Encrypts a block of text with 3DES-EDE
  @param pt The input plaintext (8 bytes)
  @param ct The output ciphertext (8 bytes)
  @param skey The key as scheduled
  @return CRYPT_OK if successful
*/
static int des3_ecb_encrypt(const unsigned char *pt, unsigned char *ct, symmetric_key *skey)
{
    ulong32 work[2];

    LOAD32H(work[0], pt+0);
    LOAD32H(work[1], pt+4);
    desfunc(work, skey->des3.ek[0]);
    desfunc(work, skey->des3.ek[1]);
    desfunc(work, skey->des3.ek[2]);
    STORE32H(work[0],ct+0);
    STORE32H(work[1],ct+4);
    return CRYPT_OK;
}

/**
  Decrypts a block of text with 3DES-EDE
  @param ct The input ciphertext (8 bytes)
  @param pt The output plaintext (8 bytes)
  @param skey The key as scheduled
  @return CRYPT_OK if successful
*/
static int des3_ecb_decrypt(const unsigned char *ct, unsigned char *pt, symmetric_key *skey)
{
    ulong32 work[2];
    LOAD32H(work[0], ct+0);
    LOAD32H(work[1], ct+4);
    desfunc(work, skey->des3.dk[0]);
    desfunc(work, skey->des3.dk[1]);
    desfunc(work, skey->des3.dk[2]);
    STORE32H(work[0],pt+0);
    STORE32H(work[1],pt+4);
    return CRYPT_OK;
}

static const struct ltc_cipher_descriptor des3_desc =
{
    "3des", 8,
    &des3_setup,
    &des3_ecb_encrypt,
    &des3_ecb_decrypt,
};

/* a simple macro for making hash "process" functions */
#define HASH_PROCESS(func_name, compress_name, state_var, block_size)                       \
int func_name (hash_state * md, const unsigned char *in, unsigned long inlen)               \
{                                                                                           \
    unsigned long n;                                                                        \
    int           err;                                                                      \
    if (md-> state_var .curlen > sizeof(md-> state_var .buf))                               \
       return CRYPT_INVALID_ARG;                                                            \
    while (inlen > 0) {                                                                     \
	if (md-> state_var .curlen == 0 && inlen >= block_size) {                           \
	   if ((err = compress_name (md, (unsigned char *)in)) != CRYPT_OK) {               \
	      return err;                                                                   \
	   }                                                                                \
	   md-> state_var .length += block_size * 8;                                        \
	   in             += block_size;                                                    \
	   inlen          -= block_size;                                                    \
	} else {                                                                            \
	   n = MIN(inlen, (block_size - md-> state_var .curlen));                           \
	   memcpy(md-> state_var .buf + md-> state_var.curlen, in, (size_t)n);              \
	   md-> state_var .curlen += n;                                                     \
	   in             += n;                                                             \
	   inlen          -= n;                                                             \
	   if (md-> state_var .curlen == block_size) {                                      \
	      if ((err = compress_name (md, md-> state_var .buf)) != CRYPT_OK) {            \
		 return err;                                                                \
	      }                                                                             \
	      md-> state_var .length += 8*block_size;                                       \
	      md-> state_var .curlen = 0;                                                   \
	   }                                                                                \
       }                                                                                    \
    }                                                                                       \
    return CRYPT_OK;                                                                        \
}
/** MD5 hash function by Tom St Denis */

#define F(x,y,z)  (z ^ (x & (y ^ z)))
#define G(x,y,z)  (y ^ (z & (y ^ x)))
#define H(x,y,z)  (x^y^z)
#define I(x,y,z)  (y^(x|(~z)))

#ifdef LTC_SMALL_CODE

#define FF(a,b,c,d,M,s,t) \
    a = (a + F(b,c,d) + M + t); a = ROL(a, s) + b;

#define GG(a,b,c,d,M,s,t) \
    a = (a + G(b,c,d) + M + t); a = ROL(a, s) + b;

#define HH(a,b,c,d,M,s,t) \
    a = (a + H(b,c,d) + M + t); a = ROL(a, s) + b;

#define II(a,b,c,d,M,s,t) \
    a = (a + I(b,c,d) + M + t); a = ROL(a, s) + b;

static const unsigned char Worder[64] = {
   0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
   1,6,11,0,5,10,15,4,9,14,3,8,13,2,7,12,
   5,8,11,14,1,4,7,10,13,0,3,6,9,12,15,2,
   0,7,14,5,12,3,10,1,8,15,6,13,4,11,2,9
};

static const unsigned char Rorder[64] = {
   7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
   5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
   4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
   6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21
};

static const ulong32 Korder[64] = {
0xd76aa478UL, 0xe8c7b756UL, 0x242070dbUL, 0xc1bdceeeUL, 0xf57c0fafUL, 0x4787c62aUL, 0xa8304613UL, 0xfd469501UL,
0x698098d8UL, 0x8b44f7afUL, 0xffff5bb1UL, 0x895cd7beUL, 0x6b901122UL, 0xfd987193UL, 0xa679438eUL, 0x49b40821UL,
0xf61e2562UL, 0xc040b340UL, 0x265e5a51UL, 0xe9b6c7aaUL, 0xd62f105dUL, 0x02441453UL, 0xd8a1e681UL, 0xe7d3fbc8UL,
0x21e1cde6UL, 0xc33707d6UL, 0xf4d50d87UL, 0x455a14edUL, 0xa9e3e905UL, 0xfcefa3f8UL, 0x676f02d9UL, 0x8d2a4c8aUL,
0xfffa3942UL, 0x8771f681UL, 0x6d9d6122UL, 0xfde5380cUL, 0xa4beea44UL, 0x4bdecfa9UL, 0xf6bb4b60UL, 0xbebfbc70UL,
0x289b7ec6UL, 0xeaa127faUL, 0xd4ef3085UL, 0x04881d05UL, 0xd9d4d039UL, 0xe6db99e5UL, 0x1fa27cf8UL, 0xc4ac5665UL,
0xf4292244UL, 0x432aff97UL, 0xab9423a7UL, 0xfc93a039UL, 0x655b59c3UL, 0x8f0ccc92UL, 0xffeff47dUL, 0x85845dd1UL,
0x6fa87e4fUL, 0xfe2ce6e0UL, 0xa3014314UL, 0x4e0811a1UL, 0xf7537e82UL, 0xbd3af235UL, 0x2ad7d2bbUL, 0xeb86d391UL
};

#else

#define FF(a,b,c,d,M,s,t) \
    a = (a + F(b,c,d) + M + t); a = ROLc(a, s) + b;

#define GG(a,b,c,d,M,s,t) \
    a = (a + G(b,c,d) + M + t); a = ROLc(a, s) + b;

#define HH(a,b,c,d,M,s,t) \
    a = (a + H(b,c,d) + M + t); a = ROLc(a, s) + b;

#define II(a,b,c,d,M,s,t) \
    a = (a + I(b,c,d) + M + t); a = ROLc(a, s) + b;


#endif

static int  md5_compress(hash_state *md, unsigned char *buf)
{
    ulong32 i, W[16], a, b, c, d;
#ifdef LTC_SMALL_CODE
    ulong32 t;
#endif

    /* copy the state into 512-bits into W[0..15] */
    for (i = 0; i < 16; i++) {
	LOAD32L(W[i], buf + (4*i));
    }

    /* copy state */
    a = md->md5.state[0];
    b = md->md5.state[1];
    c = md->md5.state[2];
    d = md->md5.state[3];

#ifdef LTC_SMALL_CODE
    for (i = 0; i < 16; ++i) {
	FF(a,b,c,d,W[Worder[i]],Rorder[i],Korder[i]);
	t = d; d = c; c = b; b = a; a = t;
    }

    for (; i < 32; ++i) {
	GG(a,b,c,d,W[Worder[i]],Rorder[i],Korder[i]);
	t = d; d = c; c = b; b = a; a = t;
    }

    for (; i < 48; ++i) {
	HH(a,b,c,d,W[Worder[i]],Rorder[i],Korder[i]);
	t = d; d = c; c = b; b = a; a = t;
    }

    for (; i < 64; ++i) {
	II(a,b,c,d,W[Worder[i]],Rorder[i],Korder[i]);
	t = d; d = c; c = b; b = a; a = t;
    }

#else
    FF(a,b,c,d,W[0],7,0xd76aa478UL)
    FF(d,a,b,c,W[1],12,0xe8c7b756UL)
    FF(c,d,a,b,W[2],17,0x242070dbUL)
    FF(b,c,d,a,W[3],22,0xc1bdceeeUL)
    FF(a,b,c,d,W[4],7,0xf57c0fafUL)
    FF(d,a,b,c,W[5],12,0x4787c62aUL)
    FF(c,d,a,b,W[6],17,0xa8304613UL)
    FF(b,c,d,a,W[7],22,0xfd469501UL)
    FF(a,b,c,d,W[8],7,0x698098d8UL)
    FF(d,a,b,c,W[9],12,0x8b44f7afUL)
    FF(c,d,a,b,W[10],17,0xffff5bb1UL)
    FF(b,c,d,a,W[11],22,0x895cd7beUL)
    FF(a,b,c,d,W[12],7,0x6b901122UL)
    FF(d,a,b,c,W[13],12,0xfd987193UL)
    FF(c,d,a,b,W[14],17,0xa679438eUL)
    FF(b,c,d,a,W[15],22,0x49b40821UL)
    GG(a,b,c,d,W[1],5,0xf61e2562UL)
    GG(d,a,b,c,W[6],9,0xc040b340UL)
    GG(c,d,a,b,W[11],14,0x265e5a51UL)
    GG(b,c,d,a,W[0],20,0xe9b6c7aaUL)
    GG(a,b,c,d,W[5],5,0xd62f105dUL)
    GG(d,a,b,c,W[10],9,0x02441453UL)
    GG(c,d,a,b,W[15],14,0xd8a1e681UL)
    GG(b,c,d,a,W[4],20,0xe7d3fbc8UL)
    GG(a,b,c,d,W[9],5,0x21e1cde6UL)
    GG(d,a,b,c,W[14],9,0xc33707d6UL)
    GG(c,d,a,b,W[3],14,0xf4d50d87UL)
    GG(b,c,d,a,W[8],20,0x455a14edUL)
    GG(a,b,c,d,W[13],5,0xa9e3e905UL)
    GG(d,a,b,c,W[2],9,0xfcefa3f8UL)
    GG(c,d,a,b,W[7],14,0x676f02d9UL)
    GG(b,c,d,a,W[12],20,0x8d2a4c8aUL)
    HH(a,b,c,d,W[5],4,0xfffa3942UL)
    HH(d,a,b,c,W[8],11,0x8771f681UL)
    HH(c,d,a,b,W[11],16,0x6d9d6122UL)
    HH(b,c,d,a,W[14],23,0xfde5380cUL)
    HH(a,b,c,d,W[1],4,0xa4beea44UL)
    HH(d,a,b,c,W[4],11,0x4bdecfa9UL)
    HH(c,d,a,b,W[7],16,0xf6bb4b60UL)
    HH(b,c,d,a,W[10],23,0xbebfbc70UL)
    HH(a,b,c,d,W[13],4,0x289b7ec6UL)
    HH(d,a,b,c,W[0],11,0xeaa127faUL)
    HH(c,d,a,b,W[3],16,0xd4ef3085UL)
    HH(b,c,d,a,W[6],23,0x04881d05UL)
    HH(a,b,c,d,W[9],4,0xd9d4d039UL)
    HH(d,a,b,c,W[12],11,0xe6db99e5UL)
    HH(c,d,a,b,W[15],16,0x1fa27cf8UL)
    HH(b,c,d,a,W[2],23,0xc4ac5665UL)
    II(a,b,c,d,W[0],6,0xf4292244UL)
    II(d,a,b,c,W[7],10,0x432aff97UL)
    II(c,d,a,b,W[14],15,0xab9423a7UL)
    II(b,c,d,a,W[5],21,0xfc93a039UL)
    II(a,b,c,d,W[12],6,0x655b59c3UL)
    II(d,a,b,c,W[3],10,0x8f0ccc92UL)
    II(c,d,a,b,W[10],15,0xffeff47dUL)
    II(b,c,d,a,W[1],21,0x85845dd1UL)
    II(a,b,c,d,W[8],6,0x6fa87e4fUL)
    II(d,a,b,c,W[15],10,0xfe2ce6e0UL)
    II(c,d,a,b,W[6],15,0xa3014314UL)
    II(b,c,d,a,W[13],21,0x4e0811a1UL)
    II(a,b,c,d,W[4],6,0xf7537e82UL)
    II(d,a,b,c,W[11],10,0xbd3af235UL)
    II(c,d,a,b,W[2],15,0x2ad7d2bbUL)
    II(b,c,d,a,W[9],21,0xeb86d391UL)
#endif

    md->md5.state[0] = md->md5.state[0] + a;
    md->md5.state[1] = md->md5.state[1] + b;
    md->md5.state[2] = md->md5.state[2] + c;
    md->md5.state[3] = md->md5.state[3] + d;

    return CRYPT_OK;
}

/**
   Initialize the hash state
   @param md   The hash state you wish to initialize
   @return CRYPT_OK if successful
*/
static int md5_init(hash_state * md)
{
   md->md5.state[0] = 0x67452301UL;
   md->md5.state[1] = 0xefcdab89UL;
   md->md5.state[2] = 0x98badcfeUL;
   md->md5.state[3] = 0x10325476UL;
   md->md5.curlen = 0;
   md->md5.length = 0;
   return CRYPT_OK;
}

/**
   Process a block of memory though the hash
   @param md     The hash state
   @param in     The data to hash
   @param inlen  The length of the data (octets)
   @return CRYPT_OK if successful
*/
static HASH_PROCESS(md5_process, md5_compress, md5, 64)

/**
   Terminate the hash to get the digest
   @param md  The hash state
   @param out [out] The destination of the hash (16 bytes)
   @return CRYPT_OK if successful
*/
static int md5_done(hash_state * md, unsigned char *out)
{
    int i;

    if (md->md5.curlen >= sizeof(md->md5.buf))
       return CRYPT_INVALID_ARG;


    /* increase the length of the message */
    md->md5.length += md->md5.curlen * 8;

    /* append the '1' bit */
    md->md5.buf[md->md5.curlen++] = (unsigned char)0x80;

    /* if the length is currently above 56 bytes we append zeros
     * then compress.  Then we can fall back to padding zeros and length
     * encoding like normal.
     */
    if (md->md5.curlen > 56) {
	while (md->md5.curlen < 64) {
	    md->md5.buf[md->md5.curlen++] = (unsigned char)0;
	}
	md5_compress(md, md->md5.buf);
	md->md5.curlen = 0;
    }

    /* pad upto 56 bytes of zeroes */
    while (md->md5.curlen < 56) {
	md->md5.buf[md->md5.curlen++] = (unsigned char)0;
    }

    /* store length */
    STORE64L(md->md5.length, md->md5.buf+56);
    md5_compress(md, md->md5.buf);

    /* copy output */
    for (i = 0; i < 4; i++) {
	STORE32L(md->md5.state[i], out+(4*i));
    }
    return CRYPT_OK;
}

/* MD5 hash function by Tom St Denis */
static const struct ltc_hash_descriptor md5_desc =
{
    "md5",
    16,
    64,
    &md5_init,
    &md5_process,
    &md5_done
};


/* SHA1 code by Tom St Denis */


#define F0(x,y,z)  (z ^ (x & (y ^ z)))
#define F1(x,y,z)  (x ^ y ^ z)
#define F2(x,y,z)  ((x & y) | (z & (x | y)))
#define F3(x,y,z)  (x ^ y ^ z)

static int  sha1_compress(hash_state *md, unsigned char *buf)
{
    ulong32 a,b,c,d,e,W[80],i;
#ifdef LTC_SMALL_CODE
    ulong32 t;
#endif

    /* copy the state into 512-bits into W[0..15] */
    for (i = 0; i < 16; i++) {
	LOAD32H(W[i], buf + (4*i));
    }

    /* copy state */
    a = md->sha1.state[0];
    b = md->sha1.state[1];
    c = md->sha1.state[2];
    d = md->sha1.state[3];
    e = md->sha1.state[4];

    /* expand it */
    for (i = 16; i < 80; i++) {
	W[i] = ROL(W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16], 1);
    }

    /* compress */
    /* round one */
    #define SHA1_FF0(a,b,c,d,e,i) e = (ROLc(a, 5) + F0(b,c,d) + e + W[i] + 0x5a827999UL); b = ROLc(b, 30);
    #define SHA1_FF1(a,b,c,d,e,i) e = (ROLc(a, 5) + F1(b,c,d) + e + W[i] + 0x6ed9eba1UL); b = ROLc(b, 30);
    #define SHA1_FF2(a,b,c,d,e,i) e = (ROLc(a, 5) + F2(b,c,d) + e + W[i] + 0x8f1bbcdcUL); b = ROLc(b, 30);
    #define SHA1_FF3(a,b,c,d,e,i) e = (ROLc(a, 5) + F3(b,c,d) + e + W[i] + 0xca62c1d6UL); b = ROLc(b, 30);

#ifdef LTC_SMALL_CODE

    for (i = 0; i < 20; ) {
       SHA1_FF0(a,b,c,d,e,i++); t = e; e = d; d = c; c = b; b = a; a = t;
    }

    for (; i < 40; ) {
       SHA1_FF1(a,b,c,d,e,i++); t = e; e = d; d = c; c = b; b = a; a = t;
    }

    for (; i < 60; ) {
       SHA1_FF2(a,b,c,d,e,i++); t = e; e = d; d = c; c = b; b = a; a = t;
    }

    for (; i < 80; ) {
       SHA1_FF3(a,b,c,d,e,i++); t = e; e = d; d = c; c = b; b = a; a = t;
    }

#else

    for (i = 0; i < 20; ) {
       SHA1_FF0(a,b,c,d,e,i++);
       SHA1_FF0(e,a,b,c,d,i++);
       SHA1_FF0(d,e,a,b,c,i++);
       SHA1_FF0(c,d,e,a,b,i++);
       SHA1_FF0(b,c,d,e,a,i++);
    }

    /* round two */
    for (; i < 40; )  {
       SHA1_FF1(a,b,c,d,e,i++);
       SHA1_FF1(e,a,b,c,d,i++);
       SHA1_FF1(d,e,a,b,c,i++);
       SHA1_FF1(c,d,e,a,b,i++);
       SHA1_FF1(b,c,d,e,a,i++);
    }

    /* round three */
    for (; i < 60; )  {
       SHA1_FF2(a,b,c,d,e,i++);
       SHA1_FF2(e,a,b,c,d,i++);
       SHA1_FF2(d,e,a,b,c,i++);
       SHA1_FF2(c,d,e,a,b,i++);
       SHA1_FF2(b,c,d,e,a,i++);
    }

    /* round four */
    for (; i < 80; )  {
       SHA1_FF3(a,b,c,d,e,i++);
       SHA1_FF3(e,a,b,c,d,i++);
       SHA1_FF3(d,e,a,b,c,i++);
       SHA1_FF3(c,d,e,a,b,i++);
       SHA1_FF3(b,c,d,e,a,i++);
    }
#endif

    /* store */
    md->sha1.state[0] = md->sha1.state[0] + a;
    md->sha1.state[1] = md->sha1.state[1] + b;
    md->sha1.state[2] = md->sha1.state[2] + c;
    md->sha1.state[3] = md->sha1.state[3] + d;
    md->sha1.state[4] = md->sha1.state[4] + e;

    return CRYPT_OK;
}

/**
   Initialize the hash state
   @param md   The hash state you wish to initialize
   @return CRYPT_OK if successful
*/
static int sha1_init(hash_state * md)
{
   md->sha1.state[0] = 0x67452301UL;
   md->sha1.state[1] = 0xefcdab89UL;
   md->sha1.state[2] = 0x98badcfeUL;
   md->sha1.state[3] = 0x10325476UL;
   md->sha1.state[4] = 0xc3d2e1f0UL;
   md->sha1.curlen = 0;
   md->sha1.length = 0;
   return CRYPT_OK;
}

/**
   Process a block of memory though the hash
   @param md     The hash state
   @param in     The data to hash
   @param inlen  The length of the data (octets)
   @return CRYPT_OK if successful
*/
static HASH_PROCESS(sha1_process, sha1_compress, sha1, 64)

/**
   Terminate the hash to get the digest
   @param md  The hash state
   @param out [out] The destination of the hash (20 bytes)
   @return CRYPT_OK if successful
*/
static int sha1_done(hash_state * md, unsigned char *out)
{
    int i;

    if (md->sha1.curlen >= sizeof(md->sha1.buf))
       return CRYPT_INVALID_ARG;

    /* increase the length of the message */
    md->sha1.length += md->sha1.curlen * 8;

    /* append the '1' bit */
    md->sha1.buf[md->sha1.curlen++] = (unsigned char)0x80;

    /* if the length is currently above 56 bytes we append zeros
     * then compress.  Then we can fall back to padding zeros and length
     * encoding like normal.
     */
    if (md->sha1.curlen > 56) {
	while (md->sha1.curlen < 64) {
	    md->sha1.buf[md->sha1.curlen++] = (unsigned char)0;
	}
	sha1_compress(md, md->sha1.buf);
	md->sha1.curlen = 0;
    }

    /* pad upto 56 bytes of zeroes */
    while (md->sha1.curlen < 56) {
	md->sha1.buf[md->sha1.curlen++] = (unsigned char)0;
    }

    /* store length */
    STORE64H(md->sha1.length, md->sha1.buf+56);
    sha1_compress(md, md->sha1.buf);

    /* copy output */
    for (i = 0; i < 5; i++) {
	STORE32H(md->sha1.state[i], out+(4*i));
    }
    return CRYPT_OK;
}

static const struct ltc_hash_descriptor sha1_desc =
{
    "sha1",
    20,
    64,
    &sha1_init,
    &sha1_process,
    &sha1_done
};

/* the two polynomials */
#define MDS_POLY          0x169
#define RS_POLY           0x14D

/* The 4x8 RS Linear Transform */
static const unsigned char RS[4][8] = {
    { 0x01, 0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E },
    { 0xA4, 0x56, 0x82, 0xF3, 0X1E, 0XC6, 0X68, 0XE5 },
    { 0X02, 0XA1, 0XFC, 0XC1, 0X47, 0XAE, 0X3D, 0X19 },
    { 0XA4, 0X55, 0X87, 0X5A, 0X58, 0XDB, 0X9E, 0X03 }
};

/* sbox usage orderings */
static const unsigned char qord[4][5] = {
   { 1, 1, 0, 0, 1 },
   { 0, 1, 1, 0, 0 },
   { 0, 0, 0, 1, 1 },
   { 1, 0, 1, 1, 0 }
};

/* The Q-box tables */
static const unsigned char qbox[2][4][16] = {
{
   { 0x8, 0x1, 0x7, 0xD, 0x6, 0xF, 0x3, 0x2, 0x0, 0xB, 0x5, 0x9, 0xE, 0xC, 0xA, 0x4 },
   { 0xE, 0XC, 0XB, 0X8, 0X1, 0X2, 0X3, 0X5, 0XF, 0X4, 0XA, 0X6, 0X7, 0X0, 0X9, 0XD },
   { 0XB, 0XA, 0X5, 0XE, 0X6, 0XD, 0X9, 0X0, 0XC, 0X8, 0XF, 0X3, 0X2, 0X4, 0X7, 0X1 },
   { 0XD, 0X7, 0XF, 0X4, 0X1, 0X2, 0X6, 0XE, 0X9, 0XB, 0X3, 0X0, 0X8, 0X5, 0XC, 0XA }
},
{
   { 0X2, 0X8, 0XB, 0XD, 0XF, 0X7, 0X6, 0XE, 0X3, 0X1, 0X9, 0X4, 0X0, 0XA, 0XC, 0X5 },
   { 0X1, 0XE, 0X2, 0XB, 0X4, 0XC, 0X3, 0X7, 0X6, 0XD, 0XA, 0X5, 0XF, 0X9, 0X0, 0X8 },
   { 0X4, 0XC, 0X7, 0X5, 0X1, 0X6, 0X9, 0XA, 0X0, 0XE, 0XD, 0X8, 0X2, 0XB, 0X3, 0XF },
   { 0xB, 0X9, 0X5, 0X1, 0XC, 0X3, 0XD, 0XE, 0X6, 0X4, 0X7, 0XF, 0X2, 0X0, 0X8, 0XA }
}
};

/* computes S_i[x] */
static ulong32 sbox(int i, ulong32 x)
{
   unsigned char a0,b0,a1,b1,a2,b2,a3,b3,a4,b4,y;

   /* a0,b0 = [x/16], x mod 16 */
   a0 = (unsigned char)((x>>4)&15);
   b0 = (unsigned char)((x)&15);

   /* a1 = a0 ^ b0 */
   a1 = a0 ^ b0;

   /* b1 = a0 ^ ROR(b0, 1) ^ 8a0 */
   b1 = (a0 ^ ((b0<<3)|(b0>>1)) ^ (a0<<3)) & 15;

   /* a2,b2 = t0[a1], t1[b1] */
   a2 = qbox[i][0][(int)a1];
   b2 = qbox[i][1][(int)b1];

   /* a3 = a2 ^ b2 */
   a3 = a2 ^ b2;

   /* b3 = a2 ^ ROR(b2, 1) ^ 8a2 */
   b3 = (a2 ^ ((b2<<3)|(b2>>1)) ^ (a2<<3)) & 15;

   /* a4,b4 = t2[a3], t3[b3] */
   a4 = qbox[i][2][(int)a3];
   b4 = qbox[i][3][(int)b3];

   /* y = 16b4 + a4 */
   y = (b4 << 4) + a4;

   /* return result */
   return (ulong32)y;
}

/* computes ab mod p */
static ulong32 gf_mult(ulong32 a, ulong32 b, ulong32 p)
{
   ulong32 result, B[2], P[2];

   P[1] = p;
   B[1] = b;
   result = P[0] = B[0] = 0;

   /* unrolled branchless GF multiplier */
   result ^= B[a&1]; a >>= 1;  B[1] = P[B[1]>>7] ^ (B[1] << 1);
   result ^= B[a&1]; a >>= 1;  B[1] = P[B[1]>>7] ^ (B[1] << 1);
   result ^= B[a&1]; a >>= 1;  B[1] = P[B[1]>>7] ^ (B[1] << 1);
   result ^= B[a&1]; a >>= 1;  B[1] = P[B[1]>>7] ^ (B[1] << 1);
   result ^= B[a&1]; a >>= 1;  B[1] = P[B[1]>>7] ^ (B[1] << 1);
   result ^= B[a&1]; a >>= 1;  B[1] = P[B[1]>>7] ^ (B[1] << 1);
   result ^= B[a&1]; a >>= 1;  B[1] = P[B[1]>>7] ^ (B[1] << 1);
   result ^= B[a&1];

   return result;
}

/* computes [y0 y1 y2 y3] = MDS . [x0] */
static ulong32 mds_column_mult(unsigned char in, int col)
{
   ulong32 x01, x5B, xEF;

   x01 = in;
   x5B = gf_mult(in, 0x5B, MDS_POLY);
   xEF = gf_mult(in, 0xEF, MDS_POLY);

   switch (col) {
       case 0:
	  return (x01 << 0 ) |
		 (x5B << 8 ) |
		 (xEF << 16) |
		 (xEF << 24);
       case 1:
	  return (xEF << 0 ) |
		 (xEF << 8 ) |
		 (x5B << 16) |
		 (x01 << 24);
       case 2:
	  return (x5B << 0 ) |
		 (xEF << 8 ) |
		 (x01 << 16) |
		 (xEF << 24);
       case 3:
	  return (x5B << 0 ) |
		 (x01 << 8 ) |
		 (xEF << 16) |
		 (x5B << 24);
   }
   /* avoid warnings, we'd never get here normally but just to calm compiler warnings... */
   return 0;
}

/* Computes [y0 y1 y2 y3] = MDS . [x0 x1 x2 x3] */
static void mds_mult(const unsigned char *in, unsigned char *out)
{
  int x;
  ulong32 tmp;
  for (tmp = x = 0; x < 4; x++) {
      tmp ^= mds_column_mult(in[x], x);
  }
  STORE32L(tmp, out);
}

/* computes [y0 y1 y2 y3] = RS . [x0 x1 x2 x3 x4 x5 x6 x7] */
static void rs_mult(const unsigned char *in, unsigned char *out)
{
  int x, y;
  for (x = 0; x < 4; x++) {
      out[x] = 0;
      for (y = 0; y < 8; y++) {
	  out[x] ^= gf_mult(in[y], RS[x][y], RS_POLY);
      }
  }
}

/* computes h(x) */
static void h_func(const unsigned char *in, unsigned char *out, unsigned char *M, int k, int offset)
{
  int x;
  unsigned char y[4];
  for (x = 0; x < 4; x++) {
      y[x] = in[x];
 }
  switch (k) {
     case 4:
	    y[0] = (unsigned char)(sbox(1, (ulong32)y[0]) ^ M[4 * (6 + offset) + 0]);
	    y[1] = (unsigned char)(sbox(0, (ulong32)y[1]) ^ M[4 * (6 + offset) + 1]);
	    y[2] = (unsigned char)(sbox(0, (ulong32)y[2]) ^ M[4 * (6 + offset) + 2]);
	    y[3] = (unsigned char)(sbox(1, (ulong32)y[3]) ^ M[4 * (6 + offset) + 3]);
     case 3:
	    y[0] = (unsigned char)(sbox(1, (ulong32)y[0]) ^ M[4 * (4 + offset) + 0]);
	    y[1] = (unsigned char)(sbox(1, (ulong32)y[1]) ^ M[4 * (4 + offset) + 1]);
	    y[2] = (unsigned char)(sbox(0, (ulong32)y[2]) ^ M[4 * (4 + offset) + 2]);
	    y[3] = (unsigned char)(sbox(0, (ulong32)y[3]) ^ M[4 * (4 + offset) + 3]);
     case 2:
	    y[0] = (unsigned char)(sbox(1, sbox(0, sbox(0, (ulong32)y[0]) ^ M[4 * (2 + offset) + 0]) ^ M[4 * (0 + offset) + 0]));
	    y[1] = (unsigned char)(sbox(0, sbox(0, sbox(1, (ulong32)y[1]) ^ M[4 * (2 + offset) + 1]) ^ M[4 * (0 + offset) + 1]));
	    y[2] = (unsigned char)(sbox(1, sbox(1, sbox(0, (ulong32)y[2]) ^ M[4 * (2 + offset) + 2]) ^ M[4 * (0 + offset) + 2]));
	    y[3] = (unsigned char)(sbox(0, sbox(1, sbox(1, (ulong32)y[3]) ^ M[4 * (2 + offset) + 3]) ^ M[4 * (0 + offset) + 3]));
  }
  mds_mult(y, out);
}

static ulong32 g_func(ulong32 x, symmetric_key *key)
{
   unsigned char g, i, y, z;
   ulong32 res;

   res = 0;
   for (y = 0; y < 4; y++) {
       z = key->twofish.start;

       /* do unkeyed substitution */
       g = sbox(qord[y][z++], (x >> (8*y)) & 255);

       /* first subkey */
       i = 0;

       /* do key mixing+sbox until z==5 */
       while (z != 5) {
	  g = g ^ key->twofish.S[4*i++ + y];
	  g = sbox(qord[y][z++], g);
       }

       /* multiply g by a column of the MDS */
       res ^= mds_column_mult(g, y);
   }
   return res;
}

#define g1_func(x, key) g_func(ROLc(x, 8), key)

/**
    Initialize the Twofish block cipher
    @param key The symmetric key you wish to pass
    @param keylen The key length in bytes
    @param num_rounds The number of rounds desired (0 for default)
    @param skey The key in as scheduled by this function.
    @return CRYPT_OK if successful
 */
static int twofish_setup(const unsigned char *key, int keylen, int num_rounds, symmetric_key *skey)
{
   int k, x, y;
   unsigned char tmp[4], tmp2[4], M[8*4];
   ulong32 A, B;

   /* invalid arguments? */
   if (num_rounds != 16 && num_rounds != 0)
      return CRYPT_INVALID_ROUNDS;

   if (keylen != 16 && keylen != 24 && keylen != 32)
      return CRYPT_INVALID_KEYSIZE;

   /* k = keysize/64 [but since our keysize is in bytes...] */
   k = keylen / 8;

   /* copy the key into M */
   for (x = 0; x < keylen; x++) {
       M[x] = key[x] & 255;
   }

   /* create the S[..] words */
   for (x = 0; x < k; x++) {
       rs_mult(M+(x*8), skey->twofish.S+(x*4));
   }

   /* make subkeys */
   for (x = 0; x < 20; x++) {
       /* A = h(p * 2x, Me) */
       for (y = 0; y < 4; y++) {
	   tmp[y] = x+x;
       }
       h_func(tmp, tmp2, M, k, 0);
       LOAD32L(A, tmp2);

       /* B = ROL(h(p * (2x + 1), Mo), 8) */
       for (y = 0; y < 4; y++) {
	   tmp[y] = (unsigned char)(x+x+1);
       }
       h_func(tmp, tmp2, M, k, 1);
       LOAD32L(B, tmp2);
       B = ROLc(B, 8);

       /* K[2i]   = A + B */
       skey->twofish.K[x+x] = (A + B) & 0xFFFFFFFFUL;

       /* K[2i+1] = (A + 2B) <<< 9 */
       skey->twofish.K[x+x+1] = ROLc(B + B + A, 9);
   }

   /* where to start in the sbox layers */
   /* small ram variant */
   switch (k) {
	 case 4 : skey->twofish.start = 0; break;
	 case 3 : skey->twofish.start = 1; break;
	 default: skey->twofish.start = 2; break;
   }
   return CRYPT_OK;
}

/**
  Encrypts a block of text with Twofish
  @param pt The input plaintext (16 bytes)
  @param ct The output ciphertext (16 bytes)
  @param skey The key as scheduled
  @return CRYPT_OK if successful
*/
static int twofish_ecb_encrypt(const unsigned char *pt, unsigned char *ct, symmetric_key *skey)
{
    ulong32 a,b,c,d,ta,tb,tc,td,t1,t2, *k;
    int r;

    LOAD32L(a,&pt[0]); LOAD32L(b,&pt[4]);
    LOAD32L(c,&pt[8]); LOAD32L(d,&pt[12]);
    a ^= skey->twofish.K[0];
    b ^= skey->twofish.K[1];
    c ^= skey->twofish.K[2];
    d ^= skey->twofish.K[3];

    k  = skey->twofish.K + 8;
    for (r = 8; r != 0; --r) {
	t2 = g1_func(b, skey);
	t1 = g_func(a, skey) + t2;
	c  = RORc(c ^ (t1 + k[0]), 1);
	d  = ROLc(d, 1) ^ (t2 + t1 + k[1]);

	t2 = g1_func(d, skey);
	t1 = g_func(c, skey) + t2;
	a  = RORc(a ^ (t1 + k[2]), 1);
	b  = ROLc(b, 1) ^ (t2 + t1 + k[3]);
	k += 4;
   }

    /* output with "undo last swap" */
    ta = c ^ skey->twofish.K[4];
    tb = d ^ skey->twofish.K[5];
    tc = a ^ skey->twofish.K[6];
    td = b ^ skey->twofish.K[7];

    /* store output */
    STORE32L(ta,&ct[0]); STORE32L(tb,&ct[4]);
    STORE32L(tc,&ct[8]); STORE32L(td,&ct[12]);

    return CRYPT_OK;
}

/**
  Decrypts a block of text with Twofish
  @param ct The input ciphertext (16 bytes)
  @param pt The output plaintext (16 bytes)
  @param skey The key as scheduled
  @return CRYPT_OK if successful
*/
static int twofish_ecb_decrypt(const unsigned char *ct, unsigned char *pt, symmetric_key *skey)
{
    ulong32 a,b,c,d,ta,tb,tc,td,t1,t2, *k;
    int r;

    /* load input */
    LOAD32L(ta,&ct[0]); LOAD32L(tb,&ct[4]);
    LOAD32L(tc,&ct[8]); LOAD32L(td,&ct[12]);

    /* undo undo final swap */
    a = tc ^ skey->twofish.K[6];
    b = td ^ skey->twofish.K[7];
    c = ta ^ skey->twofish.K[4];
    d = tb ^ skey->twofish.K[5];

    k = skey->twofish.K + 36;
    for (r = 8; r != 0; --r) {
	t2 = g1_func(d, skey);
	t1 = g_func(c, skey) + t2;
	a = ROLc(a, 1) ^ (t1 + k[2]);
	b = RORc(b ^ (t2 + t1 + k[3]), 1);

	t2 = g1_func(b, skey);
	t1 = g_func(a, skey) + t2;
	c = ROLc(c, 1) ^ (t1 + k[0]);
	d = RORc(d ^ (t2 +  t1 + k[1]), 1);
	k -= 4;
    }

    /* pre-white */
    a ^= skey->twofish.K[0];
    b ^= skey->twofish.K[1];
    c ^= skey->twofish.K[2];
    d ^= skey->twofish.K[3];

    /* store */
    STORE32L(a, &pt[0]); STORE32L(b, &pt[4]);
    STORE32L(c, &pt[8]); STORE32L(d, &pt[12]);
    return CRYPT_OK;
}

/* Implementation of Twofish by Tom St Denis */
static const struct ltc_cipher_descriptor twofish_desc =
{
    "twofish", 16,
    &twofish_setup,
    &twofish_ecb_encrypt,
    &twofish_ecb_decrypt,
};


/* Stores the cipher descriptor table, Tom St Denis */
static struct ltc_cipher_descriptor cipher_descriptor[TOMCRYPT_TAB_SIZE] = {
#ifdef DROPBEAR_AES
  { "aes", 16, rijndael_setup, rijndael_ecb_encrypt, rijndael_ecb_decrypt },
#endif
#ifdef DROPBEAR_TWOFISH
  { "twofish", 16, &twofish_setup, &twofish_ecb_encrypt, &twofish_ecb_decrypt },
#endif
#ifdef DROPBEAR_3DES
  { "3des", 8, &des3_setup, &des3_ecb_encrypt, &des3_ecb_decrypt },
#endif
};

/**
  Stores the hash descriptor table, Tom St Denis
*/
static struct ltc_hash_descriptor hash_descriptor[TOMCRYPT_TAB_SIZE] = {
  { "sha1", 20, 64, &sha1_init, &sha1_process, &sha1_done },
#ifdef DROPBEAR_MD5_HMAC
  { "md5", 16, 64, &md5_init, &md5_process, &md5_done },
#endif
};

/*
  Determine if cipher is valid, Tom St Denis
   @param idx   The index of the cipher to search for
   @return CRYPT_OK if valid
*/
static int cipher_is_valid(int idx)
{
   if (idx < 0 || idx >= TOMCRYPT_TAB_SIZE || cipher_descriptor[idx].name == NULL)
      return CRYPT_INVALID_CIPHER;
   return CRYPT_OK;
}

/**
   CBC implementation, encrypt block, Tom St Denis
  @param ct     Ciphertext
  @param pt     [out] Plaintext
  @param len    The number of bytes to process (must be multiple of block length)
  @param cbc    CBC state
  @return CRYPT_OK if successful
*/
static int cbc_decrypt(const unsigned char *ct, unsigned char *pt, unsigned long len, symmetric_CBC *cbc)
{
   int x, err;
   unsigned char tmp[16];
#ifdef LTC_FAST
   LTC_FAST_TYPE tmpy;
#else
   unsigned char tmpy;
#endif

   if ((err = cipher_is_valid(cbc->cipher)) != CRYPT_OK)
	return err;

   /* is blocklen valid? */
   if (cbc->blocklen < 1 || cbc->blocklen > (int)sizeof(cbc->IV))
	return CRYPT_INVALID_ARG;

   if (len % cbc->blocklen)
	return CRYPT_INVALID_ARG;
#ifdef LTC_FAST
   if (cbc->blocklen % sizeof(LTC_FAST_TYPE))
	return CRYPT_INVALID_ARG;
#endif

   while (len) {
	/* decrypt */
	if ((err = cipher_descriptor[cbc->cipher].ecb_decrypt(ct, tmp, &cbc->key)) != CRYPT_OK)
		return err;

	 /* xor IV against plaintext */
#if defined(LTC_FAST)
	for (x = 0; x < cbc->blocklen; x += sizeof(LTC_FAST_TYPE)) {
	    tmpy = *((LTC_FAST_TYPE*)((unsigned char *)cbc->IV + x)) ^ *((LTC_FAST_TYPE*)((unsigned char *)tmp + x));
	    *((LTC_FAST_TYPE*)((unsigned char *)cbc->IV + x)) = *((LTC_FAST_TYPE*)((unsigned char *)ct + x));
	    *((LTC_FAST_TYPE*)((unsigned char *)pt + x)) = tmpy;
	}
#else
	for (x = 0; x < cbc->blocklen; x++) {
		tmpy       = tmp[x] ^ cbc->IV[x];
		cbc->IV[x] = ct[x];
		pt[x]      = tmpy;
	}
#endif

	ct  += cbc->blocklen;
	pt  += cbc->blocklen;
	len -= cbc->blocklen;
   }
   return CRYPT_OK;
}

/**
   CBC implementation, encrypt block, Tom St Denis
*/

/**
  CBC encrypt
  @param pt     Plaintext
  @param ct     [out] Ciphertext
  @param len    The number of bytes to process (must be multiple of block length)
  @param cbc    CBC state
  @return CRYPT_OK if successful
*/
static int cbc_encrypt(const unsigned char *pt, unsigned char *ct, unsigned long len, symmetric_CBC *cbc)
{
   int x, err;

   if ((err = cipher_is_valid(cbc->cipher)) != CRYPT_OK)
       return err;

   /* is blocklen valid? */
   if (cbc->blocklen < 1 || cbc->blocklen > (int)sizeof(cbc->IV))
      return CRYPT_INVALID_ARG;

   if (len % cbc->blocklen)
      return CRYPT_INVALID_ARG;
#ifdef LTC_FAST
   if (cbc->blocklen % sizeof(LTC_FAST_TYPE))
      return CRYPT_INVALID_ARG;
#endif

   while (len) {
	 /* xor IV against plaintext */
#if defined(LTC_FAST)
	for (x = 0; x < cbc->blocklen; x += sizeof(LTC_FAST_TYPE)) {
	    *((LTC_FAST_TYPE*)((unsigned char *)cbc->IV + x)) ^= *((LTC_FAST_TYPE*)((unsigned char *)pt + x));
	}
#else
	for (x = 0; x < cbc->blocklen; x++)
		cbc->IV[x] ^= pt[x];
#endif

	/* encrypt */
	if ((err = cipher_descriptor[cbc->cipher].ecb_encrypt(cbc->IV, ct, &cbc->key)) != CRYPT_OK) {
		return err;
	}

	/* store IV [ciphertext] for a future block */
#if defined(LTC_FAST)
	for (x = 0; x < cbc->blocklen; x += sizeof(LTC_FAST_TYPE)) {
	    *((LTC_FAST_TYPE*)((unsigned char *)cbc->IV + x)) = *((LTC_FAST_TYPE*)((unsigned char *)ct + x));
	}
#else
	for (x = 0; x < cbc->blocklen; x++)
		cbc->IV[x] = ct[x];
#endif

	ct  += cbc->blocklen;
	pt  += cbc->blocklen;
	len -= cbc->blocklen;
   }
   return CRYPT_OK;
}

/**
   CBC implementation, start chain, Tom St Denis
*/

/**
   Initialize a CBC context
   @param cipher      The index of the cipher desired
   @param IV          The initial vector
   @param key         The secret key
   @param keylen      The length of the secret key (octets)
   @param num_rounds  Number of rounds in the cipher desired (0 for default)
   @param cbc         The CBC state to initialize
   @return CRYPT_OK if successful
*/
static int cbc_start(int cipher, const unsigned char *IV, const unsigned char *key,
	      int keylen, int num_rounds, symmetric_CBC *cbc)
{
   int x, err;

   /* bad param? */
   if ((err = cipher_is_valid(cipher)) != CRYPT_OK)
      return err;

   /* setup cipher */
   if ((err = cipher_descriptor[cipher].setup(key, keylen, num_rounds, &cbc->key)) != CRYPT_OK)
      return err;

   /* copy IV */
   cbc->blocklen = cipher_descriptor[cipher].block_length;
   cbc->cipher   = cipher;
   for (x = 0; x < cbc->blocklen; x++)
       cbc->IV[x] = IV[x];
   return CRYPT_OK;
}


/**
  Find a cipher in the descriptor tables, Tom St Denis
   @param name   The name of the cipher to look for
   @return >= 0 if found, -1 if not present
*/
static int find_cipher(const char *name)
{
   int x;

   for (x = 0; x < TOMCRYPT_TAB_SIZE; x++) {
       if (cipher_descriptor[x].name != NULL && !strcmp(cipher_descriptor[x].name, name))
	  return x;
   }
   return -1;
}

/**
   Find a registered hash by name, Tom St Denis
   @param name   The name of the hash to look for
   @return >= 0 if found, -1 if not present
*/
static int find_hash(const char *name)
{
   int x;

   for (x = 0; x < TOMCRYPT_TAB_SIZE; x++) {
       if (hash_descriptor[x].name != NULL && strcmp(hash_descriptor[x].name, name) == 0)
	  return x;
   }
   return -1;
}

/**
  CTR implementation, encrypt data, Tom St Denis
  @param pt     Plaintext
  @param ct     [out] Ciphertext
  @param len    Length of plaintext (octets)
  @param ctr    CTR state
  @return CRYPT_OK if successful
*/
static int ctr_encrypt(const unsigned char *pt, unsigned char *ct, unsigned long len, symmetric_CTR *ctr)
{
   int x, err;

   if ((err = cipher_is_valid(ctr->cipher)) != CRYPT_OK)
       return err;

   /* is blocklen/padlen valid? */
   if (ctr->blocklen < 1 || ctr->blocklen > (int)sizeof(ctr->ctr) ||
       ctr->padlen   < 0 || ctr->padlen   > (int)sizeof(ctr->pad))
	return CRYPT_INVALID_ARG;

#ifdef LTC_FAST
   if (ctr->blocklen % sizeof(LTC_FAST_TYPE))
      return CRYPT_INVALID_ARG;
#endif

   while (len) {
      /* is the pad empty? */
      if (ctr->padlen == ctr->blocklen) {
	 /* increment counter */
	 if (ctr->mode == CTR_COUNTER_LITTLE_ENDIAN) {
	    /* little-endian */
	    for (x = 0; x < ctr->blocklen; x++) {
	       ctr->ctr[x] = (ctr->ctr[x] + (unsigned char)1) & (unsigned char)255;
	       if (ctr->ctr[x] != (unsigned char)0) {
		  break;
	       }
	    }
	 } else {
	    /* big-endian */
	    for (x = ctr->blocklen-1; x >= 0; x--) {
	       ctr->ctr[x] = (ctr->ctr[x] + (unsigned char)1) & (unsigned char)255;
	       if (ctr->ctr[x] != (unsigned char)0) {
		  break;
	       }
	    }
	 }

	 /* encrypt it */
	 if ((err = cipher_descriptor[ctr->cipher].ecb_encrypt(ctr->ctr, ctr->pad, &ctr->key)) != CRYPT_OK) {
	    return err;
	 }
	 ctr->padlen = 0;
      }
#ifdef LTC_FAST
      if (ctr->padlen == 0 && len >= (unsigned long)ctr->blocklen) {
	 for (x = 0; x < ctr->blocklen; x += sizeof(LTC_FAST_TYPE)) {
	    *((LTC_FAST_TYPE*)((unsigned char *)ct + x)) = *((LTC_FAST_TYPE*)((unsigned char *)pt + x)) ^
							   *((LTC_FAST_TYPE*)((unsigned char *)ctr->pad + x));
	 }
       pt         += ctr->blocklen;
       ct         += ctr->blocklen;
       len        -= ctr->blocklen;
       ctr->padlen = ctr->blocklen;
       continue;
      }
#endif
      *ct++ = *pt++ ^ ctr->pad[ctr->padlen++];
      --len;
   }
   return CRYPT_OK;
}

/**
  CTR implementation, decrypt data, Tom St Denis
   @param ct      Ciphertext
   @param pt      [out] Plaintext
   @param len     Length of ciphertext (octets)
   @param ctr     CTR state
   @return CRYPT_OK if successful
*/
static int ctr_decrypt(const unsigned char *ct, unsigned char *pt, unsigned long len, symmetric_CTR *ctr)
{
	return ctr_encrypt(ct, pt, len, ctr);
}

/**
   CTR implementation, start chain, Tom St Denis
   Initialize a CTR context
   @param cipher      The index of the cipher desired
   @param IV          The initial vector
   @param key         The secret key
   @param keylen      The length of the secret key (octets)
   @param num_rounds  Number of rounds in the cipher desired (0 for default)
   @param ctr_mode    The counter mode (CTR_COUNTER_LITTLE_ENDIAN or CTR_COUNTER_BIG_ENDIAN)
   @param ctr         The CTR state to initialize
   @return CRYPT_OK if successful
*/
static int ctr_start(int cipher, const unsigned char *IV,
		     const unsigned char *key, int keylen,
		     int num_rounds, int ctr_mode, symmetric_CTR *ctr)
{
   int x, err;

   /* bad param? */
   if ((err = cipher_is_valid(cipher)) != CRYPT_OK)
      return err;

   /* setup cipher */
   if ((err = cipher_descriptor[cipher].setup(key, keylen, num_rounds, &ctr->key)) != CRYPT_OK)
      return err;

   /* copy ctr */
   ctr->blocklen = cipher_descriptor[cipher].block_length;
   ctr->cipher   = cipher;
   ctr->padlen   = 0;
   ctr->mode     = ctr_mode & 1;
   for (x = 0; x < ctr->blocklen; x++)
       ctr->ctr[x] = IV[x];

   if (ctr_mode & LTC_CTR_RFC3686) {
      /* increment the IV as per RFC 3686 */
      if (ctr->mode == CTR_COUNTER_LITTLE_ENDIAN) {
	 /* little-endian */
	 for (x = 0; x < ctr->blocklen; x++) {
	     ctr->ctr[x] = (ctr->ctr[x] + (unsigned char)1) & (unsigned char)255;
	     if (ctr->ctr[x] != (unsigned char)0) {
		break;
	     }
	 }
      } else {
	 /* big-endian */
	 for (x = ctr->blocklen-1; x >= 0; x--) {
	     ctr->ctr[x] = (ctr->ctr[x] + (unsigned char)1) & (unsigned char)255;
	     if (ctr->ctr[x] != (unsigned char)0) {
		break;
	     }
	 }
      }
   }

   return cipher_descriptor[ctr->cipher].ecb_encrypt(ctr->ctr, ctr->pad, &ctr->key);
}


/**
  Hash a block of memory and store the digest. Tom St Denis
  @param hash   The index of the hash you wish to use
  @param in     The data you wish to hash
  @param inlen  The length of the data to hash (octets)
  @param out    [out] Where to store the digest
  @param outlen [in/out] Max size and resulting size of the digest
  @return CRYPT_OK if successful
*/
static int hash_memory(int hash, const unsigned char *in, unsigned long inlen, unsigned char *out, unsigned long *outlen)
{
    hash_state *md;
    int err;

    if (*outlen < hash_descriptor[hash].hashsize) {
       *outlen = hash_descriptor[hash].hashsize;
       return CRYPT_BUFFER_OVERFLOW;
    }

    md = malloc(sizeof(hash_state));
    if (md == NULL)
       return CRYPT_MEM;

    if ((err = hash_descriptor[hash].init(md)) != CRYPT_OK)
       goto LBL_ERR;
    if ((err = hash_descriptor[hash].process(md, in, inlen)) != CRYPT_OK)
       goto LBL_ERR;
    err = hash_descriptor[hash].done(md, out);
    *outlen = hash_descriptor[hash].hashsize;
LBL_ERR:
    free(md);

    return err;
}

/**
  HMAC support, process data, Tom St Denis/Dobes Vandermeer
  Process data through HMAC
  @param hmac    The hmac state
  @param in      The data to send through HMAC
  @param inlen   The length of the data to HMAC (octets)
  @return CRYPT_OK if successful
*/
static int hmac_process(hmac_state *hmac, const unsigned char *in, unsigned long inlen)
{
    return hash_descriptor[hmac->hash].process(&hmac->md, in, inlen);
}

#define HMAC_BLOCKSIZE hash_descriptor[hash].blocksize

/**
  HMAC support, terminate stream, Tom St Denis/Dobes Vandermeer
   Terminate an HMAC session
   @param hmac    The HMAC state
   @param out     [out] The destination of the HMAC authentication tag
   @param outlen  [in/out]  The max size and resulting size of the HMAC authentication tag
   @return CRYPT_OK if successful
*/
static int hmac_done(hmac_state *hmac, unsigned char *out, unsigned long *outlen)
{
    unsigned char *buf, *isha;
    unsigned long hashsize, i;
    int hash, err;

    hash = hmac->hash;
    /* get the hash message digest size */
    hashsize = hash_descriptor[hash].hashsize;

    /* allocate buffers */
    buf  = malloc(HMAC_BLOCKSIZE);
    isha = malloc(hashsize);
    if (buf == NULL || isha == NULL) {
       if (buf != NULL) {
	  free(buf);
       }
       if (isha != NULL) {
	  free(isha);
       }
       return CRYPT_MEM;
    }

    /* Get the hash of the first HMAC vector plus the data */
    if ((err = hash_descriptor[hash].done(&hmac->md, isha)) != CRYPT_OK) {
       goto LBL_ERR;
    }

    /* Create the second HMAC vector vector for step (3) */
    for(i=0; i < HMAC_BLOCKSIZE; i++) {
	buf[i] = hmac->key[i] ^ 0x5C;
    }

    /* Now calculate the "outer" hash for step (5), (6), and (7) */
    if ((err = hash_descriptor[hash].init(&hmac->md)) != CRYPT_OK) {
       goto LBL_ERR;
    }
    if ((err = hash_descriptor[hash].process(&hmac->md, buf, HMAC_BLOCKSIZE)) != CRYPT_OK) {
       goto LBL_ERR;
    }
    if ((err = hash_descriptor[hash].process(&hmac->md, isha, hashsize)) != CRYPT_OK) {
       goto LBL_ERR;
    }
    if ((err = hash_descriptor[hash].done(&hmac->md, buf)) != CRYPT_OK) {
       goto LBL_ERR;
    }

    /* copy to output  */
    for (i = 0; i < hashsize && i < *outlen; i++) {
	out[i] = buf[i];
    }
    *outlen = i;

    err = CRYPT_OK;
LBL_ERR:
    free(hmac->key);
    free(isha);
    free(buf);

    return err;
}

#define HMAC_BLOCKSIZE hash_descriptor[hash].blocksize

/**
  HMAC support, initialize state, Tom St Denis/Dobes Vandermeer
   Initialize an HMAC context.
   @param hmac     The HMAC state
   @param hash     The index of the hash you want to use
   @param key      The secret key
   @param keylen   The length of the secret key (octets)
   @return CRYPT_OK if successful
*/
static int hmac_init(hmac_state *hmac, int hash, const unsigned char *key, unsigned long keylen)
{
    unsigned char *buf;
    unsigned long hashsize;
    unsigned long i, z;
    int err;

    hmac->hash = hash;
    hashsize   = hash_descriptor[hash].hashsize;

    /* valid key length? */
    if (keylen == 0)
	return CRYPT_INVALID_KEYSIZE;

    /* allocate ram for buf */
    buf = malloc(HMAC_BLOCKSIZE);
    if (buf == NULL)
       return CRYPT_MEM;

    /* allocate memory for key */
    hmac->key = malloc(HMAC_BLOCKSIZE);
    if (hmac->key == NULL) {
       free(buf);
       return CRYPT_MEM;
    }

    /* (1) make sure we have a large enough key */
    if(keylen > HMAC_BLOCKSIZE) {
	z = HMAC_BLOCKSIZE;
	if ((err = hash_memory(hash, key, keylen, hmac->key, &z)) != CRYPT_OK)
	   goto LBL_ERR;
	if(hashsize < HMAC_BLOCKSIZE)
	    zeromem((hmac->key) + hashsize, (size_t)(HMAC_BLOCKSIZE - hashsize));
	keylen = hashsize;
    } else {
	memcpy(hmac->key, key, (size_t)keylen);
	if(keylen < HMAC_BLOCKSIZE)
	    zeromem((hmac->key) + keylen, (size_t)(HMAC_BLOCKSIZE - keylen));
    }

    /* Create the initial vector for step (3) */
    for(i=0; i < HMAC_BLOCKSIZE;   i++)
       buf[i] = hmac->key[i] ^ 0x36;

    /* Pre-pend that to the hash data */
    if ((err = hash_descriptor[hash].init(&hmac->md)) != CRYPT_OK)
       goto LBL_ERR;

    if ((err = hash_descriptor[hash].process(&hmac->md, buf, HMAC_BLOCKSIZE)) != CRYPT_OK)
       goto LBL_ERR;
    goto done;
LBL_ERR:
    /* free the key since we failed */
    free(hmac->key);
done:
   free(buf);
   return err;
}

/* LibTomMath */

/* detect 64-bit mode if possible */
#if defined(__x86_64__)
# if !(defined(MP_64BIT) && defined(MP_16BIT) && defined(MP_8BIT))
#  define MP_64BIT
# endif
#endif

/* some default configurations.
 *
 * A "mp_digit" must be able to hold DIGIT_BIT + 1 bits
 * A "mp_word" must be able to hold 2*DIGIT_BIT + 1 bits
 *
 * At the very least a mp_digit must be able to hold 7 bits
 * [any size beyond that is ok provided it doesn't overflow the data type]
 */
#ifdef MP_8BIT
   typedef unsigned char      mp_digit;
   typedef unsigned short     mp_word;
#elif defined(MP_16BIT)
   typedef unsigned short     mp_digit;
   typedef unsigned long      mp_word;
#elif defined(MP_64BIT)
   /* for GCC only on supported platforms */
   typedef unsigned long      mp_digit;
   typedef unsigned long      mp_word __attribute__ ((mode(TI)));

# define DIGIT_BIT          60
#else
   /* this is the default case, 28-bit digits */
   typedef unsigned long      mp_digit;
   typedef ulong64            mp_word;

# ifdef MP_31BIT
   /* this is an extension that uses 31-bit digits */
#  define DIGIT_BIT          31
# else
   /* default case is 28-bit digits, defines MP_28BIT as a handy macro to test */
#  define DIGIT_BIT          28
#  define MP_28BIT
# endif
#endif

/* otherwise the bits per digit is calculated automatically from the size of a mp_digit */
#ifndef DIGIT_BIT
#define DIGIT_BIT     ((int)((CHAR_BIT * sizeof(mp_digit) - 1)))  /* bits per digit */
#endif

#define MP_MASK          ((((mp_digit)1)<<((mp_digit)DIGIT_BIT))-((mp_digit)1))

/* equalities */
#define MP_LT        -1   /* less than */
#define MP_EQ         0   /* equal to */
#define MP_GT         1   /* greater than */

#define MP_ZPOS       0   /* positive integer */
#define MP_NEG        1   /* negative */

#define MP_OKAY       0   /* ok result */
#define MP_MEM        -2  /* out of mem */
#define MP_VAL        -3  /* invalid input */
#define MP_RANGE      MP_VAL

#define MP_YES        1   /* yes response */
#define MP_NO         0   /* no response */

/* define this to use lower memory usage routines (exptmods mostly) */
/* #define MP_LOW_MEM */

/* default precision */
#ifndef MP_PREC
# ifndef MP_LOW_MEM
#  define MP_PREC                 32     /* default digits of precision */
# else
#  define MP_PREC                 8      /* default digits of precision */
# endif
#endif

/* size of comba arrays, should be at least 2 * 2**(BITS_PER_WORD - BITS_PER_DIGIT*2) */
#define MP_WARRAY               (1 << (sizeof(mp_word) * CHAR_BIT - 2 * DIGIT_BIT + 1))

/* the infamous mp_int structure */
typedef struct  {
    int used, alloc, sign;
    mp_digit *dp;
} mp_int;

/* init a null terminated series of arguments */
static int mp_init_multi(mp_int *mp, ...);

#define mp_iszero(a) (((a)->used == 0) ? MP_YES : MP_NO)
#define mp_iseven(a) (((a)->used > 0 && (((a)->dp[0] & 1) == 0)) ? MP_YES : MP_NO)
#define mp_isodd(a)  (((a)->used > 0 && (((a)->dp[0] & 1) == 1)) ? MP_YES : MP_NO)

/* c = a / 2**b */
static int mp_div_2d(mp_int *a, int b, mp_int *c, mp_int *d);
/* c = a * 2**b */
static int mp_mul_2d(mp_int *a, int b, mp_int *c);
/* c = a mod 2**d */
static int mp_mod_2d(mp_int *a, int b, mp_int *c);
/* computes a = 2**b */
static int mp_2expt(mp_int *a, int b);
/* compare |a| to |b| */
static int mp_cmp_mag(mp_int *a, mp_int *b);
/* c = a + b */
static int mp_add(mp_int *a, mp_int *b, mp_int *c);
/* c = a - b */
static int mp_sub(mp_int *a, mp_int *b, mp_int *c);
/* c = a * b */
static int mp_mul(mp_int *a, mp_int *b, mp_int *c);
/* b = a*a  */
static int mp_sqr(mp_int *a, mp_int *b);
/* a/b => cb + d == a */
static int mp_div(mp_int *a, mp_int *b, mp_int *c, mp_int *d);
/* c = a mod b, 0 <= c < b  */
static int mp_mod(mp_int *a, mp_int *b, mp_int *c);
/* c = a + b */
static int mp_add_d(mp_int *a, mp_digit b, mp_int *c);
/* c = 1/a (mod b) */
static int mp_invmod(mp_int *a, mp_int *b, mp_int *c);
/* used to setup the Barrett reduction for a given modulus b */
static int mp_reduce_setup(mp_int *a, mp_int *b);

/* lowlevel functions, do not call! */
static int s_mp_add(mp_int *a, mp_int *b, mp_int *c);
static int s_mp_sub(mp_int *a, mp_int *b, mp_int *c);
static int fast_s_mp_mul_digs(mp_int *a, mp_int *b, mp_int *c, int digs);
static int s_mp_mul_digs(mp_int *a, mp_int *b, mp_int *c, int digs);
static int fast_s_mp_mul_high_digs(mp_int *a, mp_int *b, mp_int *c, int digs);
static int s_mp_mul_high_digs(mp_int *a, mp_int *b, mp_int *c, int digs);
static int fast_s_mp_sqr(mp_int *a, mp_int *b);
static int s_mp_sqr(mp_int *a, mp_int *b);
static int fast_mp_invmod(mp_int *a, mp_int *b, mp_int *c);
static int mp_invmod_slow(mp_int * a, mp_int * b, mp_int * c);
static int fast_mp_montgomery_reduce(mp_int *a, mp_int *m, mp_digit mp);
static int mp_exptmod_fast(mp_int *G, mp_int *X, mp_int *P, mp_int *Y, int mode);
static int s_mp_exptmod(mp_int * G, mp_int * X, mp_int * P, mp_int * Y, int mode);
static void bn_reverse(unsigned char *s, int len);


/* init a new bignum mp_int */
static int mp_init (mp_int * a)
{
  int i;

  /* allocate memory required and clear it */
  a->dp = malloc (sizeof (mp_digit) * MP_PREC);
  if (a->dp == NULL)
    return MP_MEM;

  /* set the digits to zero */
  for (i = 0; i < MP_PREC; i++)
      a->dp[i] = 0;

  /* set the used to zero, allocated digits to the default precision
   * and sign to positive */
  a->used  = 0;
  a->alloc = MP_PREC;
  a->sign  = MP_ZPOS;

  return MP_OKAY;
}

/* clear one (frees)  */
static void mp_clear (mp_int * a)
{
  volatile mp_digit *p;
  int len;

  /* only do anything if a hasn't been freed previously */
  if (a->dp != NULL) {
	/* first zero the digits */
	len = a->alloc;
	p = a->dp;
	while (len--)
		*p++ = 0;

	/* free ram */
	free(a->dp);

	/* reset members to make debugging easier */
	a->dp    = NULL;
	a->alloc = a->used = 0;
	a->sign  = MP_ZPOS;
  }
}

/* d = a + b (mod c) */
static int mp_addmod (mp_int * a, mp_int * b, mp_int * c, mp_int * d)
{
  int     res;
  mp_int  t;

  if ((res = mp_init (&t)) != MP_OKAY)
    return res;

  if ((res = mp_add (a, b, &t)) != MP_OKAY) {
    mp_clear (&t);
    return res;
  }
  res = mp_mod (&t, c, d);
  mp_clear (&t);
  return res;
}

/* clear a null terminated series of arguments */
static void mp_clear_multi(mp_int *mp, ...)
{
    mp_int* next_mp = mp;
    va_list args;
    va_start(args, mp);
    while (next_mp != NULL) {
	mp_clear(next_mp);
	next_mp = va_arg(args, mp_int*);
    }
    va_end(args);
}

/* compare two ints (signed)*/
static int mp_cmp (mp_int * a, mp_int * b)
{
  /* compare based on sign */
  if (a->sign != b->sign) {
     if (a->sign == MP_NEG)
	return MP_LT;
      else
	return MP_GT;
  }

  /* compare digits */
  if (a->sign == MP_NEG) {
     /* if negative compare opposite direction */
     return mp_cmp_mag(b, a);
  } else {
     return mp_cmp_mag(a, b);
  }
}

/* compare a digit */
static int mp_cmp_d(mp_int * a, mp_digit b)
{
  /* compare based on sign */
  if (a->sign == MP_NEG) {
    return MP_LT;
  }

  /* compare based on magnitude */
  if (a->used > 1) {
    return MP_GT;
  }

  /* compare the only digit of a to b */
  if (a->dp[0] > b) {
    return MP_GT;
  } else if (a->dp[0] < b) {
    return MP_LT;
  } else {
    return MP_EQ;
  }
}

/* returns the number of bits in an int */
static int mp_count_bits (mp_int * a)
{
  int     r;
  mp_digit q;

  /* shortcut */
  if (a->used == 0)
    return 0;

  /* get number of digits and add that */
  r = (a->used - 1) * DIGIT_BIT;

  /* take the last digit and count the bits in it */
  q = a->dp[a->used - 1];
  while (q > ((mp_digit) 0)) {
    ++r;
    q >>= ((mp_digit) 1);
  }
  return r;
}

/* grow an int to a given size */
static int mp_grow (mp_int * a, int size)
{
  int     i;
  mp_digit *tmp;

  /* if the alloc size is smaller alloc more ram */
  if (a->alloc < size) {
    /* ensure there are always at least MP_PREC digits extra on top */
    size += (MP_PREC * 2) - (size % MP_PREC);

    /* reallocate the array a->dp
     *
     * We store the return in a temporary variable
     * in case the operation failed we don't want
     * to overwrite the dp member of a.
     */
    tmp = realloc (a->dp, sizeof (mp_digit) * size);
    if (tmp == NULL) {
      /* reallocation failed but "a" is still valid [can be freed] */
      return MP_MEM;
    }

    /* reallocation succeeded so set a->dp */
    a->dp = tmp;

    /* zero excess digits */
    i        = a->alloc;
    a->alloc = size;
    for (; i < a->alloc; i++) {
      a->dp[i] = 0;
    }
  }
  return MP_OKAY;
}

/* trim unused digits
 *
 * This is used to ensure that leading zero digits are
 * trimed and the leading "used" digit will be non-zero
 * Typically very fast.  Also fixes the sign if there
 * are no more leading digits
 */
static void mp_clamp (mp_int * a)
{
  /* decrease used while the most significant digit is
   * zero.
   */
  while (a->used > 0 && a->dp[a->used - 1] == 0) {
    --(a->used);
  }

  /* reset the sign flag if used == 0 */
  if (a->used == 0) {
    a->sign = MP_ZPOS;
  }
}

/* b = a/2 */
static int mp_div_2(mp_int * a, mp_int * b)
{
  int     x, res, oldused;

  /* copy */
  if (b->alloc < a->used) {
    if ((res = mp_grow (b, a->used)) != MP_OKAY)
      return res;
  }

  oldused = b->used;
  b->used = a->used;
  {
    mp_digit r, rr, *tmpa, *tmpb;

    /* source alias */
    tmpa = a->dp + b->used - 1;

    /* dest alias */
    tmpb = b->dp + b->used - 1;

    /* carry */
    r = 0;
    for (x = b->used - 1; x >= 0; x--) {
      /* get the carry for the next iteration */
      rr = *tmpa & 1;

      /* shift the current digit, add in carry and store */
      *tmpb-- = (*tmpa-- >> 1) | (r << (DIGIT_BIT - 1));

      /* forward carry to next iteration */
      r = rr;
    }

    /* zero excess digits */
    tmpb = b->dp + b->used;
    for (x = b->used; x < oldused; x++) {
      *tmpb++ = 0;
    }
  }
  b->sign = a->sign;
  mp_clamp (b);
  return MP_OKAY;
}

/* multiply by a digit: c = a * b */
static int
mp_mul_d (mp_int * a, mp_digit b, mp_int * c)
{
  mp_digit u, *tmpa, *tmpc;
  mp_word  r;
  int      ix, res, olduse;

  /* make sure c is big enough to hold a*b */
  if (c->alloc < a->used + 1) {
    if ((res = mp_grow (c, a->used + 1)) != MP_OKAY)
      return res;
  }

  /* get the original destinations used count */
  olduse = c->used;

  /* set the sign */
  c->sign = a->sign;

  /* alias for a->dp [source] */
  tmpa = a->dp;

  /* alias for c->dp [dest] */
  tmpc = c->dp;

  /* zero carry */
  u = 0;

  /* compute columns */
  for (ix = 0; ix < a->used; ix++) {
    /* compute product and carry sum for this term */
    r       = ((mp_word) u) + ((mp_word)*tmpa++) * ((mp_word)b);

    /* mask off higher bits to get a single digit */
    *tmpc++ = (mp_digit) (r & ((mp_word) MP_MASK));

    /* send carry into next iteration */
    u       = (mp_digit) (r >> ((mp_word) DIGIT_BIT));
  }

  /* store final carry [if any] and increment ix offset  */
  *tmpc++ = u;
  ++ix;

  /* now zero digits above the top */
  while (ix++ < olduse)
     *tmpc++ = 0;

  /* set used count */
  c->used = a->used + 1;
  mp_clamp(c);

  return MP_OKAY;
}

/* reduces a modulo n where n is of the form 2**p - d */
static int mp_reduce_2k(mp_int *a, mp_int *n, mp_digit d)
{
   mp_int q;
   int    p, res;

   if ((res = mp_init(&q)) != MP_OKAY)
      return res;

   p = mp_count_bits(n);
top:
   /* q = a/2**p, a = a mod 2**p */
   if ((res = mp_div_2d(a, p, &q, a)) != MP_OKAY)
      goto ERR;

   if (d != 1) {
      /* q = q * d */
      if ((res = mp_mul_d(&q, d, &q)) != MP_OKAY) {
	 goto ERR;
      }
   }

   /* a = a + q */
   if ((res = s_mp_add(a, &q, a)) != MP_OKAY) {
      goto ERR;
   }

   if (mp_cmp_mag(a, n) != MP_LT) {
      s_mp_sub(a, n, a);
      goto top;
   }

ERR:
   mp_clear(&q);
   return res;
}

/* determines if mp_reduce_2k can be used */
static int mp_reduce_is_2k(mp_int *a)
{
   int ix, iy, iw;
   mp_digit iz;

   if (a->used == 0) {
      return MP_NO;
   } else if (a->used == 1) {
      return MP_YES;
   } else if (a->used > 1) {
      iy = mp_count_bits(a);
      iz = 1;
      iw = 1;

      /* Test every bit from the second digit up, must be 1 */
      for (ix = DIGIT_BIT; ix < iy; ix++) {
	  if ((a->dp[iw] & iz) == 0) {
	     return MP_NO;
	  }
	  iz <<= 1;
	  if (iz > (mp_digit)MP_MASK) {
	     ++iw;
	     iz = 1;
	  }
      }
   }
   return MP_YES;
}

/* determines if reduce_2k_l can be used */
static int mp_reduce_is_2k_l(mp_int *a)
{
   int ix, iy;

   if (a->used == 0) {
      return MP_NO;
   } else if (a->used == 1) {
      return MP_YES;
   } else if (a->used > 1) {
      /* if more than half of the digits are -1 we're sold */
      for (iy = ix = 0; ix < a->used; ix++) {
	  if (a->dp[ix] == MP_MASK) {
	      ++iy;
	  }
      }
      return (iy >= (a->used/2)) ? MP_YES : MP_NO;

   }
   return MP_NO;
}

/* determines if a number is a valid DR modulus */
static int mp_dr_is_modulus(mp_int *a)
{
   int ix;

   /* must be at least two digits */
   if (a->used < 2)
      return 0;

   /* must be of the form b**k - a [a <= b] so all
    * but the first digit must be equal to -1 (mod b).
    */
   for (ix = 1; ix < a->used; ix++) {
       if (a->dp[ix] != MP_MASK)
	  return 0;
   }
   return 1;
}

/* copy, b = a */
static int mp_copy (mp_int * a, mp_int * b)
{
  int     res, n;

  /* if dst == src do nothing */
  if (a == b)
    return MP_OKAY;

  /* grow dest */
  if (b->alloc < a->used) {
     if ((res = mp_grow (b, a->used)) != MP_OKAY)
	return res;
  }

  /* zero b and copy the parameters over */
  {
    mp_digit *tmpa, *tmpb;

    /* pointer aliases */

    /* source */
    tmpa = a->dp;

    /* destination */
    tmpb = b->dp;

    /* copy all the digits */
    for (n = 0; n < a->used; n++)
      *tmpb++ = *tmpa++;

    /* clear high digits */
    for (; n < b->used; n++)
      *tmpb++ = 0;
  }

  /* copy used count and sign */
  b->used = a->used;
  b->sign = a->sign;
  return MP_OKAY;
}

/* b = |a|
 *
 * Simple function copies the input and fixes the sign to positive
 */
static int mp_abs (mp_int * a, mp_int * b)
{
  int     res;

  /* copy a to b */
  if (a != b) {
     if ((res = mp_copy (a, b)) != MP_OKAY)
       return res;
  }

  /* force the sign of b to positive */
  b->sign = MP_ZPOS;

  return MP_OKAY;
}

/* d = a**b (mod c) */
/* this is a shell function that calls either the normal or Montgomery
 * exptmod functions.  Originally the call to the montgomery code was
 * embedded in the normal function but that wasted alot of stack space
 * for nothing (since 99% of the time the Montgomery code would be called)
 */
static int mp_exptmod (mp_int * G, mp_int * X, mp_int * P, mp_int * Y)
{
  int dr;

  /* modulus P must be positive */
  if (P->sign == MP_NEG)
     return MP_VAL;

  /* if exponent X is negative we have to recurse */
  if (X->sign == MP_NEG) {
     mp_int tmpG, tmpX;
     int err;

     /* first compute 1/G mod P */
     if ((err = mp_init(&tmpG)) != MP_OKAY)
	return err;
     if ((err = mp_invmod(G, P, &tmpG)) != MP_OKAY) {
	mp_clear(&tmpG);
	return err;
     }

     /* now get |X| */
     if ((err = mp_init(&tmpX)) != MP_OKAY) {
	mp_clear(&tmpG);
	return err;
     }
     if ((err = mp_abs(X, &tmpX)) != MP_OKAY) {
	mp_clear_multi(&tmpG, &tmpX, NULL);
	return err;
     }

     /* and now compute (1/G)**|X| instead of G**X [X < 0] */
     err = mp_exptmod(&tmpG, &tmpX, P, Y);
     mp_clear_multi(&tmpG, &tmpX, NULL);
     return err;
  }

/* modified diminished radix reduction */
  if (mp_reduce_is_2k_l(P) == MP_YES)
     return s_mp_exptmod(G, X, P, Y, 1);

  /* is it a DR modulus? */
  dr = mp_dr_is_modulus(P);

  /* if not, is it a unrestricted DR modulus? */
  if (dr == 0)
     dr = mp_reduce_is_2k(P) << 1;

  /* if the modulus is odd or dr != 0 use the montgomery method */
  if (mp_isodd (P) == 1 || dr !=  0) {
    return mp_exptmod_fast (G, X, P, Y, dr);
  } else {
    /* otherwise use the generic Barrett reduction technique */
    return s_mp_exptmod (G, X, P, Y, 0);
  }
}


/* hac 14.61, pp608 */
int mp_invmod (mp_int * a, mp_int * b, mp_int * c)
{
  /* b cannot be negative */
  if (b->sign == MP_NEG || mp_iszero(b) == 1)
    return MP_VAL;

  /* if the modulus is odd we can use a faster routine instead */
  if (mp_isodd (b) == 1)
    return fast_mp_invmod (a, b, c);

  return mp_invmod_slow(a, b, c);
}

/* swap the elements of two integers, for cases where you can't simply swap the
 * mp_int pointers around
 */
static void mp_exch (mp_int * a, mp_int * b)
{
  mp_int  t;

  t  = *a;
  *a = *b;
  *b = t;
}

/* init an mp_init for a given size */
static int mp_init_size (mp_int * a, int size)
{
  int x;

  /* pad size so there are always extra digits */
  size += (MP_PREC * 2) - (size % MP_PREC);

  /* alloc mem */
  a->dp = malloc (sizeof (mp_digit) * size);
  if (a->dp == NULL)
    return MP_MEM;

  /* set the members */
  a->used  = 0;
  a->alloc = size;
  a->sign  = MP_ZPOS;

  /* zero the digits */
  for (x = 0; x < size; x++)
      a->dp[x] = 0;

  return MP_OKAY;
}

/* c = a mod b, 0 <= c < b */
int
mp_mod (mp_int * a, mp_int * b, mp_int * c)
{
  mp_int  t;
  int     res;

  if ((res = mp_init_size (&t, b->used)) != MP_OKAY)
    return res;

  if ((res = mp_div (a, b, NULL, &t)) != MP_OKAY) {
    mp_clear (&t);
    return res;
  }

  if (t.sign != b->sign) {
    res = mp_add (b, &t, c);
  } else {
    res = MP_OKAY;
    mp_exch (&t, c);
  }

  mp_clear (&t);
  return res;
}

/* d = a * b (mod c) */
static int mp_mulmod (mp_int * a, mp_int * b, mp_int * c, mp_int * d)
{
  int     res;
  mp_int  t;

  if ((res = mp_init_size (&t, c->used)) != MP_OKAY)
    return res;

  if ((res = mp_mul (a, b, &t)) != MP_OKAY) {
    mp_clear (&t);
    return res;
  }
  res = mp_mod (&t, c, d);
  mp_clear (&t);
  return res;
}

/* set to zero */
static void mp_zero (mp_int * a)
{
  int       n;
  mp_digit *tmp;

  a->sign = MP_ZPOS;
  a->used = 0;

  tmp = a->dp;
  for (n = 0; n < a->alloc; n++)
     *tmp++ = 0;
}

/* reads a unsigned char array, assumes the msb is stored first [big endian] */
static int mp_read_unsigned_bin (mp_int * a, const unsigned char *b, int c)
{
  int     res;

  /* make sure there are at least two digits */
  if (a->alloc < 2) {
     if ((res = mp_grow(a, 2)) != MP_OKAY)
	return res;
  }

  /* zero the int */
  mp_zero (a);

  /* read the bytes in */
  while (c-- > 0) {
    if ((res = mp_mul_2d (a, 8, a)) != MP_OKAY)
      return res;

#ifndef MP_8BIT
      a->dp[0] |= *b++;
      a->used += 1;
#else
      a->dp[0] = (*b & MP_MASK);
      a->dp[1] |= ((*b++ >> 7U) & 1);
      a->used += 2;
#endif
  }
  mp_clamp (a);
  return MP_OKAY;
}

/* set a 32-bit const */
static int mp_set_int (mp_int * a, unsigned long b)
{
  int     x, res;

  mp_zero (a);

  /* set four bits at a time */
  for (x = 0; x < 8; x++) {
    /* shift the number up four bits */
    if ((res = mp_mul_2d (a, 4, a)) != MP_OKAY)
      return res;

    /* OR in the top four bits of the source */
    a->dp[0] |= (b >> 28) & 15;

    /* shift the source up to the next four bits */
    b <<= 4;

    /* ensure that digits are not clamped off */
    a->used += 1;
  }
  mp_clamp (a);
  return MP_OKAY;
}

/* single digit subtraction: c = a - b */
static int
mp_sub_d (mp_int * a, mp_digit b, mp_int * c)
{
  mp_digit *tmpa, *tmpc, mu;
  int       res, ix, oldused;

  /* grow c as required */
  if (c->alloc < a->used + 1) {
     if ((res = mp_grow(c, a->used + 1)) != MP_OKAY)
	return res;
  }

  /* if a is negative just do an unsigned
   * addition [with fudged signs]
   */
  if (a->sign == MP_NEG) {
     a->sign = MP_ZPOS;
     res     = mp_add_d(a, b, c);
     a->sign = c->sign = MP_NEG;

     /* clamp */
     mp_clamp(c);

     return res;
  }

  /* setup regs */
  oldused = c->used;
  tmpa    = a->dp;
  tmpc    = c->dp;

  /* if a <= b simply fix the single digit */
  if ((a->used == 1 && a->dp[0] <= b) || a->used == 0) {
     if (a->used == 1) {
	*tmpc++ = b - *tmpa;
     } else {
	*tmpc++ = b;
     }
     ix      = 1;

     /* negative/1digit */
     c->sign = MP_NEG;
     c->used = 1;
  } else {
     /* positive/size */
     c->sign = MP_ZPOS;
     c->used = a->used;

     /* subtract first digit */
     *tmpc    = *tmpa++ - b;
     mu       = *tmpc >> (sizeof(mp_digit) * CHAR_BIT - 1);
     *tmpc++ &= MP_MASK;

     /* handle rest of the digits */
     for (ix = 1; ix < a->used; ix++) {
	*tmpc    = *tmpa++ - mu;
	mu       = *tmpc >> (sizeof(mp_digit) * CHAR_BIT - 1);
	*tmpc++ &= MP_MASK;
     }
  }

  /* zero excess digits */
  while (ix++ < oldused)
     *tmpc++ = 0;
  mp_clamp(c);
  return MP_OKAY;
}


/* creates "a" then copies b into it */
static int mp_init_copy (mp_int * a, mp_int * b)
{
  int     res;

  if ((res = mp_init_size (a, b->used)) != MP_OKAY)
    return res;
  return mp_copy (b, a);
}

/* store in unsigned [big endian] format */
static int mp_to_unsigned_bin (mp_int * a, unsigned char *b)
{
  int     x, res;
  mp_int  t;

  if ((res = mp_init_copy (&t, a)) != MP_OKAY)
    return res;

  x = 0;
  while (mp_iszero (&t) == 0) {
#ifndef MP_8BIT
      b[x++] = (unsigned char) (t.dp[0] & 255);
#else
      b[x++] = (unsigned char) (t.dp[0] | ((t.dp[1] & 0x01) << 7));
#endif
    if ((res = mp_div_2d (&t, 8, &t, NULL)) != MP_OKAY) {
      mp_clear (&t);
      return res;
    }
  }
  bn_reverse (b, x);
  mp_clear (&t);
  return MP_OKAY;
}

/* get the size for an unsigned equivalent */
static int mp_unsigned_bin_size (mp_int * a)
{
  int     size = mp_count_bits (a);
  return (size / 8 + ((size & 7) != 0 ? 1 : 0));
}


/* reverse an array, used for radix code */
void
bn_reverse (unsigned char *s, int len)
{
  int     ix, iy;
  unsigned char t;

  ix = 0;
  iy = len - 1;
  while (ix < iy) {
    t     = s[ix];
    s[ix] = s[iy];
    s[iy] = t;
    ++ix;
    --iy;
  }
}

/* set to a digit */
static void mp_set (mp_int * a, mp_digit b)
{
  mp_zero (a);
  a->dp[0] = b & MP_MASK;
  a->used  = (a->dp[0] != 0) ? 1 : 0;
}


/* computes the modular inverse via binary extended euclidean algorithm,
 * that is c = 1/a mod b
 *
 * Based on slow invmod except this is optimized for the case where b is
 * odd as per HAC Note 14.64 on pp. 610
 */
int fast_mp_invmod (mp_int * a, mp_int * b, mp_int * c)
{
  mp_int  x, y, u, v, B, D;
  int     res, neg;

  /* 2. [modified] b must be odd   */
  if (mp_iseven (b) == 1)
    return MP_VAL;

  /* init all our temps */
  if ((res = mp_init_multi(&x, &y, &u, &v, &B, &D, NULL)) != MP_OKAY)
     return res;

  /* x == modulus, y == value to invert */
  if ((res = mp_copy (b, &x)) != MP_OKAY)
    goto LBL_ERR;

  /* we need y = |a| */
  if ((res = mp_mod (a, b, &y)) != MP_OKAY)
    goto LBL_ERR;

  /* 3. u=x, v=y, A=1, B=0, C=0,D=1 */
  if ((res = mp_copy (&x, &u)) != MP_OKAY)
    goto LBL_ERR;
  if ((res = mp_copy (&y, &v)) != MP_OKAY)
    goto LBL_ERR;
  mp_set (&D, 1);

top:
  /* 4.  while u is even do */
  while (mp_iseven (&u) == 1) {
    /* 4.1 u = u/2 */
    if ((res = mp_div_2 (&u, &u)) != MP_OKAY)
      goto LBL_ERR;
    /* 4.2 if B is odd then */
    if (mp_isodd (&B) == 1) {
      if ((res = mp_sub (&B, &x, &B)) != MP_OKAY)
	goto LBL_ERR;
    }
    /* B = B/2 */
    if ((res = mp_div_2 (&B, &B)) != MP_OKAY)
      goto LBL_ERR;
  }

  /* 5.  while v is even do */
  while (mp_iseven (&v) == 1) {
    /* 5.1 v = v/2 */
    if ((res = mp_div_2 (&v, &v)) != MP_OKAY)
      goto LBL_ERR;
    /* 5.2 if D is odd then */
    if (mp_isodd (&D) == 1) {
      /* D = (D-x)/2 */
      if ((res = mp_sub (&D, &x, &D)) != MP_OKAY)
	goto LBL_ERR;
    }
    /* D = D/2 */
    if ((res = mp_div_2 (&D, &D)) != MP_OKAY)
      goto LBL_ERR;
  }

  /* 6.  if u >= v then */
  if (mp_cmp (&u, &v) != MP_LT) {
    /* u = u - v, B = B - D */
    if ((res = mp_sub (&u, &v, &u)) != MP_OKAY)
      goto LBL_ERR;

    if ((res = mp_sub (&B, &D, &B)) != MP_OKAY)
      goto LBL_ERR;
  } else {
    /* v - v - u, D = D - B */
    if ((res = mp_sub (&v, &u, &v)) != MP_OKAY)
      goto LBL_ERR;

    if ((res = mp_sub (&D, &B, &D)) != MP_OKAY)
      goto LBL_ERR;
  }

  /* if not zero goto step 4 */
  if (mp_iszero (&u) == 0)
    goto top;

  /* now a = C, b = D, gcd == g*v */

  /* if v != 1 then there is no inverse */
  if (mp_cmp_d (&v, 1) != MP_EQ) {
    res = MP_VAL;
    goto LBL_ERR;
  }

  /* b is now the inverse */
  neg = a->sign;
  while (D.sign == MP_NEG) {
    if ((res = mp_add (&D, b, &D)) != MP_OKAY)
      goto LBL_ERR;
  }
  mp_exch (&D, c);
  c->sign = neg;
  res = MP_OKAY;

LBL_ERR:
  mp_clear_multi (&x, &y, &u, &v, &B, &D, NULL);
  return res;
}


/* high level addition (handles signs) */
int mp_add (mp_int * a, mp_int * b, mp_int * c)
{
  int     sa, sb, res;

  /* get sign of both inputs */
  sa = a->sign;
  sb = b->sign;

  /* handle two cases, not four */
  if (sa == sb) {
    /* both positive or both negative */
    /* add their magnitudes, copy the sign */
    c->sign = sa;
    res = s_mp_add (a, b, c);
  } else {
    /* one positive, the other negative */
    /* subtract the one with the greater magnitude from */
    /* the one of the lesser magnitude.  The result gets */
    /* the sign of the one with the greater magnitude. */
    if (mp_cmp_mag (a, b) == MP_LT) {
      c->sign = sb;
      res = s_mp_sub (b, a, c);
    } else {
      c->sign = sa;
      res = s_mp_sub (a, b, c);
    }
  }
  return res;
}

/* single digit addition */
int
mp_add_d (mp_int * a, mp_digit b, mp_int * c)
{
  int     res, ix, oldused;
  mp_digit *tmpa, *tmpc, mu;

  /* grow c as required */
  if (c->alloc < a->used + 1) {
     if ((res = mp_grow(c, a->used + 1)) != MP_OKAY)
	return res;
  }

  /* if a is negative and |a| >= b, call c = |a| - b */
  if (a->sign == MP_NEG && (a->used > 1 || a->dp[0] >= b)) {
     /* temporarily fix sign of a */
     a->sign = MP_ZPOS;

     /* c = |a| - b */
     res = mp_sub_d(a, b, c);

     /* fix sign  */
     a->sign = c->sign = MP_NEG;

     /* clamp */
     mp_clamp(c);

     return res;
  }

  /* old number of used digits in c */
  oldused = c->used;

  /* sign always positive */
  c->sign = MP_ZPOS;

  /* source alias */
  tmpa    = a->dp;

  /* destination alias */
  tmpc    = c->dp;

  /* if a is positive */
  if (a->sign == MP_ZPOS) {
     /* add digit, after this we're propagating
      * the carry.
      */
     *tmpc   = *tmpa++ + b;
     mu      = *tmpc >> DIGIT_BIT;
     *tmpc++ &= MP_MASK;

     /* now handle rest of the digits */
     for (ix = 1; ix < a->used; ix++) {
	*tmpc   = *tmpa++ + mu;
	mu      = *tmpc >> DIGIT_BIT;
	*tmpc++ &= MP_MASK;
     }
     /* set final carry */
     ix++;
     *tmpc++  = mu;

     /* setup size */
     c->used = a->used + 1;
  } else {
     /* a was negative and |a| < b */
     c->used  = 1;

     /* the result is a single digit */
     if (a->used == 1) {
	*tmpc++  =  b - a->dp[0];
     } else {
	*tmpc++  =  b;
     }

     /* setup count so the clearing of oldused
      * can fall through correctly
      */
     ix       = 1;
  }

  /* now zero to oldused */
  while (ix++ < oldused) {
     *tmpc++ = 0;
  }
  mp_clamp(c);

  return MP_OKAY;
}

/* compare maginitude of two ints (unsigned) */
int mp_cmp_mag (mp_int * a, mp_int * b)
{
  int     n;
  mp_digit *tmpa, *tmpb;

  /* compare based on # of non-zero digits */
  if (a->used > b->used)
    return MP_GT;

  if (a->used < b->used)
    return MP_LT;

  /* alias for a */
  tmpa = a->dp + (a->used - 1);

  /* alias for b */
  tmpb = b->dp + (a->used - 1);

  /* compare based on digits  */
  for (n = 0; n < a->used; ++n, --tmpa, --tmpb) {
    if (*tmpa > *tmpb)
      return MP_GT;
    if (*tmpa < *tmpb)
      return MP_LT;
  }
  return MP_EQ;
}

/* shift right a certain amount of digits */
static void mp_rshd (mp_int * a, int b)
{
  int     x;

  /* if b <= 0 then ignore it */
  if (b <= 0)
    return;

  /* if b > used then simply zero it and return */
  if (a->used <= b) {
    mp_zero (a);
    return;
  }

  {
    mp_digit *bottom, *top;

    /* shift the digits down */

    /* bottom */
    bottom = a->dp;

    /* top [offset into digits] */
    top = a->dp + b;

    /* this is implemented as a sliding window where
     * the window is b-digits long and digits from
     * the top of the window are copied to the bottom
     *
     * e.g.

     b-2 | b-1 | b0 | b1 | b2 | ... | bb |   ---->
		 /\                   |      ---->
		  \-------------------/      ---->
     */
    for (x = 0; x < (a->used - b); x++) {
      *bottom++ = *top++;
    }

    /* zero the top digits */
    for (; x < a->used; x++) {
      *bottom++ = 0;
    }
  }

  /* remove excess digits */
  a->used -= b;
}

/* shift right by a certain bit count (store quotient in c, optional remainder in d) */
int mp_div_2d (mp_int * a, int b, mp_int * c, mp_int * d)
{
  mp_digit D, r, rr;
  int     x, res;
  mp_int  t;


  /* if the shift count is <= 0 then we do no work */
  if (b <= 0) {
    res = mp_copy (a, c);
    if (d != NULL)
      mp_zero (d);
    return res;
  }

  if ((res = mp_init (&t)) != MP_OKAY)
    return res;

  /* get the remainder */
  if (d != NULL) {
    if ((res = mp_mod_2d (a, b, &t)) != MP_OKAY) {
      mp_clear (&t);
      return res;
    }
  }

  /* copy */
  if ((res = mp_copy (a, c)) != MP_OKAY) {
    mp_clear (&t);
    return res;
  }

  /* shift by as many digits in the bit count */
  if (b >= (int)DIGIT_BIT)
    mp_rshd (c, b / DIGIT_BIT);

  /* shift any bit count < DIGIT_BIT */
  D = (mp_digit) (b % DIGIT_BIT);
  if (D != 0) {
    mp_digit *tmpc, mask, shift;

    /* mask */
    mask = (((mp_digit)1) << D) - 1;

    /* shift for lsb */
    shift = DIGIT_BIT - D;

    /* alias */
    tmpc = c->dp + (c->used - 1);

    /* carry */
    r = 0;
    for (x = c->used - 1; x >= 0; x--) {
      /* get the lower  bits of this word in a temp */
      rr = *tmpc & mask;

      /* shift the current word and mix in the carry bits from the previous word */
      *tmpc = (*tmpc >> D) | (r << shift);
      --tmpc;

      /* set the carry to the carry bits of the current word found above */
      r = rr;
    }
  }
  mp_clamp (c);
  if (d != NULL)
    mp_exch (&t, d);
  mp_clear (&t);
  return MP_OKAY;
}

/* shift left a certain amount of digits */
static int mp_lshd (mp_int * a, int b)
{
  int     x, res;

  /* if its less than zero return */
  if (b <= 0)
    return MP_OKAY;

  /* grow to fit the new digits */
  if (a->alloc < a->used + b) {
     if ((res = mp_grow (a, a->used + b)) != MP_OKAY)
       return res;
  }

  {
    mp_digit *top, *bottom;

    /* increment the used by the shift amount then copy upwards */
    a->used += b;

    /* top */
    top = a->dp + a->used - 1;

    /* base */
    bottom = a->dp + a->used - 1 - b;

    /* much like mp_rshd this is implemented using a sliding window
     * except the window goes the otherway around.  Copying from
     * the bottom to the top.  see bn_mp_rshd.c for more info.
     */
    for (x = a->used - 1; x >= b; x--)
      *top-- = *bottom--;

    /* zero the lower digits */
    top = a->dp;
    for (x = 0; x < b; x++)
      *top++ = 0;
  }
  return MP_OKAY;
}

/* integer signed division.
 * c*b + d == a [e.g. a/b, c=quotient, d=remainder]
 * HAC pp.598 Algorithm 14.20
 *
 * Note that the description in HAC is horribly
 * incomplete.  For example, it doesn't consider
 * the case where digits are removed from 'x' in
 * the inner loop.  It also doesn't consider the
 * case that y has fewer than three digits, etc..
 *
 * The overall algorithm is as described as
 * 14.20 from HAC but fixed to treat these cases.
*/
int mp_div (mp_int * a, mp_int * b, mp_int * c, mp_int * d)
{
  mp_int  q, x, y, t1, t2;
  int     res, n, t, i, norm, neg;

  /* is divisor zero ? */
  if (mp_iszero (b) == 1)
    return MP_VAL;

  /* if a < b then q=0, r = a */
  if (mp_cmp_mag (a, b) == MP_LT) {
    if (d != NULL) {
      res = mp_copy (a, d);
    } else {
      res = MP_OKAY;
    }
    if (c != NULL)
      mp_zero (c);
    return res;
  }

  if ((res = mp_init_size (&q, a->used + 2)) != MP_OKAY)
    return res;
  q.used = a->used + 2;

  if ((res = mp_init (&t1)) != MP_OKAY)
    goto LBL_Q;

  if ((res = mp_init (&t2)) != MP_OKAY)
    goto LBL_T1;

  if ((res = mp_init_copy (&x, a)) != MP_OKAY)
    goto LBL_T2;

  if ((res = mp_init_copy (&y, b)) != MP_OKAY)
    goto LBL_X;

  /* fix the sign */
  neg = (a->sign == b->sign) ? MP_ZPOS : MP_NEG;
  x.sign = y.sign = MP_ZPOS;

  /* normalize both x and y, ensure that y >= b/2, [b == 2**DIGIT_BIT] */
  norm = mp_count_bits(&y) % DIGIT_BIT;
  if (norm < (int)(DIGIT_BIT-1)) {
     norm = (DIGIT_BIT-1) - norm;
     if ((res = mp_mul_2d (&x, norm, &x)) != MP_OKAY)
       goto LBL_Y;
     if ((res = mp_mul_2d (&y, norm, &y)) != MP_OKAY)
       goto LBL_Y;
  } else {
     norm = 0;
  }

  /* note hac does 0 based, so if used==5 then its 0,1,2,3,4, e.g. use 4 */
  n = x.used - 1;
  t = y.used - 1;

  /* while (x >= y*b**n-t) do { q[n-t] += 1; x -= y*b**{n-t} } */
  if ((res = mp_lshd (&y, n - t)) != MP_OKAY)  /* y = y*b**{n-t} */
    goto LBL_Y;

  while (mp_cmp (&x, &y) != MP_LT) {
    ++(q.dp[n - t]);
    if ((res = mp_sub (&x, &y, &x)) != MP_OKAY)
      goto LBL_Y;
  }

  /* reset y by shifting it back down */
  mp_rshd (&y, n - t);

  /* step 3. for i from n down to (t + 1) */
  for (i = n; i >= (t + 1); i--) {
    if (i > x.used)
      continue;

    /* step 3.1 if xi == yt then set q{i-t-1} to b-1,
     * otherwise set q{i-t-1} to (xi*b + x{i-1})/yt */
    if (x.dp[i] == y.dp[t]) {
      q.dp[i - t - 1] = ((((mp_digit)1) << DIGIT_BIT) - 1);
    } else {
      mp_word tmp;
      tmp = ((mp_word) x.dp[i]) << ((mp_word) DIGIT_BIT);
      tmp |= ((mp_word) x.dp[i - 1]);
      tmp /= ((mp_word) y.dp[t]);
      if (tmp > (mp_word) MP_MASK)
	tmp = MP_MASK;
      q.dp[i - t - 1] = (mp_digit) (tmp & (mp_word) (MP_MASK));
    }

    /* while (q{i-t-1} * (yt * b + y{t-1})) >
	     xi * b**2 + xi-1 * b + xi-2

       do q{i-t-1} -= 1;
    */
    q.dp[i - t - 1] = (q.dp[i - t - 1] + 1) & MP_MASK;
    do {
      q.dp[i - t - 1] = (q.dp[i - t - 1] - 1) & MP_MASK;

      /* find left hand */
      mp_zero (&t1);
      t1.dp[0] = (t - 1 < 0) ? 0 : y.dp[t - 1];
      t1.dp[1] = y.dp[t];
      t1.used = 2;
      if ((res = mp_mul_d (&t1, q.dp[i - t - 1], &t1)) != MP_OKAY)
	goto LBL_Y;

      /* find right hand */
      t2.dp[0] = (i - 2 < 0) ? 0 : x.dp[i - 2];
      t2.dp[1] = (i - 1 < 0) ? 0 : x.dp[i - 1];
      t2.dp[2] = x.dp[i];
      t2.used = 3;
    } while (mp_cmp_mag(&t1, &t2) == MP_GT);

    /* step 3.3 x = x - q{i-t-1} * y * b**{i-t-1} */
    if ((res = mp_mul_d (&y, q.dp[i - t - 1], &t1)) != MP_OKAY)
      goto LBL_Y;

    if ((res = mp_lshd (&t1, i - t - 1)) != MP_OKAY)
      goto LBL_Y;

    if ((res = mp_sub (&x, &t1, &x)) != MP_OKAY)
      goto LBL_Y;

    /* if x < 0 then { x = x + y*b**{i-t-1}; q{i-t-1} -= 1; } */
    if (x.sign == MP_NEG) {
      if ((res = mp_copy (&y, &t1)) != MP_OKAY)
	goto LBL_Y;
      if ((res = mp_lshd (&t1, i - t - 1)) != MP_OKAY)
	goto LBL_Y;
      if ((res = mp_add (&x, &t1, &x)) != MP_OKAY)
	goto LBL_Y;

      q.dp[i - t - 1] = (q.dp[i - t - 1] - 1UL) & MP_MASK;
    }
  }

  /* now q is the quotient and x is the remainder
   * [which we have to normalize]
   */

  /* get sign before writing to c */
  x.sign = x.used == 0 ? MP_ZPOS : a->sign;

  if (c != NULL) {
    mp_clamp (&q);
    mp_exch (&q, c);
    c->sign = neg;
  }

  if (d != NULL) {
    if ((res = mp_div_2d (&x, norm, &x, NULL)) != MP_OKAY) {
		goto LBL_Y;
	}
    mp_exch (&x, d);
  }

  res = MP_OKAY;

LBL_Y: mp_clear (&y);
LBL_X: mp_clear (&x);
LBL_T2: mp_clear (&t2);
LBL_T1: mp_clear (&t1);
LBL_Q: mp_clear (&q);
  return res;
}


/* determines the setup value */
static int mp_reduce_2k_setup(mp_int *a, mp_digit *d)
{
   int res, p;
   mp_int tmp;

   if ((res = mp_init(&tmp)) != MP_OKAY)
      return res;

   p = mp_count_bits(a);
   if ((res = mp_2expt(&tmp, p)) != MP_OKAY) {
      mp_clear(&tmp);
      return res;
   }

   if ((res = s_mp_sub(&tmp, a, &tmp)) != MP_OKAY) {
      mp_clear(&tmp);
      return res;
   }

   *d = tmp.dp[0];
   mp_clear(&tmp);
   return MP_OKAY;
}

/* reduce "x" in place modulo "n" using the Diminished Radix algorithm.
 *
 * Based on algorithm from the paper
 *
 * "Generating Efficient Primes for Discrete Log Cryptosystems"
 *                 Chae Hoon Lim, Pil Joong Lee,
 *          POSTECH Information Research Laboratories
 *
 * The modulus must be of a special format [see manual]
 *
 * Has been modified to use algorithm 7.10 from the LTM book instead
 *
 * Input x must be in the range 0 <= x <= (n-1)**2
 */
static int
mp_dr_reduce (mp_int * x, mp_int * n, mp_digit k)
{
  int      err, i, m;
  mp_word  r;
  mp_digit mu, *tmpx1, *tmpx2;

  /* m = digits in modulus */
  m = n->used;

  /* ensure that "x" has at least 2m digits */
  if (x->alloc < m + m) {
    if ((err = mp_grow (x, m + m)) != MP_OKAY)
      return err;
  }

/* top of loop, this is where the code resumes if
 * another reduction pass is required.
 */
top:
  /* aliases for digits */
  /* alias for lower half of x */
  tmpx1 = x->dp;

  /* alias for upper half of x, or x/B**m */
  tmpx2 = x->dp + m;

  /* set carry to zero */
  mu = 0;

  /* compute (x mod B**m) + k * [x/B**m] inline and inplace */
  for (i = 0; i < m; i++) {
      r         = ((mp_word)*tmpx2++) * ((mp_word)k) + *tmpx1 + mu;
      *tmpx1++  = (mp_digit)(r & MP_MASK);
      mu        = (mp_digit)(r >> ((mp_word)DIGIT_BIT));
  }

  /* set final carry */
  *tmpx1++ = mu;

  /* zero words above m */
  for (i = m + 1; i < x->used; i++)
      *tmpx1++ = 0;

  /* clamp, sub and return */
  mp_clamp (x);

  /* if x >= n then subtract and reduce again
   * Each successive "recursion" makes the input smaller and smaller.
   */
  if (mp_cmp_mag (x, n) != MP_LT) {
    s_mp_sub(x, n, x);
    goto top;
  }
  return MP_OKAY;
}

/* sets the value of "d" required for mp_dr_reduce */
static void mp_dr_setup(mp_int *a, mp_digit *d)
{
   /* the casts are required if DIGIT_BIT is one less than
    * the number of bits in a mp_digit [e.g. DIGIT_BIT==31]
    */
   *d = (mp_digit)((((mp_word)1) << ((mp_word)DIGIT_BIT)) -
	((mp_word)a->dp[0]));
}

/* computes xR**-1 == x (mod N) via Montgomery Reduction */
static int
mp_montgomery_reduce (mp_int * x, mp_int * n, mp_digit rho)
{
  int     ix, res, digs;
  mp_digit mu;

  /* can the fast reduction [comba] method be used?
   *
   * Note that unlike in mul you're safely allowed *less*
   * than the available columns [255 per default] since carries
   * are fixed up in the inner loop.
   */
  digs = n->used * 2 + 1;
  if ((digs < MP_WARRAY) &&
      n->used <
      (1 << ((CHAR_BIT * sizeof (mp_word)) - (2 * DIGIT_BIT)))) {
    return fast_mp_montgomery_reduce (x, n, rho);
  }

  /* grow the input as required */
  if (x->alloc < digs) {
    if ((res = mp_grow (x, digs)) != MP_OKAY) {
      return res;
    }
  }
  x->used = digs;

  for (ix = 0; ix < n->used; ix++) {
    /* mu = ai * rho mod b
     *
     * The value of rho must be precalculated via
     * montgomery_setup() such that
     * it equals -1/n0 mod b this allows the
     * following inner loop to reduce the
     * input one digit at a time
     */
    mu = (mp_digit) (((mp_word)x->dp[ix]) * ((mp_word)rho) & MP_MASK);

    /* a = a + mu * m * b**i */
    {
      int iy;
      mp_digit *tmpn, *tmpx, u;
      mp_word r;

      /* alias for digits of the modulus */
      tmpn = n->dp;

      /* alias for the digits of x [the input] */
      tmpx = x->dp + ix;

      /* set the carry to zero */
      u = 0;

      /* Multiply and add in place */
      for (iy = 0; iy < n->used; iy++) {
	/* compute product and sum */
	r       = ((mp_word)mu) * ((mp_word)*tmpn++) +
		  ((mp_word) u) + ((mp_word) * tmpx);

	/* get carry */
	u       = (mp_digit)(r >> ((mp_word) DIGIT_BIT));

	/* fix digit */
	*tmpx++ = (mp_digit)(r & ((mp_word) MP_MASK));
      }
      /* At this point the ix'th digit of x should be zero */


      /* propagate carries upwards as required*/
      while (u) {
	*tmpx   += u;
	u        = *tmpx >> DIGIT_BIT;
	*tmpx++ &= MP_MASK;
      }
    }
  }

  /* at this point the n.used'th least
   * significant digits of x are all zero
   * which means we can shift x to the
   * right by n.used digits and the
   * residue is unchanged.
   */

  /* x = x/b**n.used */
  mp_clamp(x);
  mp_rshd (x, n->used);

  /* if x >= n then x = x - n */
  if (mp_cmp_mag (x, n) != MP_LT) {
    return s_mp_sub (x, n, x);
  }

  return MP_OKAY;
}

/* b = a*2 */
static int mp_mul_2(mp_int * a, mp_int * b)
{
  int     x, res, oldused;

  /* grow to accomodate result */
  if (b->alloc < a->used + 1) {
    if ((res = mp_grow (b, a->used + 1)) != MP_OKAY)
      return res;
  }

  oldused = b->used;
  b->used = a->used;

  {
    mp_digit r, rr, *tmpa, *tmpb;

    /* alias for source */
    tmpa = a->dp;

    /* alias for dest */
    tmpb = b->dp;

    /* carry */
    r = 0;
    for (x = 0; x < a->used; x++) {

      /* get what will be the *next* carry bit from the
       * MSB of the current digit
       */
      rr = *tmpa >> ((mp_digit)(DIGIT_BIT - 1));

      /* now shift up this digit, add in the carry [from the previous] */
      *tmpb++ = ((*tmpa++ << ((mp_digit)1)) | r) & MP_MASK;

      /* copy the carry that would be from the source
       * digit into the next iteration
       */
      r = rr;
    }

    /* new leading digit? */
    if (r != 0) {
      /* add a MSB which is always 1 at this point */
      *tmpb = 1;
      ++(b->used);
    }

    /* now zero any excess digits on the destination
     * that we didn't write to
     */
    tmpb = b->dp + b->used;
    for (x = b->used; x < oldused; x++) {
      *tmpb++ = 0;
    }
  }
  b->sign = a->sign;
  return MP_OKAY;
}

/*
 * shifts with subtractions when the result is greater than b:
 * computes a = B**n mod b without division or multiplication useful for
 * normalizing numbers in a Montgomery system.
 * The method is slightly modified to shift B unconditionally upto just under
 * the leading bit of b.  This saves alot of multiple precision shifting.
 */
static int mp_montgomery_calc_normalization (mp_int * a, mp_int * b)
{
  int     x, bits, res;

  /* how many bits of last digit does b use */
  bits = mp_count_bits (b) % DIGIT_BIT;

  if (b->used > 1) {
     if ((res = mp_2expt (a, (b->used - 1) * DIGIT_BIT + bits - 1)) != MP_OKAY)
	return res;
  } else {
     mp_set(a, 1);
     bits = 1;
  }


  /* now compute C = A * B mod b */
  for (x = bits - 1; x < (int)DIGIT_BIT; x++) {
    if ((res = mp_mul_2 (a, a)) != MP_OKAY)
      return res;
    if (mp_cmp_mag (a, b) != MP_LT) {
      if ((res = s_mp_sub (a, b, a)) != MP_OKAY)
	return res;
    }
  }

  return MP_OKAY;
}

/* setups the montgomery reduction stuff */
static int
mp_montgomery_setup (mp_int * n, mp_digit * rho)
{
  mp_digit x, b;

/* fast inversion mod 2**k
 *
 * Based on the fact that
 *
 * XA = 1 (mod 2**n)  =>  (X(2-XA)) A = 1 (mod 2**2n)
 *                    =>  2*X*A - X*X*A*A = 1
 *                    =>  2*(1) - (1)     = 1
 */
  b = n->dp[0];

  if ((b & 1) == 0)
    return MP_VAL;

  x = (((b + 2) & 4) << 1) + b; /* here x*a==1 mod 2**4 */
  x *= 2 - b * x;               /* here x*a==1 mod 2**8 */
#if !defined(MP_8BIT)
  x *= 2 - b * x;               /* here x*a==1 mod 2**16 */
#endif
#if defined(MP_64BIT) || !(defined(MP_8BIT) || defined(MP_16BIT))
  x *= 2 - b * x;               /* here x*a==1 mod 2**32 */
#endif
#ifdef MP_64BIT
  x *= 2 - b * x;               /* here x*a==1 mod 2**64 */
#endif

  /* rho = -1/m mod b */
  *rho = (unsigned long)(((mp_word)1 << ((mp_word) DIGIT_BIT)) - x) & MP_MASK;

  return MP_OKAY;
}

/* computes Y == G**X mod P, HAC pp.616, Algorithm 14.85
 *
 * Uses a left-to-right k-ary sliding window to compute the modular exponentiation.
 * The value of k changes based on the size of the exponent.
 *
 * Uses Montgomery or Diminished Radix reduction [whichever appropriate]
 */
#ifdef MP_LOW_MEM
# define MP_EXPTMOD_TAB_SIZE 32
#else
# define MP_EXPTMOD_TAB_SIZE 256
#endif

int mp_exptmod_fast (mp_int * G, mp_int * X, mp_int * P, mp_int * Y, int redmode)
{
  mp_int  M[MP_EXPTMOD_TAB_SIZE], res;
  mp_digit buf, mp;
  int     err, bitbuf, bitcpy, bitcnt, mode, digidx, x, y, winsize;

  /* use a pointer to the reduction algorithm.  This allows us to use
   * one of many reduction algorithms without modding the guts of
   * the code with if statements everywhere.
   */
  int     (*redux)(mp_int*,mp_int*,mp_digit);

  /* find window size */
  x = mp_count_bits (X);
  if (x <= 7)
    winsize = 2;
   else if (x <= 36)
    winsize = 3;
   else if (x <= 140)
    winsize = 4;
#ifndef MP_LOW_MEM
   else if (x <= 450)
    winsize = 5;
   else if (x <= 1303)
    winsize = 6;
   else if (x <= 3529)
    winsize = 7;
   else
    winsize = 8;
#else
   else
    winsize = 5;
#endif

  /* init M array */
  /* init first cell */
  if ((err = mp_init_size(&M[1], P->alloc)) != MP_OKAY) {
     return err;
  }

  /* now init the second half of the array */
  for (x = 1<<(winsize-1); x < (1 << winsize); x++) {
    if ((err = mp_init_size(&M[x], P->alloc)) != MP_OKAY) {
      for (y = 1<<(winsize-1); y < x; y++) {
	mp_clear (&M[y]);
      }
      mp_clear(&M[1]);
      return err;
    }
  }

  /* determine and setup reduction code */
  if (redmode == 0) {
     /* now setup montgomery  */
     if ((err = mp_montgomery_setup (P, &mp)) != MP_OKAY) {
	goto LBL_M;
     }

     /* automatically pick the comba one if available (saves quite a few calls/ifs) */
     if (((P->used * 2 + 1) < MP_WARRAY) &&
	  P->used < (1 << ((CHAR_BIT * sizeof (mp_word)) - (2 * DIGIT_BIT)))) {
	redux = fast_mp_montgomery_reduce;
     } else {
	/* use slower baseline Montgomery method */
	redux = mp_montgomery_reduce;
     }
  } else if (redmode == 1) {
     /* setup DR reduction for moduli of the form B**k - b */
     mp_dr_setup(P, &mp);
     redux = mp_dr_reduce;
  } else {
     /* setup DR reduction for moduli of the form 2**k - b */
     if ((err = mp_reduce_2k_setup(P, &mp)) != MP_OKAY) {
	goto LBL_M;
     }
     redux = mp_reduce_2k;
  }

  /* setup result */
  if ((err = mp_init_size (&res, P->alloc)) != MP_OKAY) {
    goto LBL_M;
  }

  /* create M table
   *

   *
   * The first half of the table is not computed though accept for M[0] and M[1]
   */

  if (redmode == 0) {
     /* now we need R mod m */
     if ((err = mp_montgomery_calc_normalization (&res, P)) != MP_OKAY) {
       goto LBL_RES;
     }

     /* now set M[1] to G * R mod m */
     if ((err = mp_mulmod (G, &res, P, &M[1])) != MP_OKAY) {
       goto LBL_RES;
     }
  } else {
     mp_set(&res, 1);
     if ((err = mp_mod(G, P, &M[1])) != MP_OKAY) {
	goto LBL_RES;
     }
  }

  /* compute the value at M[1<<(winsize-1)] by squaring M[1] (winsize-1) times */
  if ((err = mp_copy (&M[1], &M[1 << (winsize - 1)])) != MP_OKAY) {
    goto LBL_RES;
  }

  for (x = 0; x < (winsize - 1); x++) {
    if ((err = mp_sqr (&M[1 << (winsize - 1)], &M[1 << (winsize - 1)])) != MP_OKAY) {
      goto LBL_RES;
    }
    if ((err = redux (&M[1 << (winsize - 1)], P, mp)) != MP_OKAY) {
      goto LBL_RES;
    }
  }

  /* create upper table */
  for (x = (1 << (winsize - 1)) + 1; x < (1 << winsize); x++) {
    if ((err = mp_mul (&M[x - 1], &M[1], &M[x])) != MP_OKAY) {
      goto LBL_RES;
    }
    if ((err = redux (&M[x], P, mp)) != MP_OKAY) {
      goto LBL_RES;
    }
  }

  /* set initial mode and bit cnt */
  mode   = 0;
  bitcnt = 1;
  buf    = 0;
  digidx = X->used - 1;
  bitcpy = 0;
  bitbuf = 0;

  for (;;) {
    /* grab next digit as required */
    if (--bitcnt == 0) {
      /* if digidx == -1 we are out of digits so break */
      if (digidx == -1) {
	break;
      }
      /* read next digit and reset bitcnt */
      buf    = X->dp[digidx--];
      bitcnt = (int)DIGIT_BIT;
    }

    /* grab the next msb from the exponent */
    y     = (mp_digit)(buf >> (DIGIT_BIT - 1)) & 1;
    buf <<= (mp_digit)1;

    /* if the bit is zero and mode == 0 then we ignore it
     * These represent the leading zero bits before the first 1 bit
     * in the exponent.  Technically this opt is not required but it
     * does lower the # of trivial squaring/reductions used
     */
    if (mode == 0 && y == 0) {
      continue;
    }

    /* if the bit is zero and mode == 1 then we square */
    if (mode == 1 && y == 0) {
      if ((err = mp_sqr (&res, &res)) != MP_OKAY) {
	goto LBL_RES;
      }
      if ((err = redux (&res, P, mp)) != MP_OKAY) {
	goto LBL_RES;
      }
      continue;
    }

    /* else we add it to the window */
    bitbuf |= (y << (winsize - ++bitcpy));
    mode    = 2;

    if (bitcpy == winsize) {
      /* ok window is filled so square as required and multiply  */
      /* square first */
      for (x = 0; x < winsize; x++) {
	if ((err = mp_sqr (&res, &res)) != MP_OKAY) {
	  goto LBL_RES;
	}
	if ((err = redux (&res, P, mp)) != MP_OKAY) {
	  goto LBL_RES;
	}
      }

      /* then multiply */
      if ((err = mp_mul (&res, &M[bitbuf], &res)) != MP_OKAY) {
	goto LBL_RES;
      }
      if ((err = redux (&res, P, mp)) != MP_OKAY) {
	goto LBL_RES;
      }

      /* empty window and reset */
      bitcpy = 0;
      bitbuf = 0;
      mode   = 1;
    }
  }

  /* if bits remain then square/multiply */
  if (mode == 2 && bitcpy > 0) {
    /* square then multiply if the bit is set */
    for (x = 0; x < bitcpy; x++) {
      if ((err = mp_sqr (&res, &res)) != MP_OKAY) {
	goto LBL_RES;
      }
      if ((err = redux (&res, P, mp)) != MP_OKAY) {
	goto LBL_RES;
      }

      /* get next bit of the window */
      bitbuf <<= 1;
      if ((bitbuf & (1 << winsize)) != 0) {
	/* then multiply */
	if ((err = mp_mul (&res, &M[1], &res)) != MP_OKAY) {
	  goto LBL_RES;
	}
	if ((err = redux (&res, P, mp)) != MP_OKAY) {
	  goto LBL_RES;
	}
      }
    }
  }

  if (redmode == 0) {
     /* fixup result if Montgomery reduction is used
      * recall that any value in a Montgomery system is
      * actually multiplied by R mod n.  So we have
      * to reduce one more time to cancel out the factor
      * of R.
      */
     if ((err = redux(&res, P, mp)) != MP_OKAY) {
       goto LBL_RES;
     }
  }

  /* swap res with Y */
  mp_exch (&res, Y);
  err = MP_OKAY;
LBL_RES: mp_clear (&res);
LBL_M:
  mp_clear(&M[1]);
  for (x = 1<<(winsize-1); x < (1 << winsize); x++) {
    mp_clear (&M[x]);
  }
  return err;
}




/* hac 14.61, pp608 */
int mp_invmod_slow (mp_int * a, mp_int * b, mp_int * c)
{
  mp_int  x, y, u, v, A, B, C, D;
  int     res;

  /* b cannot be negative */
  if (b->sign == MP_NEG || mp_iszero(b) == 1)
    return MP_VAL;

  /* init temps */
  if ((res = mp_init_multi(&x, &y, &u, &v,
			   &A, &B, &C, &D, NULL)) != MP_OKAY) {
     return res;
  }

  /* x = a, y = b */
  if ((res = mp_mod(a, b, &x)) != MP_OKAY)
      goto LBL_ERR;
  if ((res = mp_copy (b, &y)) != MP_OKAY)
    goto LBL_ERR;

  /* 2. [modified] if x,y are both even then return an error! */
  if (mp_iseven (&x) == 1 && mp_iseven (&y) == 1) {
    res = MP_VAL;
    goto LBL_ERR;
  }

  /* 3. u=x, v=y, A=1, B=0, C=0,D=1 */
  if ((res = mp_copy (&x, &u)) != MP_OKAY)
    goto LBL_ERR;
  if ((res = mp_copy (&y, &v)) != MP_OKAY)
    goto LBL_ERR;
  mp_set (&A, 1);
  mp_set (&D, 1);

top:
  /* 4.  while u is even do */
  while (mp_iseven (&u) == 1) {
    /* 4.1 u = u/2 */
    if ((res = mp_div_2 (&u, &u)) != MP_OKAY)
      goto LBL_ERR;
    /* 4.2 if A or B is odd then */
    if (mp_isodd (&A) == 1 || mp_isodd (&B) == 1) {
      /* A = (A+y)/2, B = (B-x)/2 */
      if ((res = mp_add (&A, &y, &A)) != MP_OKAY)
	 goto LBL_ERR;
      if ((res = mp_sub (&B, &x, &B)) != MP_OKAY)
	 goto LBL_ERR;
    }
    /* A = A/2, B = B/2 */
    if ((res = mp_div_2 (&A, &A)) != MP_OKAY)
      goto LBL_ERR;
    if ((res = mp_div_2 (&B, &B)) != MP_OKAY)
      goto LBL_ERR;
  }

  /* 5.  while v is even do */
  while (mp_iseven (&v) == 1) {
    /* 5.1 v = v/2 */
    if ((res = mp_div_2 (&v, &v)) != MP_OKAY)
      goto LBL_ERR;
    /* 5.2 if C or D is odd then */
    if (mp_isodd (&C) == 1 || mp_isodd (&D) == 1) {
      /* C = (C+y)/2, D = (D-x)/2 */
      if ((res = mp_add (&C, &y, &C)) != MP_OKAY)
	 goto LBL_ERR;
      if ((res = mp_sub (&D, &x, &D)) != MP_OKAY)
	 goto LBL_ERR;
    }
    /* C = C/2, D = D/2 */
    if ((res = mp_div_2 (&C, &C)) != MP_OKAY)
      goto LBL_ERR;
    if ((res = mp_div_2 (&D, &D)) != MP_OKAY)
      goto LBL_ERR;
  }

  /* 6.  if u >= v then */
  if (mp_cmp (&u, &v) != MP_LT) {
    /* u = u - v, A = A - C, B = B - D */
    if ((res = mp_sub (&u, &v, &u)) != MP_OKAY)
      goto LBL_ERR;

    if ((res = mp_sub (&A, &C, &A)) != MP_OKAY)
      goto LBL_ERR;

    if ((res = mp_sub (&B, &D, &B)) != MP_OKAY)
      goto LBL_ERR;
  } else {
    /* v - v - u, C = C - A, D = D - B */
    if ((res = mp_sub (&v, &u, &v)) != MP_OKAY)
      goto LBL_ERR;

    if ((res = mp_sub (&C, &A, &C)) != MP_OKAY)
      goto LBL_ERR;

    if ((res = mp_sub (&D, &B, &D)) != MP_OKAY)
      goto LBL_ERR;
  }

  /* if not zero goto step 4 */
  if (mp_iszero (&u) == 0)
    goto top;

  /* now a = C, b = D, gcd == g*v */

  /* if v != 1 then there is no inverse */
  if (mp_cmp_d (&v, 1) != MP_EQ) {
    res = MP_VAL;
    goto LBL_ERR;
  }

  /* if its too low */
  while (mp_cmp_d(&C, 0) == MP_LT) {
      if ((res = mp_add(&C, b, &C)) != MP_OKAY)
	 goto LBL_ERR;
  }

  /* too big */
  while (mp_cmp_mag(&C, b) != MP_LT) {
      if ((res = mp_sub(&C, b, &C)) != MP_OKAY)
	 goto LBL_ERR;
  }

  /* C is now the inverse */
  mp_exch (&C, c);
  res = MP_OKAY;
LBL_ERR:
  mp_clear_multi (&x, &y, &u, &v, &A, &B, &C, &D, NULL);
  return res;
}

/* shift left by a certain bit count */
int mp_mul_2d (mp_int * a, int b, mp_int * c)
{
  mp_digit d;
  int      res;

  /* copy */
  if (a != c) {
     if ((res = mp_copy (a, c)) != MP_OKAY)
       return res;
  }

  if (c->alloc < (int)(c->used + b/DIGIT_BIT + 1)) {
     if ((res = mp_grow (c, c->used + b / DIGIT_BIT + 1)) != MP_OKAY)
       return res;
  }

  /* shift by as many digits in the bit count */
  if (b >= (int)DIGIT_BIT) {
    if ((res = mp_lshd (c, b / DIGIT_BIT)) != MP_OKAY)
      return res;
  }

  /* shift any bit count < DIGIT_BIT */
  d = (mp_digit) (b % DIGIT_BIT);
  if (d != 0) {
    mp_digit *tmpc, shift, mask, r, rr;
    int x;

    /* bitmask for carries */
    mask = (((mp_digit)1) << d) - 1;

    /* shift for msbs */
    shift = DIGIT_BIT - d;

    /* alias */
    tmpc = c->dp;

    /* carry */
    r    = 0;
    for (x = 0; x < c->used; x++) {
      /* get the higher bits of the current word */
      rr = (*tmpc >> shift) & mask;

      /* shift the current word and OR in the carry */
      *tmpc = ((*tmpc << d) | r) & MP_MASK;
      ++tmpc;

      /* set the carry to the carry bits of the current word */
      r = rr;
    }

    /* set final carry */
    if (r != 0) {
       c->dp[(c->used)++] = r;
    }
  }
  mp_clamp (c);
  return MP_OKAY;
}

/* high level multiplication (handles sign) */
int mp_mul (mp_int * a, mp_int * b, mp_int * c)
{
  int     res, neg;
  neg = (a->sign == b->sign) ? MP_ZPOS : MP_NEG;

  {
    /* can we use the fast multiplier?
     *
     * The fast multiplier can be used if the output will
     * have less than MP_WARRAY digits and the number of
     * digits won't affect carry propagation
     */
    int     digs = a->used + b->used + 1;

    if ((digs < MP_WARRAY) &&
	MIN(a->used, b->used) <=
	(1 << ((CHAR_BIT * sizeof (mp_word)) - (2 * DIGIT_BIT)))) {
      res = fast_s_mp_mul_digs (a, b, c, digs);
    } else
      res = s_mp_mul_digs(a, b, c, a->used + b->used + 1);
  }
  c->sign = (c->used > 0) ? neg : MP_ZPOS;
  return res;
}

/* determines the setup value */
static int mp_reduce_2k_setup_l(mp_int *a, mp_int *d)
{
   int    res;
   mp_int tmp;

   if ((res = mp_init(&tmp)) != MP_OKAY)
      return res;

   if ((res = mp_2expt(&tmp, mp_count_bits(a))) != MP_OKAY)
      goto ERR;

   if ((res = s_mp_sub(&tmp, a, d)) != MP_OKAY)
      goto ERR;

ERR:
   mp_clear(&tmp);
   return res;
}

/* reduces a modulo n where n is of the form 2**p - d
   This differs from reduce_2k since "d" can be larger
   than a single digit.
*/
static int mp_reduce_2k_l(mp_int *a, mp_int *n, mp_int *d)
{
   mp_int q;
   int    p, res;

   if ((res = mp_init(&q)) != MP_OKAY) {
      return res;
   }

   p = mp_count_bits(n);
top:
   /* q = a/2**p, a = a mod 2**p */
   if ((res = mp_div_2d(a, p, &q, a)) != MP_OKAY) {
      goto ERR;
   }

   /* q = q * d */
   if ((res = mp_mul(&q, d, &q)) != MP_OKAY) {
      goto ERR;
   }

   /* a = a + q */
   if ((res = s_mp_add(a, &q, a)) != MP_OKAY) {
      goto ERR;
   }

   if (mp_cmp_mag(a, n) != MP_LT) {
      s_mp_sub(a, n, a);
      goto top;
   }

ERR:
   mp_clear(&q);
   return res;
}

/* reduces x mod m, assumes 0 < x < m**2, mu is
 * precomputed via mp_reduce_setup.
 * From HAC pp.604 Algorithm 14.42
 */
static int mp_reduce (mp_int * x, mp_int * m, mp_int * mu)
{
  mp_int  q;
  int     res, um = m->used;

  /* q = x */
  if ((res = mp_init_copy (&q, x)) != MP_OKAY)
    return res;

  /* q1 = x / b**(k-1)  */
  mp_rshd (&q, um - 1);

  /* according to HAC this optimization is ok */
  if (((unsigned long) um) > (((mp_digit)1) << (DIGIT_BIT - 1))) {
    if ((res = mp_mul (&q, mu, &q)) != MP_OKAY)
      goto CLEANUP;
  } else {
    if ((res = s_mp_mul_high_digs (&q, mu, &q, um)) != MP_OKAY)
      goto CLEANUP;
  }

  /* q3 = q2 / b**(k+1) */
  mp_rshd (&q, um + 1);

  /* x = x mod b**(k+1), quick (no division) */
  if ((res = mp_mod_2d (x, DIGIT_BIT * (um + 1), x)) != MP_OKAY)
    goto CLEANUP;

  /* q = q * m mod b**(k+1), quick (no division) */
  if ((res = s_mp_mul_digs (&q, m, &q, um + 1)) != MP_OKAY)
    goto CLEANUP;

  /* x = x - q */
  if ((res = mp_sub (x, &q, x)) != MP_OKAY)
    goto CLEANUP;

  /* If x < 0, add b**(k+1) to it */
  if (mp_cmp_d (x, 0) == MP_LT) {
    mp_set (&q, 1);
    if ((res = mp_lshd (&q, um + 1)) != MP_OKAY)
      goto CLEANUP;
    if ((res = mp_add (x, &q, x)) != MP_OKAY)
      goto CLEANUP;
  }

  /* Back off if it's too big */
  while (mp_cmp (x, m) != MP_LT) {
    if ((res = s_mp_sub (x, m, x)) != MP_OKAY)
      goto CLEANUP;
  }

CLEANUP:
  mp_clear (&q);

  return res;
}

static int
s_mp_exptmod (mp_int * G, mp_int * X, mp_int * P, mp_int * Y, int redmode)
{
  mp_int  M[MP_EXPTMOD_TAB_SIZE], res, mu;
  mp_digit buf;
  int     err, bitbuf, bitcpy, bitcnt, mode, digidx, x, y, winsize;
  int (*redux)(mp_int*,mp_int*,mp_int*);

  /* find window size */
  x = mp_count_bits (X);
  if (x <= 7)
    winsize = 2;
   else if (x <= 36)
    winsize = 3;
   else if (x <= 140)
    winsize = 4;
#ifndef MP_LOW_MEM
   else if (x <= 450)
    winsize = 5;
   else if (x <= 1303)
    winsize = 6;
   else if (x <= 3529)
    winsize = 7;
   else
    winsize = 8;
#else
   else
    winsize = 5;
#endif

  /* init M array */
  /* init first cell */
  if ((err = mp_init(&M[1])) != MP_OKAY)
     return err;

  /* now init the second half of the array */
  for (x = 1<<(winsize-1); x < (1 << winsize); x++) {
    if ((err = mp_init(&M[x])) != MP_OKAY) {
      for (y = 1<<(winsize-1); y < x; y++)
	mp_clear (&M[y]);
      mp_clear(&M[1]);
      return err;
    }
  }

  /* create mu, used for Barrett reduction */
  if ((err = mp_init (&mu)) != MP_OKAY)
    goto LBL_M;

  if (redmode == 0) {
     if ((err = mp_reduce_setup (&mu, P)) != MP_OKAY)
	goto LBL_MU;
     redux = mp_reduce;
  } else {
     if ((err = mp_reduce_2k_setup_l (P, &mu)) != MP_OKAY)
	goto LBL_MU;
     redux = mp_reduce_2k_l;
  }

  /* create M table
   *
   * The M table contains powers of the base,
   * e.g. M[x] = G**x mod P
   *
   * The first half of the table is not
   * computed though accept for M[0] and M[1]
   */
  if ((err = mp_mod (G, P, &M[1])) != MP_OKAY)
    goto LBL_MU;

  /* compute the value at M[1<<(winsize-1)] by squaring
   * M[1] (winsize-1) times
   */
  if ((err = mp_copy (&M[1], &M[1 << (winsize - 1)])) != MP_OKAY)
    goto LBL_MU;

  for (x = 0; x < (winsize - 1); x++) {
    /* square it */
    if ((err = mp_sqr (&M[1 << (winsize - 1)],
		       &M[1 << (winsize - 1)])) != MP_OKAY) {
      goto LBL_MU;
    }

    /* reduce modulo P */
    if ((err = redux (&M[1 << (winsize - 1)], P, &mu)) != MP_OKAY)
      goto LBL_MU;
  }

  /* create upper table, that is M[x] = M[x-1] * M[1] (mod P)
   * for x = (2**(winsize - 1) + 1) to (2**winsize - 1)
   */
  for (x = (1 << (winsize - 1)) + 1; x < (1 << winsize); x++) {
    if ((err = mp_mul (&M[x - 1], &M[1], &M[x])) != MP_OKAY)
      goto LBL_MU;
    if ((err = redux (&M[x], P, &mu)) != MP_OKAY)
      goto LBL_MU;
  }

  /* setup result */
  if ((err = mp_init (&res)) != MP_OKAY)
    goto LBL_MU;
  mp_set (&res, 1);

  /* set initial mode and bit cnt */
  mode   = 0;
  bitcnt = 1;
  buf    = 0;
  digidx = X->used - 1;
  bitcpy = 0;
  bitbuf = 0;

  for (;;) {
    /* grab next digit as required */
    if (--bitcnt == 0) {
      /* if digidx == -1 we are out of digits */
      if (digidx == -1)
	break;
      /* read next digit and reset the bitcnt */
      buf    = X->dp[digidx--];
      bitcnt = (int) DIGIT_BIT;
    }

    /* grab the next msb from the exponent */
    y     = (buf >> (mp_digit)(DIGIT_BIT - 1)) & 1;
    buf <<= (mp_digit)1;

    /* if the bit is zero and mode == 0 then we ignore it
     * These represent the leading zero bits before the first 1 bit
     * in the exponent.  Technically this opt is not required but it
     * does lower the # of trivial squaring/reductions used
     */
    if (mode == 0 && y == 0)
      continue;

    /* if the bit is zero and mode == 1 then we square */
    if (mode == 1 && y == 0) {
      if ((err = mp_sqr (&res, &res)) != MP_OKAY)
	goto LBL_RES;
      if ((err = redux (&res, P, &mu)) != MP_OKAY)
	goto LBL_RES;
      continue;
    }

    /* else we add it to the window */
    bitbuf |= (y << (winsize - ++bitcpy));
    mode    = 2;

    if (bitcpy == winsize) {
      /* ok window is filled so square as required and multiply  */
      /* square first */
      for (x = 0; x < winsize; x++) {
	if ((err = mp_sqr (&res, &res)) != MP_OKAY)
	  goto LBL_RES;
	if ((err = redux (&res, P, &mu)) != MP_OKAY)
	  goto LBL_RES;
      }

      /* then multiply */
      if ((err = mp_mul (&res, &M[bitbuf], &res)) != MP_OKAY)
	goto LBL_RES;
      if ((err = redux (&res, P, &mu)) != MP_OKAY)
	goto LBL_RES;

      /* empty window and reset */
      bitcpy = 0;
      bitbuf = 0;
      mode   = 1;
    }
  }

  /* if bits remain then square/multiply */
  if (mode == 2 && bitcpy > 0) {
    /* square then multiply if the bit is set */
    for (x = 0; x < bitcpy; x++) {
      if ((err = mp_sqr (&res, &res)) != MP_OKAY)
	goto LBL_RES;
      if ((err = redux (&res, P, &mu)) != MP_OKAY)
	goto LBL_RES;

      bitbuf <<= 1;
      if ((bitbuf & (1 << winsize)) != 0) {
	/* then multiply */
	if ((err = mp_mul (&res, &M[1], &res)) != MP_OKAY)
	  goto LBL_RES;
	if ((err = redux (&res, P, &mu)) != MP_OKAY)
	  goto LBL_RES;
      }
    }
  }

  mp_exch (&res, Y);
  err = MP_OKAY;
LBL_RES:
  mp_clear (&res);
LBL_MU:
  mp_clear (&mu);
LBL_M:
  mp_clear(&M[1]);
  for (x = 1<<(winsize-1); x < (1 << winsize); x++)
    mp_clear (&M[x]);
  return err;
}

/* computes xR**-1 == x (mod N) via Montgomery Reduction
 *
 * This is an optimized implementation of montgomery_reduce
 * which uses the comba method to quickly calculate the columns of the
 * reduction.
 *
 * Based on Algorithm 14.32 on pp.601 of HAC.
*/
int fast_mp_montgomery_reduce (mp_int * x, mp_int * n, mp_digit rho)
{
  int     ix, res, olduse;
  mp_word W[MP_WARRAY];

  /* get old used count */
  olduse = x->used;

  /* grow a as required */
  if (x->alloc < n->used + 1) {
    if ((res = mp_grow (x, n->used + 1)) != MP_OKAY)
      return res;
  }

  /* first we have to get the digits of the input into
   * an array of double precision words W[...]
   */
  {
    mp_word *_W;
    mp_digit *tmpx;

    /* alias for the W[] array */
    _W   = W;

    /* alias for the digits of  x*/
    tmpx = x->dp;

    /* copy the digits of a into W[0..a->used-1] */
    for (ix = 0; ix < x->used; ix++)
      *_W++ = *tmpx++;

    /* zero the high words of W[a->used..m->used*2] */
    for (; ix < n->used * 2 + 1; ix++)
      *_W++ = 0;
  }

  /* now we proceed to zero successive digits
   * from the least significant upwards
   */
  for (ix = 0; ix < n->used; ix++) {
    /* mu = ai * m' mod b
     *
     * We avoid a double precision multiplication (which isn't required)
     * by casting the value down to a mp_digit.  Note this requires
     * that W[ix-1] have  the carry cleared (see after the inner loop)
     */
    mp_digit mu;

    mu = (mp_digit) (((W[ix] & MP_MASK) * rho) & MP_MASK);

    /* a = a + mu * m * b**i
     *
     * This is computed in place and on the fly.  The multiplication
     * by b**i is handled by offseting which columns the results
     * are added to.
     *
     * Note the comba method normally doesn't handle carries in the
     * inner loop In this case we fix the carry from the previous
     * column since the Montgomery reduction requires digits of the
     * result (so far) [see above] to work.  This is
     * handled by fixing up one carry after the inner loop.  The
     * carry fixups are done in order so after these loops the
     * first m->used words of W[] have the carries fixed
     */
    {
      int iy;
      mp_digit *tmpn;
      mp_word *_W;

      /* alias for the digits of the modulus */
      tmpn = n->dp;

      /* Alias for the columns set by an offset of ix */
      _W = W + ix;

      /* inner loop */
      for (iy = 0; iy < n->used; iy++) {
	  *_W++ += ((mp_word)mu) * ((mp_word)*tmpn++);
      }
    }

    /* now fix carry for next digit, W[ix+1] */
    W[ix + 1] += W[ix] >> ((mp_word) DIGIT_BIT);
  }

  /* now we have to propagate the carries and
   * shift the words downward [all those least
   * significant digits we zeroed].
   */
  {
    mp_digit *tmpx;
    mp_word *_W, *_W1;

    /* nox fix rest of carries */

    /* alias for current word */
    _W1 = W + ix;

    /* alias for next word, where the carry goes */
    _W = W + ++ix;

    for (; ix <= n->used * 2 + 1; ix++)
      *_W++ += *_W1++ >> ((mp_word) DIGIT_BIT);

    /* copy out, A = A/b**n
     *
     * The result is A/b**n but instead of converting from an
     * array of mp_word to mp_digit than calling mp_rshd
     * we just copy them in the right order
     */

    /* alias for destination word */
    tmpx = x->dp;

    /* alias for shifted double precision result */
    _W = W + n->used;

    for (ix = 0; ix < n->used + 1; ix++)
      *tmpx++ = (mp_digit)(*_W++ & ((mp_word) MP_MASK));

    /* zero oldused digits, if the input a was larger than
     * m->used+1 we'll have to clear the digits
     */
    for (; ix < olduse; ix++)
      *tmpx++ = 0;
  }

  /* set the max used and clamp */
  x->used = n->used + 1;
  mp_clamp (x);

  /* if A >= m then A = A - m */
  if (mp_cmp_mag (x, n) != MP_LT)
    return s_mp_sub (x, n, x);
  return MP_OKAY;
}

/* Fast (comba) multiplier
 *
 * This is the fast column-array [comba] multiplier.  It is
 * designed to compute the columns of the product first
 * then handle the carries afterwards.  This has the effect
 * of making the nested loops that compute the columns very
 * simple and schedulable on super-scalar processors.
 *
 * This has been modified to produce a variable number of
 * digits of output so if say only a half-product is required
 * you don't have to compute the upper half (a feature
 * required for fast Barrett reduction).
 *
 * Based on Algorithm 14.12 on pp.595 of HAC.
 *
 */
int fast_s_mp_mul_digs (mp_int * a, mp_int * b, mp_int * c, int digs)
{
  int     olduse, res, pa, ix, iz;
  mp_digit W[MP_WARRAY];
  mp_word  _W;

  /* grow the destination as required */
  if (c->alloc < digs) {
    if ((res = mp_grow (c, digs)) != MP_OKAY)
      return res;
  }

  /* number of output digits to produce */
  pa = MIN(digs, a->used + b->used);

  /* clear the carry */
  _W = 0;
  for (ix = 0; ix < pa; ix++) {
      int      tx, ty;
      int      iy;
      mp_digit *tmpx, *tmpy;

      /* get offsets into the two bignums */
      ty = MIN(b->used-1, ix);
      tx = ix - ty;

      /* setup temp aliases */
      tmpx = a->dp + tx;
      tmpy = b->dp + ty;

      /* this is the number of times the loop will iterrate, essentially
	 while (tx++ < a->used && ty-- >= 0) { ... }
       */
      iy = MIN(a->used-tx, ty+1);

      /* execute loop */
      for (iz = 0; iz < iy; ++iz) {
	 _W += ((mp_word)*tmpx++)*((mp_word)*tmpy--);

      }

      /* store term */
      W[ix] = ((mp_digit)_W) & MP_MASK;

      /* make next carry */
      _W = _W >> ((mp_word)DIGIT_BIT);
 }

  /* setup dest */
  olduse  = c->used;
  c->used = pa;

  {
    mp_digit *tmpc;

    tmpc = c->dp;
    for (ix = 0; ix < pa+1; ix++) {
      /* now extract the previous digit [below the carry] */
      *tmpc++ = W[ix];
    }

    /* clear unused digits [that existed in the old copy of c] */
    for (; ix < olduse; ix++)
      *tmpc++ = 0;
  }
  mp_clamp (c);
  return MP_OKAY;
}


int mp_init_multi(mp_int *mp, ...)
{
    int res = MP_OKAY;      /* Assume ok until proven otherwise */
    int n = 0;                 /* Number of ok inits */
    mp_int* cur_arg = mp;
    va_list args;

    va_start(args, mp);        /* init args to next argument from caller */
    while (cur_arg != NULL) {
	if (mp_init(cur_arg) != MP_OKAY) {
	    /* Oops - error! Back-track and mp_clear what we already
	       succeeded in init-ing, then return error.
	    */
	    va_list clean_args;

	    /* end the current list */
	    va_end(args);

	    /* now start cleaning up */
	    cur_arg = mp;
	    va_start(clean_args, mp);
	    while (n--) {
		mp_clear(cur_arg);
		cur_arg = va_arg(clean_args, mp_int*);
	    }
	    va_end(clean_args);
	    res = MP_MEM;
	    break;
	}
	n++;
	cur_arg = va_arg(args, mp_int*);
    }
    va_end(args);
    return res;                /* Assumed ok, if error flagged above. */
}


/* calc a value mod 2**b */
int
mp_mod_2d (mp_int * a, int b, mp_int * c)
{
  int     x, res;

  /* if b is <= 0 then zero the int */
  if (b <= 0) {
    mp_zero (c);
    return MP_OKAY;
  }

  /* if the modulus is larger than the value than return */
  if (b >= (int) (a->used * DIGIT_BIT)) {
    res = mp_copy (a, c);
    return res;
  }

  /* copy */
  if ((res = mp_copy (a, c)) != MP_OKAY)
    return res;

  /* zero digits above the last digit of the modulus */
  for (x = (b / DIGIT_BIT) + ((b % DIGIT_BIT) == 0 ? 0 : 1); x < c->used; x++)
    c->dp[x] = 0;
  /* clear the digit that is not completely outside/inside the modulus */
  c->dp[b / DIGIT_BIT] &=
    (mp_digit) ((((mp_digit) 1) << (((mp_digit) b) % DIGIT_BIT)) - ((mp_digit) 1));
  mp_clamp (c);
  return MP_OKAY;
}




/* pre-calculate the value required for Barrett reduction
 * For a given modulus "b" it calulates the value required in "a"
 */
int mp_reduce_setup (mp_int * a, mp_int * b)
{
  int     res;

  if ((res = mp_2expt (a, b->used * 2 * DIGIT_BIT)) != MP_OKAY) {
    return res;
  }
  return mp_div (a, b, a, NULL);
}



/* computes b = a*a */
int
mp_sqr (mp_int * a, mp_int * b)
{
  int     res;

  {
    /* can we use the fast comba multiplier? */
    if ((a->used * 2 + 1) < MP_WARRAY &&
	 a->used <
	 (1 << (sizeof(mp_word) * CHAR_BIT - 2*DIGIT_BIT - 1))) {
      res = fast_s_mp_sqr (a, b);
    } else
      res = s_mp_sqr (a, b);
  }
  b->sign = MP_ZPOS;
  return res;
}

/* high level subtraction (handles signs) */
int
mp_sub (mp_int * a, mp_int * b, mp_int * c)
{
  int     sa, sb, res;

  sa = a->sign;
  sb = b->sign;

  if (sa != sb) {
    /* subtract a negative from a positive, OR */
    /* subtract a positive from a negative. */
    /* In either case, ADD their magnitudes, */
    /* and use the sign of the first number. */
    c->sign = sa;
    res = s_mp_add (a, b, c);
  } else {
    /* subtract a positive from a positive, OR */
    /* subtract a negative from a negative. */
    /* First, take the difference between their */
    /* magnitudes, then... */
    if (mp_cmp_mag (a, b) != MP_LT) {
      /* Copy the sign from the first */
      c->sign = sa;
      /* The first has a larger or equal magnitude */
      res = s_mp_sub (a, b, c);
    } else {
      /* The result has the *opposite* sign from */
      /* the first number. */
      c->sign = (sa == MP_ZPOS) ? MP_NEG : MP_ZPOS;
      /* The second has a larger magnitude */
      res = s_mp_sub (b, a, c);
    }
  }
  return res;
}

/* low level addition, based on HAC pp.594, Algorithm 14.7 */
int
s_mp_add (mp_int * a, mp_int * b, mp_int * c)
{
  mp_int *x;
  int     olduse, res, min, max;

  /* find sizes, we let |a| <= |b| which means we have to sort
   * them.  "x" will point to the input with the most digits
   */
  if (a->used > b->used) {
    min = b->used;
    max = a->used;
    x = a;
  } else {
    min = a->used;
    max = b->used;
    x = b;
  }

  /* init result */
  if (c->alloc < max + 1) {
    if ((res = mp_grow (c, max + 1)) != MP_OKAY) {
      return res;
    }
  }

  /* get old used digit count and set new one */
  olduse = c->used;
  c->used = max + 1;

  {
    mp_digit u, *tmpa, *tmpb, *tmpc;
    int i;

    /* alias for digit pointers */

    /* first input */
    tmpa = a->dp;

    /* second input */
    tmpb = b->dp;

    /* destination */
    tmpc = c->dp;

    /* zero the carry */
    u = 0;
    for (i = 0; i < min; i++) {
      /* Compute the sum at one digit, T[i] = A[i] + B[i] + U */
      *tmpc = *tmpa++ + *tmpb++ + u;

      /* U = carry bit of T[i] */
      u = *tmpc >> ((mp_digit)DIGIT_BIT);

      /* take away carry bit from T[i] */
      *tmpc++ &= MP_MASK;
    }

    /* now copy higher words if any, that is in A+B
     * if A or B has more digits add those in
     */
    if (min != max) {
      for (; i < max; i++) {
	/* T[i] = X[i] + U */
	*tmpc = x->dp[i] + u;

	/* U = carry bit of T[i] */
	u = *tmpc >> ((mp_digit)DIGIT_BIT);

	/* take away carry bit from T[i] */
	*tmpc++ &= MP_MASK;
      }
    }

    /* add carry */
    *tmpc++ = u;

    /* clear digits above oldused */
    for (i = c->used; i < olduse; i++) {
      *tmpc++ = 0;
    }
  }

  mp_clamp (c);
  return MP_OKAY;
}

/* multiplies |a| * |b| and only computes upto digs digits of result
 * HAC pp. 595, Algorithm 14.12  Modified so you can control how
 * many digits of output are created.
 */
int s_mp_mul_digs (mp_int * a, mp_int * b, mp_int * c, int digs)
{
  mp_int  t;
  int     res, pa, pb, ix, iy;
  mp_digit u;
  mp_word r;
  mp_digit tmpx, *tmpt, *tmpy;

  /* can we use the fast multiplier? */
  if (((digs) < MP_WARRAY) &&
      MIN (a->used, b->used) <
	  (1 << ((CHAR_BIT * sizeof (mp_word)) - (2 * DIGIT_BIT)))) {
    return fast_s_mp_mul_digs (a, b, c, digs);
  }

  if ((res = mp_init_size (&t, digs)) != MP_OKAY) {
    return res;
  }
  t.used = digs;

  /* compute the digits of the product directly */
  pa = a->used;
  for (ix = 0; ix < pa; ix++) {
    /* set the carry to zero */
    u = 0;

    /* limit ourselves to making digs digits of output */
    pb = MIN (b->used, digs - ix);

    /* setup some aliases */
    /* copy of the digit from a used within the nested loop */
    tmpx = a->dp[ix];

    /* an alias for the destination shifted ix places */
    tmpt = t.dp + ix;

    /* an alias for the digits of b */
    tmpy = b->dp;

    /* compute the columns of the output and propagate the carry */
    for (iy = 0; iy < pb; iy++) {
      /* compute the column as a mp_word */
      r       = ((mp_word)*tmpt) +
		((mp_word)tmpx) * ((mp_word)*tmpy++) +
		((mp_word) u);

      /* the new column is the lower part of the result */
      *tmpt++ = (mp_digit) (r & ((mp_word) MP_MASK));

      /* get the carry word from the result */
      u       = (mp_digit) (r >> ((mp_word) DIGIT_BIT));
    }
    /* set carry if it is placed below digs */
    if (ix + iy < digs) {
      *tmpt = u;
    }
  }

  mp_clamp (&t);
  mp_exch (&t, c);

  mp_clear (&t);
  return MP_OKAY;
}

/* low level subtraction (assumes |a| > |b|), HAC pp.595 Algorithm 14.9 */
int
s_mp_sub (mp_int * a, mp_int * b, mp_int * c)
{
  int     olduse, res, min, max;

  /* find sizes */
  min = b->used;
  max = a->used;

  /* init result */
  if (c->alloc < max) {
    if ((res = mp_grow (c, max)) != MP_OKAY) {
      return res;
    }
  }
  olduse = c->used;
  c->used = max;

  {
    mp_digit u, *tmpa, *tmpb, *tmpc;
    int i;

    /* alias for digit pointers */
    tmpa = a->dp;
    tmpb = b->dp;
    tmpc = c->dp;

    /* set carry to zero */
    u = 0;
    for (i = 0; i < min; i++) {
      /* T[i] = A[i] - B[i] - U */
      *tmpc = *tmpa++ - *tmpb++ - u;

      /* U = carry bit of T[i]
       * Note this saves performing an AND operation since
       * if a carry does occur it will propagate all the way to the
       * MSB.  As a result a single shift is enough to get the carry
       */
      u = *tmpc >> ((mp_digit)(CHAR_BIT * sizeof (mp_digit) - 1));

      /* Clear carry from T[i] */
      *tmpc++ &= MP_MASK;
    }

    /* now copy higher words if any, e.g. if A has more digits than B  */
    for (; i < max; i++) {
      /* T[i] = A[i] - U */
      *tmpc = *tmpa++ - u;

      /* U = carry bit of T[i] */
      u = *tmpc >> ((mp_digit)(CHAR_BIT * sizeof (mp_digit) - 1));

      /* Clear carry from T[i] */
      *tmpc++ &= MP_MASK;
    }

    /* clear digits above used (since we may not have grown result above) */
    for (i = c->used; i < olduse; i++) {
      *tmpc++ = 0;
    }
  }

  mp_clamp (c);
  return MP_OKAY;
}

/* the jist of squaring...
 * you do like mult except the offset of the tmpx [one that
 * starts closer to zero] can't equal the offset of tmpy.
 * So basically you set up iy like before then you min it with
 * (ty-tx) so that it never happens.  You double all those
 * you add in the inner loop

After that loop you do the squares and add them in.
*/

int fast_s_mp_sqr (mp_int * a, mp_int * b)
{
  int       olduse, res, pa, ix, iz;
  mp_digit   W[MP_WARRAY], *tmpx;
  mp_word   W1;

  /* grow the destination as required */
  pa = a->used + a->used;
  if (b->alloc < pa) {
    if ((res = mp_grow (b, pa)) != MP_OKAY) {
      return res;
    }
  }

  /* number of output digits to produce */
  W1 = 0;
  for (ix = 0; ix < pa; ix++) {
      int      tx, ty, iy;
      mp_word  _W;
      mp_digit *tmpy;

      /* clear counter */
      _W = 0;

      /* get offsets into the two bignums */
      ty = MIN(a->used-1, ix);
      tx = ix - ty;

      /* setup temp aliases */
      tmpx = a->dp + tx;
      tmpy = a->dp + ty;

      /* this is the number of times the loop will iterrate, essentially
	 while (tx++ < a->used && ty-- >= 0) { ... }
       */
      iy = MIN(a->used-tx, ty+1);

      /* now for squaring tx can never equal ty
       * we halve the distance since they approach at a rate of 2x
       * and we have to round because odd cases need to be executed
       */
      iy = MIN(iy, (ty-tx+1)>>1);

      /* execute loop */
      for (iz = 0; iz < iy; iz++) {
	 _W += ((mp_word)*tmpx++)*((mp_word)*tmpy--);
      }

      /* double the inner product and add carry */
      _W = _W + _W + W1;

      /* even columns have the square term in them */
      if ((ix&1) == 0) {
	 _W += ((mp_word)a->dp[ix>>1])*((mp_word)a->dp[ix>>1]);
      }

      /* store it */
      W[ix] = (mp_digit)(_W & MP_MASK);

      /* make next carry */
      W1 = _W >> ((mp_word)DIGIT_BIT);
  }

  /* setup dest */
  olduse  = b->used;
  b->used = a->used+a->used;

  {
    mp_digit *tmpb;
    tmpb = b->dp;
    for (ix = 0; ix < pa; ix++) {
      *tmpb++ = W[ix] & MP_MASK;
    }

    /* clear unused digits [that existed in the old copy of c] */
    for (; ix < olduse; ix++) {
      *tmpb++ = 0;
    }
  }
  mp_clamp (b);
  return MP_OKAY;
}

/* computes a = 2**b
 *
 * Simple algorithm which zeroes the int, grows it then just sets one bit
 * as required.
 */
int
mp_2expt (mp_int * a, int b)
{
  int     res;

  /* zero a as per default */
  mp_zero (a);

  /* grow a to accomodate the single bit */
  if ((res = mp_grow (a, b / DIGIT_BIT + 1)) != MP_OKAY) {
    return res;
  }

  /* set the used count of where the bit will go */
  a->used = b / DIGIT_BIT + 1;

  /* put the single bit in its place */
  a->dp[b / DIGIT_BIT] = ((mp_digit)1) << (b % DIGIT_BIT);

  return MP_OKAY;
}


/* multiplies |a| * |b| and does not compute the lower digs digits
 * [meant to get the higher part of the product]
 */
int
s_mp_mul_high_digs (mp_int * a, mp_int * b, mp_int * c, int digs)
{
  mp_int  t;
  int     res, pa, pb, ix, iy;
  mp_digit u;
  mp_word r;
  mp_digit tmpx, *tmpt, *tmpy;

  /* can we use the fast multiplier? */
  if (((a->used + b->used + 1) < MP_WARRAY)
      && MIN (a->used, b->used) < (1 << ((CHAR_BIT * sizeof (mp_word)) - (2 * DIGIT_BIT)))) {
    return fast_s_mp_mul_high_digs (a, b, c, digs);
  }

  if ((res = mp_init_size (&t, a->used + b->used + 1)) != MP_OKAY) {
    return res;
  }
  t.used = a->used + b->used + 1;

  pa = a->used;
  pb = b->used;
  for (ix = 0; ix < pa; ix++) {
    /* clear the carry */
    u = 0;

    /* left hand side of A[ix] * B[iy] */
    tmpx = a->dp[ix];

    /* alias to the address of where the digits will be stored */
    tmpt = &(t.dp[digs]);

    /* alias for where to read the right hand side from */
    tmpy = b->dp + (digs - ix);

    for (iy = digs - ix; iy < pb; iy++) {
      /* calculate the double precision result */
      r       = ((mp_word)*tmpt) +
		((mp_word)tmpx) * ((mp_word)*tmpy++) +
		((mp_word) u);

      /* get the lower part */
      *tmpt++ = (mp_digit) (r & ((mp_word) MP_MASK));

      /* carry the carry */
      u       = (mp_digit) (r >> ((mp_word) DIGIT_BIT));
    }
    *tmpt = u;
  }
  mp_clamp (&t);
  mp_exch (&t, c);
  mp_clear (&t);
  return MP_OKAY;
}

/* low level squaring, b = a*a, HAC pp.596-597, Algorithm 14.16 */
int s_mp_sqr (mp_int * a, mp_int * b)
{
  mp_int  t;
  int     res, ix, iy, pa;
  mp_word r;
  mp_digit u, tmpx, *tmpt;

  pa = a->used;
  if ((res = mp_init_size (&t, 2*pa + 1)) != MP_OKAY) {
    return res;
  }

  /* default used is maximum possible size */
  t.used = 2*pa + 1;

  for (ix = 0; ix < pa; ix++) {
    /* first calculate the digit at 2*ix */
    /* calculate double precision result */
    r = ((mp_word) t.dp[2*ix]) +
	((mp_word)a->dp[ix])*((mp_word)a->dp[ix]);

    /* store lower part in result */
    t.dp[ix+ix] = (mp_digit) (r & ((mp_word) MP_MASK));

    /* get the carry */
    u           = (mp_digit)(r >> ((mp_word) DIGIT_BIT));

    /* left hand side of A[ix] * A[iy] */
    tmpx        = a->dp[ix];

    /* alias for where to store the results */
    tmpt        = t.dp + (2*ix + 1);

    for (iy = ix + 1; iy < pa; iy++) {
      /* first calculate the product */
      r       = ((mp_word)tmpx) * ((mp_word)a->dp[iy]);

      /* now calculate the double precision result, note we use
       * addition instead of *2 since it's easier to optimize
       */
      r       = ((mp_word) *tmpt) + r + r + ((mp_word) u);

      /* store lower part */
      *tmpt++ = (mp_digit) (r & ((mp_word) MP_MASK));

      /* get carry */
      u       = (mp_digit)(r >> ((mp_word) DIGIT_BIT));
    }
    /* propagate upwards */
    while (u != ((mp_digit) 0)) {
      r       = ((mp_word) *tmpt) + ((mp_word) u);
      *tmpt++ = (mp_digit) (r & ((mp_word) MP_MASK));
      u       = (mp_digit)(r >> ((mp_word) DIGIT_BIT));
    }
  }

  mp_clamp (&t);
  mp_exch (&t, b);
  mp_clear (&t);
  return MP_OKAY;
}

/* this is a modified version of fast_s_mul_digs that only produces
 * output digits *above* digs.  See the comments for fast_s_mul_digs
 * to see how it works.
 *
 * This is used in the Barrett reduction since for one of the multiplications
 * only the higher digits were needed.  This essentially halves the work.
 *
 * Based on Algorithm 14.12 on pp.595 of HAC.
 */
int fast_s_mp_mul_high_digs (mp_int * a, mp_int * b, mp_int * c, int digs)
{
  int     olduse, res, pa, ix, iz;
  mp_digit W[MP_WARRAY];
  mp_word  _W;

  /* grow the destination as required */
  pa = a->used + b->used;
  if (c->alloc < pa) {
    if ((res = mp_grow (c, pa)) != MP_OKAY) {
      return res;
    }
  }

  /* number of output digits to produce */
  pa = a->used + b->used;
  _W = 0;
  for (ix = digs; ix < pa; ix++) {
      int      tx, ty, iy;
      mp_digit *tmpx, *tmpy;

      /* get offsets into the two bignums */
      ty = MIN(b->used-1, ix);
      tx = ix - ty;

      /* setup temp aliases */
      tmpx = a->dp + tx;
      tmpy = b->dp + ty;

      /* this is the number of times the loop will iterrate, essentially its
	 while (tx++ < a->used && ty-- >= 0) { ... }
       */
      iy = MIN(a->used-tx, ty+1);

      /* execute loop */
      for (iz = 0; iz < iy; iz++) {
	 _W += ((mp_word)*tmpx++)*((mp_word)*tmpy--);
      }

      /* store term */
      W[ix] = ((mp_digit)_W) & MP_MASK;

      /* make next carry */
      _W = _W >> ((mp_word)DIGIT_BIT);
  }

  /* setup dest */
  olduse  = c->used;
  c->used = pa;

  {
    mp_digit *tmpc;

    tmpc = c->dp + digs;
    for (ix = digs; ix < pa; ix++) {
      /* now extract the previous digit [below the carry] */
      *tmpc++ = W[ix];
    }

    /* clear unused digits [that existed in the old copy of c] */
    for (; ix < olduse; ix++)
      *tmpc++ = 0;
  }
  mp_clamp (c);
  return MP_OKAY;
}


/* Control the memory/performance/compression tradeoff for zlib.
 * Set windowBits=8 for least memory usage, see your system's
 * zlib.h for full details.
 * Default settings (windowBits=15) will use 256kB for compression
 * windowBits=8 will use 129kB for compression.
 * Both modes will use ~35kB for decompression (using windowBits=15 for
 * interoperability) */
#ifndef DROPBEAR_ZLIB_WINDOW_BITS
#define DROPBEAR_ZLIB_WINDOW_BITS 15
#endif

/* We'll use /dev/urandom by default, since /dev/random is too much hassle.
 * If system developers aren't keeping seeds between boots nor getting
 * any entropy from somewhere it's their own fault. */
#define DROPBEAR_RANDOM_DEV "/dev/urandom"

/* Specify the number of clients we will allow to be connected but
 * not yet authenticated. After this limit, connections are rejected */
/* The first setting is per-IP, to avoid denial of service */
#ifndef MAX_UNAUTH_PER_IP
#define MAX_UNAUTH_PER_IP 5
#endif

/* And then a global limit to avoid chewing memory if connections
 * come from many IPs */
#ifndef MAX_UNAUTH_CLIENTS
#define MAX_UNAUTH_CLIENTS 30
#endif

/* Maximum number of failed authentication tries (server option) */
#ifndef MAX_AUTH_TRIES
#define MAX_AUTH_TRIES 10
#endif

/* Window size limits. These tend to be a trade-off between memory
   usage and network performance: */
/* Size of the network receive window. This amount of memory is allocated
   as a per-channel receive buffer. Increasing this value can make a
   significant difference to network performance. 24kB was empirically
   chosen for a 100mbit ethernet network. The value can be altered at
   runtime with the -W argument. */
#ifndef DEFAULT_RECV_WINDOW
#define DEFAULT_RECV_WINDOW 24576
#endif
/* Maximum size of a received SSH data packet - this _MUST_ be >= 32768
   in order to interoperate with other implementations */
#ifndef RECV_MAX_PAYLOAD_LEN
#define RECV_MAX_PAYLOAD_LEN 32768
#endif
/* Maximum size of a transmitted data packet - this can be any value,
   though increasing it may not make a significant difference. */
#ifndef TRANS_MAX_PAYLOAD_LEN
#define TRANS_MAX_PAYLOAD_LEN 16384
#endif

/* Ensure that data is transmitted every KEEPALIVE seconds. This can
be overridden at runtime with -K. 0 disables keepalives */
#define DEFAULT_KEEPALIVE 0

/* Ensure that data is received within IDLE_TIMEOUT seconds. This can
be overridden at runtime with -I. 0 disables idle timeouts */
#define DEFAULT_IDLE_TIMEOUT 0

/* Spec recommends after one hour or 1 gigabyte of data. One hour
 * is a bit too verbose, so we try 8 hours */
#ifndef KEX_REKEY_TIMEOUT
#define KEX_REKEY_TIMEOUT (3600 * 8)
#endif
#ifndef KEX_REKEY_DATA
#define KEX_REKEY_DATA (1<<30) /* 2^30 == 1GB, this value must be < INT_MAX */
#endif

/* Close connections to clients which haven't authorised after AUTH_TIMEOUT */
#ifndef AUTH_TIMEOUT
#define AUTH_TIMEOUT 300 /* we choose 5 minutes */
#endif

/* Minimum key sizes for DSS and RSA */
#ifndef MIN_DSS_KEYLEN
#define MIN_DSS_KEYLEN 512
#endif
#ifndef MIN_RSA_KEYLEN
#define MIN_RSA_KEYLEN 512
#endif

#define MAX_BANNER_SIZE 2000 /* this is 25*80 chars, any more is foolish */
#define MAX_BANNER_LINES 20 /* How many lines the client will display */

#ifndef _PATH_TTY
#define _PATH_TTY "/dev/tty"
#endif

/* success/failure defines */
#define DROPBEAR_SUCCESS 0
#define DROPBEAR_FAILURE -1

/* various algorithm identifiers */
#define DROPBEAR_KEX_DH_GROUP1 0
#define DROPBEAR_KEX_DH_GROUP14 1

#define DROPBEAR_SIGNKEY_ANY 0
#define DROPBEAR_SIGNKEY_RSA 1
#define DROPBEAR_SIGNKEY_DSS 2
#define DROPBEAR_SIGNKEY_NONE 3

#define DROPBEAR_COMP_NONE 0
#define DROPBEAR_COMP_ZLIB 1
#define DROPBEAR_COMP_ZLIB_DELAY 2

/* SHA1 is 20 bytes == 160 bits */
#define SHA1_HASH_SIZE 20
/* SHA512 is 64 bytes == 512 bits */
#define SHA512_HASH_SIZE 64
/* MD5 is 16 bytes = 128 bits */
#define MD5_HASH_SIZE 16

/* largest of MD5 and SHA1 */
#define MAX_MAC_LEN SHA1_HASH_SIZE


#define MAX_KEY_LEN 32 /* 256 bits for aes256 etc */
#define MAX_IV_LEN 20 /* must be same as max blocksize,
						 and >= SHA1_HASH_SIZE */
#define MAX_MAC_KEY 20

#define MAX_NAME_LEN 64 /* maximum length of a protocol name, isn't
						   explicitly specified for all protocols (just
						   for algos) but seems valid */

#define MAX_PROPOSED_ALGO 20

/* size/count limits */
/* From transport rfc */
#define MIN_PACKET_LEN 16

#define RECV_MAX_PACKET_LEN (MAX(35000, ((RECV_MAX_PAYLOAD_LEN)+100)))

/* for channel code */
#define TRANS_MAX_WINDOW 500000000 /* 500MB is sufficient, stopping overflow */
#define TRANS_MAX_WIN_INCR 500000000 /* overflow prevention */

#define RECV_WINDOWEXTEND (opts.recv_window / 3) /* We send a "window extend" every
								RECV_WINDOWEXTEND bytes */
#define MAX_RECV_WINDOW (1024*1024) /* 1 MB should be enough */

#define MAX_CHANNELS 100 /* simple mem restriction, includes each tcp/x11
							connection, so can't be _too_ small */

#define MAX_STRING_LEN 1400 /* ~= MAX_PROPOSED_ALGO * MAX_NAME_LEN, also
							   is the max length for a password etc */

/* For a 4096 bit DSS key, empirically determined */
#define MAX_PUBKEY_SIZE 1700
/* For a 4096 bit DSS key, empirically determined */
#define MAX_PRIVKEY_SIZE 1700

/* The maximum size of the bignum portion of the kexhash buffer */
/* Sect. 8 of the transport rfc 4253, K_S + e + f + K */
#define KEXHASHBUF_MAX_INTS (1700 + 130 + 130 + 130)

/* IPv4, IPv6 are all we'll get for now. Revisit in a few years time.... */
#define DROPBEAR_MAX_SOCKS 2

#define DROPBEAR_MAX_CLI_PASS 1024

/* The number of prompts we'll accept for keyb-interactive auth */
#define DROPBEAR_MAX_CLI_INTERACT_PROMPTS 80

#if defined(DROPBEAR_AES256) || defined(DROPBEAR_AES128)
#define DROPBEAR_AES
#endif

#if defined(DROPBEAR_TWOFISH256) || defined(DROPBEAR_TWOFISH128)
#define DROPBEAR_TWOFISH
#endif

#if defined(ENABLE_CLI_REMOTETCPFWD) || defined(ENABLE_CLI_LOCALTCPFWD)
#define ENABLE_CLI_ANYTCPFWD
#endif

#if defined(ENABLE_CLI_LOCALTCPFWD)
#define DROPBEAR_TCP_ACCEPT
#endif

#if defined(ENABLE_CLI_REMOTETCPFWD) || defined(ENABLE_CLI_LOCALTCPFWD)
#define USING_LISTENERS
#endif

#if defined(ENABLE_CLI_AGENTFWD)
#define ENABLE_CONNECT_UNIX
#endif

/* Changing this is inadvisable, it appears to have problems
 * with flushing compressed data */
#define DROPBEAR_ZLIB_MEM_LEVEL 8

#ifndef _PATH_DEVNULL
#define _PATH_DEVNULL "/dev/null"
#endif


/*
 * First, socket and INET6 related definitions
 */
#ifndef IN6_IS_ADDR_LOOPBACK
# define IN6_IS_ADDR_LOOPBACK(a) \
	(((u_int32_t *)(a))[0] == 0 && ((u_int32_t *)(a))[1] == 0 && \
	 ((u_int32_t *)(a))[2] == 0 && ((u_int32_t *)(a))[3] == htonl(1))
#endif /* !IN6_IS_ADDR_LOOPBACK */

#ifndef AF_INET6
/* Define it to something that should never appear */
#define AF_INET6 AF_MAX
#endif

/*
 * Next, RFC2553 name / address resolution API
 */

#ifndef NI_NUMERICHOST
# define NI_NUMERICHOST    (1)
#endif
#ifndef NI_NAMEREQD
# define NI_NAMEREQD       (1<<1)
#endif
#ifndef NI_NUMERICSERV
# define NI_NUMERICSERV    (1<<2)
#endif

#ifndef AI_PASSIVE
# define AI_PASSIVE             (1)
#endif
#ifndef AI_CANONNAME
# define AI_CANONNAME           (1<<1)
#endif
#ifndef AI_NUMERICHOST
# define AI_NUMERICHOST         (1<<2)
#endif

#ifndef NI_MAXSERV
# define NI_MAXSERV 32
#endif /* !NI_MAXSERV */
#ifndef NI_MAXHOST
# define NI_MAXHOST 1025
#endif /* !NI_MAXHOST */

#ifndef EAI_NODATA
# define EAI_NODATA     (INT_MAX - 1)
#endif
#ifndef EAI_MEMORY
# define EAI_MEMORY     (INT_MAX - 2)
#endif
#ifndef EAI_NONAME
# define EAI_NONAME     (INT_MAX - 3)
#endif
#ifndef EAI_SYSTEM
# define EAI_SYSTEM     (INT_MAX - 4)
#endif
#ifndef EAI_FAMILY
# define EAI_FAMILY     (INT_MAX - 5)
#endif

#ifndef LOG_AUTHPRIV
#define LOG_AUTHPRIV LOG_AUTH
#endif

#ifdef ENABLE_CLI_AGENTFWD

/* An agent reply can be reasonably large, as it can
 * contain a list of all public keys held by the agent.
 * 10000 is arbitrary */
#define MAX_AGENT_REPLY  10000


#ifdef __hpux
#define seteuid(a)       setresuid(-1, (a), -1)
#define setegid(a)       setresgid(-1, (a), -1)
#endif

/* need to know if the session struct has been initialised, this way isn't the
 * cleanest, but works OK */
static int sessinitdone; /* GLOBAL, Is set to 0 somewhere */

struct dropbear_cipher {
	const struct ltc_cipher_descriptor *cipherdesc;
	unsigned long keysize;
	unsigned char blocksize;
};

struct dropbear_cipher_mode {
	int (*start)(int cipher, const unsigned char *IV,
			const unsigned char *key,
			int keylen, int num_rounds, void *cipher_state);
	int (*encrypt)(const unsigned char *pt, unsigned char *ct,
			unsigned long len, void *cipher_state);
	int (*decrypt)(const unsigned char *ct, unsigned char *pt,
			unsigned long len, void *cipher_state);
};

struct dropbear_hash {
	const struct ltc_hash_descriptor *hashdesc;
	unsigned long keysize;
	unsigned char hashsize;
};

/* crypto parameters that are stored individually for transmit and receive */
struct key_context_directional {
	const struct dropbear_cipher *algo_crypt; /* NULL for none */
	const struct dropbear_cipher_mode *crypt_mode;
	const struct dropbear_hash *algo_mac; /* NULL for none */
	int hash_index; /* lookup for libtomcrypt */
	char algo_comp; /* compression */
#ifndef DISABLE_ZLIB
	z_streamp zstream;
#endif
	/* actual keys */
	union {
		symmetric_CBC cbc;
#ifdef DROPBEAR_ENABLE_CTR_MODE
		symmetric_CTR ctr;
#endif
	} cipher_state;
	unsigned char mackey[MAX_MAC_KEY];
};

struct key_context {
	struct key_context_directional recv;
	struct key_context_directional trans;

	char algo_kex;
	char algo_hostkey;

	int allow_compress; /* whether compression has started (useful in
							zlib@openssh.com delayed compression case) */
};

struct buf {
	unsigned char * data;
	unsigned int len; /* the used size */
	unsigned int pos;
	unsigned int size; /* the memory size */

};

typedef struct buf buffer;

struct packetlist {
	struct packetlist *next;
	buffer * payload;
};

struct Link {
	void* item;
	struct Link* link;
};

struct Queue {
	struct Link* head;
	struct Link* tail;
	unsigned int count; /* safety value */
};

typedef struct PacketType {
	unsigned char type; /* SSH_MSG_FOO */
	void (*handler)();
} packettype;

struct KEXState {

	unsigned sentkexinit : 1; /*set when we've sent/recv kexinit packet */
	unsigned recvkexinit : 1;
	unsigned firstfollows : 1; /* true when first_kex_packet_follows is set */
	unsigned sentnewkeys : 1; /* set once we've send MSG_NEWKEYS (will be cleared once we have also received */
	unsigned recvnewkeys : 1; /* set once we've received MSG_NEWKEYS (cleared once we have also sent */

	unsigned donefirstkex : 1; /* Set to 1 after the first kex has completed,
								  ie the transport layer has been set up */

	time_t lastkextime; /* time of the last kex */
	unsigned int datatrans; /* data transmitted since last kex */
	unsigned int datarecv; /* data received since last kex */

};

typedef struct Algo_Type {
	char *name; /* identifying name */
	char val; /* a value for this cipher, or -1 for invalid */
	const void *data; /* algorithm specific data */
	char usable; /* whether we can use this algorithm */
	const void *mode; /* the mode, currently only used for ciphers,
			     points to a 'struct dropbear_cipher_mode' */
} algo_type;

/* This structure is shared between server and client - it contains
 * relatively little extraneous bits when used for the client rather than the
 * server */
struct AuthState {
	char *username; /* This is the username the client presents to check. It
					   is updated each run through, used for auth checking */
	unsigned char authtypes; /* Flags indicating which auth types are still
								valid */
	unsigned int failcount; /* Number of (failed) authentication attempts.*/
	unsigned authdone : 1; /* 0 if we haven't authed, 1 if we have. Applies for
							  client and server (though has differing [obvious]
							  meanings). */
	unsigned perm_warn : 1; /* Server only, set if bad permissions on
							   ~/.ssh/authorized_keys have already been
							   logged. */

	/* These are only used for the server */
	uid_t pw_uid;
	gid_t pw_gid;
	char *pw_dir;
	char *pw_shell;
	char *pw_name;
	char *pw_passwd;
};

struct Listener {
	int socks[DROPBEAR_MAX_SOCKS];
	unsigned int nsocks;

	int index; /* index in the array of listeners */

	void (*acceptor)(struct Listener*, int sock);
	void (*cleanup)(struct Listener*);

	int type; /* CHANNEL_ID_X11, CHANNEL_ID_AGENT,
				 CHANNEL_ID_TCPDIRECT (for clients),
				 CHANNEL_ID_TCPFORWARDED (for servers) */

	void *typedata;
};

struct ChanType;

struct sshsession {
	/* Is it a client or server? */
	unsigned char isserver;
	/* time the connection was established (cleared after auth once
	   we're not respecting AUTH_TIMEOUT any more) */
	time_t connect_time;

	int sock_in;
	int sock_out;

	char *remoteident;

	int maxfd; /* the maximum file descriptor to check with select() */


	/* Packet buffers/values etc */
	buffer *writepayload; /* Unencrypted payload to write - this is used
							 throughout the code, as handlers fill out this
							 buffer with the packet to send. */
	struct Queue writequeue; /* A queue of encrypted packets to send */
	buffer *readbuf; /* From the wire, decrypted in-place */
	buffer *payload; /* Post-decompression, the actual SSH packet */
	unsigned int transseq, recvseq; /* Sequence IDs */

	/* Packet-handling flags */
	const packettype * packettypes; /* Packet handler mappings for this
										session, see process-packet.c */

	unsigned dataallowed : 1; /* whether we can send data packets or we are in
								 the middle of a KEX or something */

	unsigned char requirenext; /* byte indicating what packet we require next,
								or 0x00 for any */

	unsigned char ignorenext; /* whether to ignore the next packet,
								 used for kex_follows stuff */

	unsigned char lastpacket; /* What the last received packet type was */

	int signal_pipe[2]; /* stores endpoints of a self-pipe used for
						   race-free signal handling */

	time_t last_trx_packet_time; /* time of the last packet transmission, for
							keepalive purposes */

	time_t last_packet_time; /* time of the last packet transmission or receive, for
								idle timeout purposes */


	/* KEX/encryption related */
	struct KEXState kexstate;
	struct key_context *keys;
	struct key_context *newkeys;
	char *session_id; /* this is the hash from the first kex */
	/* The below are used temorarily during kex, are freed after use */
	mp_int * dh_K; /* SSH_MSG_KEXDH_REPLY and sending SSH_MSH_NEWKEYS */
	unsigned char hash[SHA1_HASH_SIZE]; /* the hash*/
	buffer* kexhashbuf; /* session hash buffer calculated from various packets*/
	buffer* transkexinit; /* the kexinit packet we send should be kept so we
							 can add it to the hash when generating keys */

	/* Enables/disables compression */
	algo_type *compress_algos;

	/* a list of queued replies that should be sent after a KEX has
	   concluded (ie, while dataallowed was unset)*/
	struct packetlist *reply_queue_head, *reply_queue_tail;

	algo_type*(*buf_match_algo)(buffer*buf, algo_type localalgos[],
			int *goodguess); /* The function to use to choose which algorithm
								to use from the ones presented by the remote
								side. Is specific to the client/server mode,
								hence the function-pointer callback.*/

	void(*remoteclosed)(); /* A callback to handle closure of the
									  remote connection */


	struct AuthState authstate; /* Common amongst client and server, since most
								   struct elements are common */

	/* Channel related */
	struct Channel ** channels; /* these pointers may be null */
	unsigned int chansize; /* the number of Channel*s allocated for channels */
	unsigned int chancount; /* the number of Channel*s in use */
	const struct ChanType **chantypes; /* The valid channel types */


	/* TCP forwarding - where manage listeners */
	struct Listener ** listeners;
	unsigned int listensize;

	/* Whether to allow binding to privileged ports (<1024). This doesn't
	 * really belong here, but nowhere else fits nicely */
	int allowprivport;

};

struct exitinfo {
	int exitpid; /* -1 if not exited */
	int exitstatus;
	int exitsignal;
	int exitcore;
};

struct ChanSess {
	char * cmd; /* command to exec */
	pid_t pid; /* child process pid */

	/* pty details */
	int master; /* the master terminal fd*/
	int slave;
	unsigned char * tty;
	unsigned char * term;

	/* exit details */
	struct exitinfo exit;

	/* Used to set $SSH_CONNECTION in the child session.
	Is only set temporarily before forking */
	char *connection_string;
};

struct ChildPid {
	pid_t pid;
	struct ChanSess * chansess;
};


struct serversession {
	/* Server specific options */
	int childpipe; /* kept open until we successfully authenticate */
	/* userauth */

	struct ChildPid * childpids; /* array of mappings childpid<->channel */
	unsigned int childpidsize;

	/* Used to avoid a race in the exit returncode handling - see
	 * svr-chansession.c for details */
	struct exitinfo lastexit;

	/* The numeric address they connected from, used for logging */
	char * addrstring;

	/* The resolved remote address, used for lastlog etc */
	char *remotehost;

#ifdef __uClinux__
	pid_t server_pid;
#endif

};

typedef enum {
	KEX_NOTHING,
	KEXINIT_RCVD,
	KEXDH_INIT_SENT,
	KEXDONE
} cli_kex_state;

typedef enum {
	STATE_NOTHING,
	SERVICE_AUTH_REQ_SENT,
	SERVICE_AUTH_ACCEPT_RCVD,
	SERVICE_CONN_REQ_SENT,
	SERVICE_CONN_ACCEPT_RCVD,
	USERAUTH_REQ_SENT,
	USERAUTH_FAIL_RCVD,
	USERAUTH_SUCCESS_RCVD,
	SESSION_RUNNING
} cli_state;

/* Sources for signing keys */
typedef enum {
	SIGNKEY_SOURCE_RAW_FILE,
	SIGNKEY_SOURCE_AGENT,
	SIGNKEY_SOURCE_INVALID,
} signkey_source;

typedef struct {
	mp_int* p;
	mp_int* q;
	mp_int* g;
	mp_int* y;
	/* x is the private part */
	mp_int* x;
} dropbear_dss_key;

typedef struct {
	mp_int* n;
	mp_int* e;
	/* d, p, and q are private parts */
	mp_int* d;
	mp_int* p;
	mp_int* q;
} dropbear_rsa_key;

struct SIGN_key {
	int type; /* The type of key (dss or rsa) */
	signkey_source source;
	char *filename;
	/* the buffer? for encrypted keys, so we can later get
	 * the private key portion */

#ifdef DROPBEAR_DSS
	dropbear_dss_key * dsskey;
#endif
#ifdef DROPBEAR_RSA
	dropbear_rsa_key * rsakey;
#endif
};

typedef struct SIGN_key sign_key;


struct clientsession {
	mp_int *dh_e, *dh_x; /* Used during KEX */
	cli_kex_state kex_state; /* Used for progressing KEX */
	cli_state state; /* Used to progress auth/channelsession etc */
	unsigned donefirstkex : 1; /* Set when we set sentnewkeys, never reset */

	int tty_raw_mode; /* Whether we're in raw mode (and have to clean up) */
	struct termios saved_tio;
	int stdincopy;
	int stdinflags;
	int stdoutcopy;
	int stdoutflags;
	int stderrcopy;
	int stderrflags;

	int winchange; /* Set to 1 when a windowchange signal happens */

	int lastauthtype; /* either AUTH_TYPE_PUBKEY or AUTH_TYPE_PASSWORD,
						 for the last type of auth we tried */
#ifdef ENABLE_CLI_INTERACT_AUTH
	int auth_interact_failed; /* flag whether interactive auth can still
								 be used */
	int interact_request_received; /* flag whether we've received an
									  info request from the server for
									  interactive auth.*/
#endif
	sign_key *lastprivkey;

	int retval; /* What the command exit status was - we emulate it */
};

/* Global structs storing the state */
static struct sshsession ses;
static struct clientsession cli_ses;

/* The various numbers in the protocol */

/* message numbers */
#define SSH_MSG_DISCONNECT             1
#define SSH_MSG_IGNORE                 2
#define SSH_MSG_UNIMPLEMENTED          3
#define SSH_MSG_DEBUG                  4
#define SSH_MSG_SERVICE_REQUEST        5
#define SSH_MSG_SERVICE_ACCEPT         6
#define SSH_MSG_KEXINIT                20
#define SSH_MSG_NEWKEYS                21
#define SSH_MSG_KEXDH_INIT             30
#define SSH_MSG_KEXDH_REPLY            31

/* userauth message numbers */
#define SSH_MSG_USERAUTH_REQUEST            50
#define SSH_MSG_USERAUTH_FAILURE            51
#define SSH_MSG_USERAUTH_SUCCESS            52
#define SSH_MSG_USERAUTH_BANNER             53

/* packets 60-79 are method-specific, aren't one-one mapping */
#define SSH_MSG_USERAUTH_SPECIFIC_60   60

#define SSH_MSG_USERAUTH_PASSWD_CHANGEREQ   60

#define SSH_MSG_USERAUTH_PK_OK                          60

/* keyboard interactive auth */
#define SSH_MSG_USERAUTH_INFO_REQUEST           60
#define SSH_MSG_USERAUTH_INFO_RESPONSE          61


/* If adding numbers here, check MAX_UNAUTH_PACKET_TYPE in process-packet.c
 * is still valid */

/* connect message numbers */
#define SSH_MSG_GLOBAL_REQUEST                  80
#define SSH_MSG_REQUEST_SUCCESS                 81
#define SSH_MSG_REQUEST_FAILURE                 82
#define SSH_MSG_CHANNEL_OPEN                    90
#define SSH_MSG_CHANNEL_OPEN_CONFIRMATION       91
#define SSH_MSG_CHANNEL_OPEN_FAILURE            92
#define SSH_MSG_CHANNEL_WINDOW_ADJUST           93
#define SSH_MSG_CHANNEL_DATA                    94
#define SSH_MSG_CHANNEL_EXTENDED_DATA           95
#define SSH_MSG_CHANNEL_EOF                     96
#define SSH_MSG_CHANNEL_CLOSE                   97
#define SSH_MSG_CHANNEL_REQUEST                 98
#define SSH_MSG_CHANNEL_SUCCESS                 99
#define SSH_MSG_CHANNEL_FAILURE                 100

/* extended data types */
#define SSH_EXTENDED_DATA_STDERR        1

/* disconnect codes */
#define SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT      1
#define SSH_DISCONNECT_PROTOCOL_ERROR                   2
#define SSH_DISCONNECT_KEY_EXCHANGE_FAILED              3
#define SSH_DISCONNECT_RESERVED                         4
#define SSH_DISCONNECT_MAC_ERROR                        5
#define SSH_DISCONNECT_COMPRESSION_ERROR                6
#define SSH_DISCONNECT_SERVICE_NOT_AVAILABLE            7
#define SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED   8
#define SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE          9
#define SSH_DISCONNECT_CONNECTION_LOST                 10
#define SSH_DISCONNECT_BY_APPLICATION                  11
#define SSH_DISCONNECT_TOO_MANY_CONNECTIONS            12
#define SSH_DISCONNECT_AUTH_CANCELLED_BY_USER          13
#define SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE  14
#define SSH_DISCONNECT_ILLEGAL_USER_NAME               15

/* service types */
#define SSH_SERVICE_USERAUTH "ssh-userauth"
#define SSH_SERVICE_USERAUTH_LEN 12
#define SSH_SERVICE_CONNECTION "ssh-connection"
#define SSH_SERVICE_CONNECTION_LEN 14

/* public key types */
#define SSH_SIGNKEY_DSS "ssh-dss"
#define SSH_SIGNKEY_DSS_LEN 7
#define SSH_SIGNKEY_RSA "ssh-rsa"
#define SSH_SIGNKEY_RSA_LEN 7

/* Agent commands. These aren't part of the spec, and are defined
 * only on the openssh implementation. */
#define SSH_AGENT_FAILURE                       5
#define SSH_AGENT_SUCCESS                       6
#define SSH2_AGENTC_REQUEST_IDENTITIES          11
#define SSH2_AGENT_IDENTITIES_ANSWER            12
#define SSH2_AGENTC_SIGN_REQUEST                13
#define SSH2_AGENT_SIGN_RESPONSE                14

#define SSH2_AGENT_FAILURE                      30


#ifdef __GNUC__
#define ATTRIB_PRINTF(fmt,args) __attribute__((format(printf, fmt, args)))
#else
#define ATTRIB_PRINTF(fmt,args)
#endif

#ifdef __GNUC__
#define ATTRIB_NORETURN __attribute__((noreturn))
#else
#define ATTRIB_NORETURN
#endif

struct _m_list;

struct _m_list_elem {
    void *item;
	struct _m_list_elem *next;
	struct _m_list_elem *prev;
    struct _m_list *list;
};

typedef struct _m_list_elem m_list_elem;

struct _m_list {
    m_list_elem *first;
    m_list_elem *last;
};

typedef struct _m_list m_list;

/* client functions */
static void common_session_init(int sock_in, int sock_out);
static void session_loop(void(*loophandler)()) ATTRIB_NORETURN;

static void cli_start_send_channel_request(struct Channel *channel, char *type);

/* channel->type values */
#define CHANNEL_ID_NONE 0
#define CHANNEL_ID_SESSION 1
#define CHANNEL_ID_X11 2
#define CHANNEL_ID_AGENT 3
#define CHANNEL_ID_TCPDIRECT 4
#define CHANNEL_ID_TCPFORWARDED 5

#define SSH_OPEN_ADMINISTRATIVELY_PROHIBITED    1
#define SSH_OPEN_CONNECT_FAILED                 2
#define SSH_OPEN_UNKNOWN_CHANNEL_TYPE           3
#define SSH_OPEN_RESOURCE_SHORTAGE              4

/* Not a real type */
#define SSH_OPEN_IN_PROGRESS                                    99

#define CHAN_EXTEND_SIZE 3 /* how many extra slots to add when we need more */

typedef struct circbuf {
	unsigned int size;
	unsigned int readpos;
	unsigned int writepos;
	unsigned int used;
	unsigned char* data;
} circbuffer;

struct Channel {
	unsigned int index; /* the local channel index */
	unsigned int remotechan;
	unsigned int recvwindow, transwindow;
	unsigned int recvdonelen;
	unsigned int recvmaxpacket, transmaxpacket;
	void* typedata; /* a pointer to type specific data */
	int writefd; /* read from wire, written to insecure side */
	int readfd; /* read from insecure side, written to wire */
	int errfd; /* used like writefd or readfd, depending if it's client or server.
				  Doesn't exactly belong here, but is cleaner here */
	circbuffer *writebuf; /* data from the wire, for local consumption */
	circbuffer *extrabuf; /* extended-data for the program - used like writebuf
					     but for stderr */

	/* whether close/eof messages have been exchanged */
	int sent_close, recv_close;
	int recv_eof, sent_eof;

	/* Set after running the ChanType-specific close hander
	 * to ensure we don't run it twice (nor type->checkclose()). */
	int close_handler_done;

	int initconn; /* used for TCP forwarding, whether the channel has been
					 fully initialised */

	int await_open; /* flag indicating whether we've sent an open request
					   for this channel (and are awaiting a confirmation
					   or failure). */

	int flushing;

	const struct ChanType* type;

};

struct ChanType {
	int sepfds; /* Whether this channel has seperate pipes for in/out or not */
	char *name;
	int (*inithandler)(struct Channel*);
	int (*check_close)(struct Channel*);
	void (*reqhandler)(struct Channel*);
	void (*closehandler)(struct Channel*);
};

static void chaninitialise(const struct ChanType *chantypes[]);

static void recv_msg_channel_open(void);
static void recv_msg_channel_request(void);
static void send_msg_channel_failure(struct Channel *channel);
static void recv_msg_channel_data(void);
static void recv_msg_channel_window_adjust(void);
static void recv_msg_channel_close(void);
static void recv_msg_channel_eof();

static void common_recv_msg_channel_data(struct Channel *channel, int fd,
		circbuffer * buf);

static int send_msg_channel_open_init(int fd, const struct ChanType *type);
static void recv_msg_channel_open_confirmation(void);
static void recv_msg_channel_open_failure(void);

static void write_packet(void);
static void read_packet();
static void decrypt_packet();
static void encrypt_packet();
static void process_packet(void);

static void maybe_flush_reply_queue(void);

#define PACKET_PADDING_OFF 4
#define PACKET_PAYLOAD_OFF 5

#define INIT_READBUF 128

#define MAX_LISTENERS 20
#define LISTENER_EXTEND_SIZE 1

typedef struct runopts {
#if defined(ENABLE_CLI_LOCALTCPFWD)
	int listen_fwd_all;
#endif
	unsigned int recv_window;
	time_t keepalive_secs;
	time_t idle_timeout_secs;

#ifndef DISABLE_ZLIB
	/* TODO: add a commandline flag. Currently this is on by default if compression
	 * is compiled in, but disabled for a client's non-final multihop stages. (The
	 * intermediate stages are compressed streams, so are uncompressible. */
	int enable_compress;
#endif
} runopts;

static runopts opts; /* GLOBAL */

typedef struct cli_runopts {
	char *progname;
	char *remotehost;
	char *remoteport;

	char *own_user;
	char *username;

	char *cmd;
	int wantpty;
	int always_accept_key;
	int no_cmd;
	int backgrounded;
	int is_subsystem;
#ifdef ENABLE_CLI_PUBKEY_AUTH
	m_list *privkeys; /* Keys to use for public-key auth */
#endif
#ifdef ENABLE_CLI_REMOTETCPFWD
	m_list * remotefwds;
#endif
#ifdef ENABLE_CLI_LOCALTCPFWD
	m_list * localfwds;
#endif
#ifdef ENABLE_CLI_AGENTFWD
	int agent_fwd;
	int agent_keys_loaded; /* whether pubkeys has been populated with a
							  list of keys held by the agent */
	int agent_fd; /* The agent fd is only set during authentication. Forwarded
			 agent sessions have their own file descriptors */
#endif
} cli_runopts;

static cli_runopts cli_opts; /* GLOBAL */

static sign_key * new_sign_key(void);
static const char* signkey_name_from_type(int type, int *namelen);
static int signkey_type_from_name(const char* name, int namelen);
static int buf_get_pub_key(buffer *buf, sign_key *key, int *type);
static int buf_get_priv_key(buffer* buf, sign_key *key, int *type);
static void buf_put_pub_key(buffer* buf, sign_key *key, int type);
static void sign_key_free(sign_key *key);
static void buf_put_sign(buffer* buf, sign_key *key, int type,
		const unsigned char *data, unsigned int len);
static int buf_verify(buffer * buf, sign_key *key, const unsigned char *data,
		unsigned int len);
static char * sign_key_fingerprint(unsigned char* keyblob, unsigned int keybloblen);
static int cmp_base64_key(const unsigned char* keyblob, unsigned int keybloblen,
					const char* algoname, unsigned int algolen,
					buffer * line, char ** fingerprint);

static void list_append(m_list *list, void *item);
static void * list_remove(m_list_elem *elem);


#define MAX_USERNAME_LEN 25 /* arbitrary for the moment */

#define AUTH_TYPE_NONE      1
#define AUTH_TYPE_PUBKEY    1 << 1
#define AUTH_TYPE_PASSWORD  1 << 2
#define AUTH_TYPE_INTERACT  1 << 3

#define AUTH_METHOD_NONE "none"
#define AUTH_METHOD_NONE_LEN 4
#define AUTH_METHOD_PUBKEY "publickey"
#define AUTH_METHOD_PUBKEY_LEN 9
#define AUTH_METHOD_PASSWORD "password"
#define AUTH_METHOD_PASSWORD_LEN 8
#define AUTH_METHOD_INTERACT "keyboard-interactive"
#define AUTH_METHOD_INTERACT_LEN 20


static void dropbear_exit(const char* format, ...) ATTRIB_PRINTF(1,2) ATTRIB_NORETURN;

static void dropbear_close(const char* format, ...) ATTRIB_PRINTF(1,2) ;
static void dropbear_log(const char* format, ...) ATTRIB_PRINTF(1,2) ;

static void * m_malloc(size_t size) {

	void* ret;

	if (size == 0) {
		dropbear_exit("m_malloc failed");
	}
	ret = calloc(1, size);
	if (ret == NULL)
		dropbear_exit("m_malloc failed");
	return ret;

}

static void * m_realloc(void* ptr, size_t size) {

	void *ret;

	if (size == 0)
		dropbear_exit("m_realloc failed");
	ret = realloc(ptr, size);
	if (ret == NULL)
		dropbear_exit("m_realloc failed");
	return ret;
}

/* Clear the data, based on the method in David Wheeler's
 * "Secure Programming for Linux and Unix HOWTO" */
/* Beware of calling this from within dbutil.c - things might get
 * optimised away */
static void m_burn(void *data, unsigned int len) {
	volatile char *p = data;

	if (data == NULL)
		return;
	while (len--) {
		*p++ = 0x0;
	}
}

static void fail_assert(const char* expr, const char* file, int line) {
	dropbear_exit("Failed assertion (%s:%d): `%s'", file, line, expr);
}

/*
 * atomicio.c
 * Copied from OpenSSH 3.6.1p2.
 */
/*
 * ensure all of data on socket comes through. f==read || f==write
 */
static ssize_t atomicio(ssize_t (*f) (), int fd, void *_s, size_t n)
{
	char *s = _s;
	ssize_t res;
	size_t pos = 0;

	while (n > pos) {
		res = (f) (fd, s + pos, n - pos);
		switch (res) {
		case -1:
#ifdef EWOULDBLOCK
			if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
#else
			if (errno == EINTR || errno == EAGAIN)
#endif
				continue;
		case 0:
			return (res);
		default:
			pos += res;
		}
	}
	return (pos);
}

/* Buffer handling routines, designed to avoid overflows/using invalid data */

/* Prevent integer overflows when incrementing buffer position/length.
 * Calling functions should check arguments first, but this provides a
 * backstop */
#define BUF_MAX_INCR 1000000000
#define BUF_MAX_SIZE 1000000000

/* avoid excessively large numbers, > ~8192 bits */
#define BUF_MAX_MPINT (8240 / 8)

#define m_free(X) free(X); (X) = NULL;
/* Dropbear assertion */
#define dropbear_assert(X) do { if (!(X)) { fail_assert(#X, __FILE__, __LINE__); } } while (0)

/* Create (malloc) a new buffer of size */
static buffer* buf_new(unsigned int size) {

	buffer* buf;

	if (size > BUF_MAX_SIZE)
		dropbear_exit("buf->size too big");

	buf = (buffer*)m_malloc(sizeof(buffer));

	if (size > 0) {
		buf->data = (unsigned char*)m_malloc(size);
	} else {
		buf->data = NULL;
	}

	buf->size = size;
	buf->pos = 0;
	buf->len = 0;

	return buf;

}

/* free the buffer's data and the buffer itself */
static void buf_free(buffer* buf) {

	m_free(buf->data);
	m_free(buf);
}

/* overwrite the contents of the buffer to clear it */
static void buf_burn(buffer* buf) {

	m_burn(buf->data, buf->size);

}

/* resize a buffer, pos and len will be repositioned if required when
 * downsizing */
static void buf_resize(buffer *buf, unsigned int newsize) {

	if (newsize > BUF_MAX_SIZE)
		dropbear_exit("buf->size too big");

	buf->data = m_realloc(buf->data, newsize);
	buf->size = newsize;
	buf->len = MIN(newsize, buf->len);
	buf->pos = MIN(newsize, buf->pos);

}

/* Create a copy of buf, allocating required memory etc. */
/* The new buffer is sized the same as the length of the source buffer. */
static buffer* buf_newcopy(buffer* buf) {

	buffer* ret;

	ret = buf_new(buf->len);
	ret->len = buf->len;
	memcpy(ret->data, buf->data, buf->len);
	return ret;
}

/* Set the length of the buffer */
static void buf_setlen(buffer* buf, unsigned int len) {
	if (len > buf->size)
		dropbear_exit("Bad buf_setlen");
	buf->len = len;
}

/* Increment the length of the buffer */
static void buf_incrlen(buffer* buf, unsigned int incr) {
	if (incr > BUF_MAX_INCR || buf->len + incr > buf->size)
		dropbear_exit("Bad buf_incrlen");
	buf->len += incr;
}
/* Set the position of the buffer */
static void buf_setpos(buffer* buf, unsigned int pos) {
	if (pos > buf->len)
		dropbear_exit("Bad buf_setpos");
	buf->pos = pos;
}

/* increment the postion by incr, increasing the buffer length if required */
static void buf_incrwritepos(buffer* buf, unsigned int incr) {
	if (incr > BUF_MAX_INCR || buf->pos + incr > buf->size)
		dropbear_exit("Bad buf_incrwritepos");
	buf->pos += incr;
	if (buf->pos > buf->len) {
		buf->len = buf->pos;
	}
}

/* increment the position by incr, negative values are allowed, to
 * decrement the pos*/
static void buf_incrpos(buffer* buf,  int incr) {
	if (incr > BUF_MAX_INCR ||
			(unsigned int)((int)buf->pos + incr) > buf->len
			|| ((int)buf->pos + incr) < 0) {
		dropbear_exit("Bad buf_incrpos");
	}
	buf->pos += incr;
}

/* Get a byte from the buffer and increment the pos */
static unsigned char buf_getbyte(buffer* buf) {

	/* This check is really just ==, but the >= allows us to check for the
	 * bad case of pos > len, which should _never_ happen. */
	if (buf->pos >= buf->len)
		dropbear_exit("Bad buf_getbyte");
	return buf->data[buf->pos++];
}

/* Get a bool from the buffer and increment the pos */
static unsigned char buf_getbool(buffer* buf) {

	unsigned char b;
	b = buf_getbyte(buf);
	if (b != 0)
		b = 1;
	return b;
}

/* put a byte, incrementing the length if required */
static void buf_putbyte(buffer* buf, unsigned char val) {

	if (buf->pos >= buf->len) {
		buf_incrlen(buf, 1);
	}
	buf->data[buf->pos] = val;
	buf->pos++;
}

/* returns an in-place pointer to the buffer, checking that
 * the next len bytes from that position can be used */
static unsigned char* buf_getptr(buffer* buf, unsigned int len) {
	if (buf->pos + len > buf->len)
		dropbear_exit("Bad buf_getptr");
	return &buf->data[buf->pos];
}

/* like buf_getptr, but checks against total size, not used length.
 * This allows writing past the used length, but not past the size */
static unsigned char* buf_getwriteptr(buffer* buf, unsigned int len) {
	if (buf->pos + len > buf->size)
		dropbear_exit("Bad buf_getwriteptr");
	return &buf->data[buf->pos];
}

/* Get an uint32 from the buffer and increment the pos */
static unsigned int buf_getint(buffer* buf) {
	unsigned int ret;

	LOAD32H(ret, buf_getptr(buf, 4));
	buf_incrpos(buf, 4);
	return ret;
}

/* Return a null-terminated string, it is malloced, so must be free()ed
 * Note that the string isn't checked for null bytes, hence the retlen
 * may be longer than what is returned by strlen */
static char* buf_getstring(buffer* buf, unsigned int *retlen) {
	unsigned int len;
	char* ret;

	len = buf_getint(buf);
	if (len > MAX_STRING_LEN)
		dropbear_exit("String too long");

	if (retlen != NULL)
		*retlen = len;
	ret = m_malloc(len+1);
	memcpy(ret, buf_getptr(buf, len), len);
	buf_incrpos(buf, len);
	ret[len] = '\0';

	return ret;
}

/* Return a string as a newly allocated buffer */
static buffer * buf_getstringbuf(buffer *buf) {
	buffer *ret;
	char* str;
	unsigned int len;

	str = buf_getstring(buf, &len);
	ret = m_malloc(sizeof(*ret));
	ret->data = (unsigned char *)str;
	ret->len = len;
	ret->size = len;
	ret->pos = 0;
	return ret;
}

/* Just increment the buffer position the same as if we'd used buf_getstring,
 * but don't bother copying/malloc()ing for it */
static void buf_eatstring(buffer *buf) {

	buf_incrpos( buf, buf_getint(buf) );
}


/* put a 32bit uint into the buffer, incr bufferlen & pos if required */
static void buf_putint(buffer* buf, int unsigned val) {

	STORE32H(val, buf_getwriteptr(buf, 4));
	buf_incrwritepos(buf, 4);

}

/* put the set of len bytes into the buffer, incrementing the pos, increasing
 * len if required */
static void buf_putbytes(buffer *buf, const unsigned char *bytes, unsigned int len) {
	memcpy(buf_getwriteptr(buf, len), bytes, len);
	buf_incrwritepos(buf, len);
}

/* put a SSH style string into the buffer, increasing buffer len if required */
static void buf_putstring(buffer* buf, const char* str, unsigned int len) {

	buf_putint(buf, len);
	buf_putbytes(buf, (unsigned char*)str, len);

}

/* for our purposes we only need positive (or 0) numbers, so will
 * fail if we get negative numbers */
static void buf_putmpint(buffer* buf, mp_int * mp) {
	unsigned int len, pad = 0;

	dropbear_assert(mp != NULL);

	if (mp->sign == MP_NEG)
		dropbear_exit("negative bignum");

	/* zero check */
	if (mp->used == 1 && mp->dp[0] == 0) {
		len = 0;
	} else {
		/* SSH spec requires padding for mpints with the MSB set, this code
		 * implements it */
		len = mp_count_bits(mp);
		/* if the top bit of MSB is set, we need to pad */
		pad = (len%8 == 0) ? 1 : 0;
		len = len / 8 + 1; /* don't worry about rounding, we need it for
							  padding anyway when len%8 == 0 */

	}

	/* store the length */
	buf_putint(buf, len);

	/* store the actual value */
	if (len > 0) {
		if (pad) {
			buf_putbyte(buf, 0x00);
		}
		if (mp_to_unsigned_bin(mp, buf_getwriteptr(buf, len-pad)) != MP_OKAY)
			dropbear_exit("mpint error");
		buf_incrwritepos(buf, len-pad);
	}
}

/* Retrieve an mp_int from the buffer.
 * Will fail for -ve since they shouldn't be required here.
 * Returns DROPBEAR_SUCCESS or DROPBEAR_FAILURE */
static int buf_getmpint(buffer* buf, mp_int* mp) {

	unsigned int len;
	len = buf_getint(buf);

	if (len == 0) {
		mp_zero(mp);
		return DROPBEAR_SUCCESS;
	}

	if (len > BUF_MAX_MPINT) {
		return DROPBEAR_FAILURE;
	}

	/* check for negative */
	if (*buf_getptr(buf, 1) & (1 << (CHAR_BIT-1))) {
		return DROPBEAR_FAILURE;
	}

	if (mp_read_unsigned_bin(mp, buf_getptr(buf, len), len) != MP_OKAY) {
		return DROPBEAR_FAILURE;
	}

	buf_incrpos(buf, len);
	return DROPBEAR_SUCCESS;
}

static int dropbear_listen(const char* address, const char* port,
		int *socks, unsigned int sockcount, char **errstring, int *maxfd);
#ifdef ENABLE_CONNECT_UNIX
static int connect_unix(const char* addr);
#endif
static int connect_remote(const char* remotehost, const char* remoteport,
		int nonblocking, char ** errstring);
static int buf_readfile(buffer* buf, const char* filename);
static int buf_getline(buffer * line, FILE * authfile);

static void m_close(int fd);
static void * m_strdup(const char * str);
static void setnonblocking(int fd);
static void disallow_core();
static int m_str_to_uint(const char* str, unsigned int *val);

static void initqueue(struct Queue* queue);
static void* dequeue(struct Queue* queue);
static void *examine(struct Queue* queue);
static void enqueue(struct Queue* queue, void* item);

/* Used to force mp_ints to be initialised */
#define DEF_MP_INT(X) mp_int X = {0, 0, 0, NULL}


/* wrapper for mp_init, failing fatally on errors (memory allocation) */
static void m_mp_init(mp_int *mp) {
	if (mp_init(mp) != MP_OKAY)
		dropbear_exit("Mem alloc error");
}

/* simplified duplication of bn_mp_multi's mp_init_multi, but die fatally
 * on error */
static void m_mp_init_multi(mp_int *mp, ...)
{
    mp_int* cur_arg = mp;
    va_list args;

    va_start(args, mp);        /* init args to next argument from caller */
    while (cur_arg != NULL) {
	if (mp_init(cur_arg) != MP_OKAY)
		dropbear_exit("Mem alloc error");
	cur_arg = va_arg(args, mp_int*);
    }
    va_end(args);
}

static void bytes_to_mp(mp_int *mp, const unsigned char* bytes, unsigned int len) {
	if (mp_read_unsigned_bin(mp, (unsigned char*)bytes, len) != MP_OKAY)
		dropbear_exit("Mem alloc error");
}

/* hash the ssh representation of the mp_int mp */
static void sha1_process_mp(hash_state *hs, mp_int *mp) {

	int i;
	buffer * buf;

	buf = buf_new(512 + 20); /* max buffer is a 4096 bit key,
								plus header + some leeway*/
	buf_putmpint(buf, mp);
	i = buf->pos;
	buf_setpos(buf, 0);
	sha1_process(hs, buf_getptr(buf, i), i);
	buf_free(buf);
}


static circbuffer * cbuf_new(unsigned int size);
static void cbuf_free(circbuffer * cbuf);

static unsigned int cbuf_getused(circbuffer * cbuf); /* how much data stored */
static unsigned int cbuf_getavail(circbuffer * cbuf); /* how much we can write */
static unsigned int cbuf_readlen(circbuffer *cbuf); /* max linear read len */
static unsigned int cbuf_writelen(circbuffer *cbuf); /* max linear write len */

static unsigned char* cbuf_readptr(circbuffer *cbuf, unsigned int len);
static unsigned char* cbuf_writeptr(circbuffer *cbuf, unsigned int len);
static void cbuf_incrwrite(circbuffer *cbuf, unsigned int len);
static void cbuf_incrread(circbuffer *cbuf, unsigned int len);

#define MAX_CBUF_SIZE 100000000

static circbuffer * cbuf_new(unsigned int size) {

	circbuffer *cbuf = NULL;

	if (size > MAX_CBUF_SIZE)
		dropbear_exit("Bad cbuf size");

	cbuf = (circbuffer*)m_malloc(sizeof(circbuffer));
	cbuf->data = (unsigned char*)m_malloc(size);
	cbuf->used = 0;
	cbuf->readpos = 0;
	cbuf->writepos = 0;
	cbuf->size = size;

	return cbuf;
}

static void cbuf_free(circbuffer * cbuf) {

	m_burn(cbuf->data, cbuf->size);
	m_free(cbuf->data);
	m_free(cbuf);
}

static unsigned int cbuf_getused(circbuffer * cbuf) {

	return cbuf->used;

}

static unsigned int cbuf_getavail(circbuffer * cbuf) {

	return cbuf->size - cbuf->used;

}

static unsigned int cbuf_readlen(circbuffer *cbuf) {

	dropbear_assert(((2*cbuf->size)+cbuf->writepos-cbuf->readpos)%cbuf->size == cbuf->used%cbuf->size);
	dropbear_assert(((2*cbuf->size)+cbuf->readpos-cbuf->writepos)%cbuf->size == (cbuf->size-cbuf->used)%cbuf->size);

	if (cbuf->used == 0)
		return 0;

	if (cbuf->readpos < cbuf->writepos)
		return cbuf->writepos - cbuf->readpos;

	return cbuf->size - cbuf->readpos;
}

static unsigned int cbuf_writelen(circbuffer *cbuf) {

	dropbear_assert(cbuf->used <= cbuf->size);
	dropbear_assert(((2*cbuf->size)+cbuf->writepos-cbuf->readpos)%cbuf->size == cbuf->used%cbuf->size);
	dropbear_assert(((2*cbuf->size)+cbuf->readpos-cbuf->writepos)%cbuf->size == (cbuf->size-cbuf->used)%cbuf->size);

	if (cbuf->used == cbuf->size)
		return 0; /* full */

	if (cbuf->writepos < cbuf->readpos)
		return cbuf->readpos - cbuf->writepos;

	return cbuf->size - cbuf->writepos;
}

static unsigned char* cbuf_readptr(circbuffer *cbuf, unsigned int len) {
	if (len > cbuf_readlen(cbuf))
		dropbear_exit("Bad cbuf read");
	return &cbuf->data[cbuf->readpos];
}

static unsigned char* cbuf_writeptr(circbuffer *cbuf, unsigned int len) {
	if (len > cbuf_writelen(cbuf))
		dropbear_exit("Bad cbuf write");
	return &cbuf->data[cbuf->writepos];
}

static void cbuf_incrwrite(circbuffer *cbuf, unsigned int len) {
	if (len > cbuf_writelen(cbuf))
		dropbear_exit("Bad cbuf write");
	cbuf->used += len;
	dropbear_assert(cbuf->used <= cbuf->size);
	cbuf->writepos = (cbuf->writepos + len) % cbuf->size;
}


static void cbuf_incrread(circbuffer *cbuf, unsigned int len) {
	if (len > cbuf_readlen(cbuf))
		dropbear_exit("Bad cbuf read");
	dropbear_assert(cbuf->used >= len);
	cbuf->used -= len;
	cbuf->readpos = (cbuf->readpos + len) % cbuf->size;
}


/* The protocol implemented to talk to OpenSSH's SSH2 agent is documented in
   PROTOCOL.agent in recent OpenSSH source distributions (5.1p1 has it). */

static int new_agent_chan(struct Channel * channel);

static const struct ChanType cli_chan_agent = {
	0, /* sepfds */
	"auth-agent@openssh.com",
	new_agent_chan,
	NULL,
	NULL,
	NULL
};

static int connect_agent() {

	int fd = -1;
	char* agent_sock = NULL;

	agent_sock = getenv("SSH_AUTH_SOCK");
	if (agent_sock == NULL)
		return -1;

	fd = connect_unix(agent_sock);

	if (fd < 0) {
		dropbear_log("Failed to connect to agent");
	}

	return fd;
}

// handle a request for a connection to the locally running ssh-agent
// or forward.
static int new_agent_chan(struct Channel * channel) {

	int fd = -1;

	if (!cli_opts.agent_fwd)
		return SSH_OPEN_ADMINISTRATIVELY_PROHIBITED;

	fd = connect_agent();
	if (fd < 0) {
		return SSH_OPEN_CONNECT_FAILED;
	}

	setnonblocking(fd);

	ses.maxfd = MAX(ses.maxfd, fd);

	channel->readfd = fd;
	channel->writefd = fd;

	// success
	return 0;
}

/* Sends a request to the agent, returning a newly allocated buffer
 * with the response */
/* This function will block waiting for a response - it will
 * only be used by client authentication (not for forwarded requests)
 * won't cause problems for interactivity. */
/* Packet format (from draft-ylonen)
   4 bytes     Length, msb first.  Does not include length itself.
   1 byte      Packet type.  The value 255 is reserved for future extensions.
   data        Any data, depending on packet type.  Encoding as in the ssh packet
	       protocol.
*/
static buffer * agent_request(unsigned char type, buffer *data) {

	buffer * payload = NULL;
	buffer * inbuf = NULL;
	size_t readlen = 0;
	ssize_t ret;
	const int fd = cli_opts.agent_fd;
	unsigned int data_len = 0;
	if (data)
	{
		data_len = data->len;
	}

	payload = buf_new(4 + 1 + data_len);

	buf_putint(payload, 1 + data_len);
	buf_putbyte(payload, type);
	if (data) {
		buf_putbytes(payload, data->data, data->len);
	}
	buf_setpos(payload, 0);

	ret = atomicio(write, fd, buf_getptr(payload, payload->len), payload->len);
	if ((size_t)ret != payload->len)
		goto out;

	buf_free(payload);
	payload = NULL;
	/* Now we read the response */
	inbuf = buf_new(4);
	ret = atomicio(read, fd, buf_getwriteptr(inbuf, 4), 4);
	if (ret != 4)
		goto out;
	buf_setpos(inbuf, 0);
	buf_setlen(inbuf, ret);

	readlen = buf_getint(inbuf);
	if (readlen > MAX_AGENT_REPLY)
		goto out;

	buf_resize(inbuf, readlen);
	buf_setpos(inbuf, 0);
	ret = atomicio(read, fd, buf_getwriteptr(inbuf, readlen), readlen);
	if ((size_t)ret != readlen)
		goto out;
	buf_incrwritepos(inbuf, readlen);
	buf_setpos(inbuf, 0);

out:
	if (payload)
		buf_free(payload);

	return inbuf;
}

static void agent_get_key_list(m_list * ret_list)
{
	buffer * inbuf = NULL;
	unsigned int num = 0;
	unsigned char packet_type;
	unsigned int i;
	int ret;

	inbuf = agent_request(SSH2_AGENTC_REQUEST_IDENTITIES, NULL);
	if (!inbuf)
		goto out;

	/* The reply has a format of:
		byte                    SSH2_AGENT_IDENTITIES_ANSWER
		uint32                  num_keys
	   Followed by zero or more consecutive keys, encoded as:
	 string                 key_blob
	 string                 key_comment
	 */
	packet_type = buf_getbyte(inbuf);
	if (packet_type != SSH2_AGENT_IDENTITIES_ANSWER) {
		goto out;
	}

	num = buf_getint(inbuf);
	for (i = 0; i < num; i++) {
		sign_key * pubkey = NULL;
		int key_type = DROPBEAR_SIGNKEY_ANY;
		buffer * key_buf;

		/* each public key is encoded as a string */
		key_buf = buf_getstringbuf(inbuf);
		pubkey = new_sign_key();
		ret = buf_get_pub_key(key_buf, pubkey, &key_type);
		buf_free(key_buf);
		if (ret != DROPBEAR_SUCCESS) {
			/* This is slack, properly would cleanup vars etc */
			dropbear_exit("Bad pubkey received from agent");
		}
		pubkey->type = key_type;
		pubkey->source = SIGNKEY_SOURCE_AGENT;

		list_append(ret_list, pubkey);

		/* We'll ignore the comment for now. might want it later.*/
		buf_eatstring(inbuf);
	}

out:
	if (inbuf) {
		buf_free(inbuf);
		inbuf = NULL;
	}
}

static void cli_setup_agent(struct Channel *channel)
{
	if (!getenv("SSH_AUTH_SOCK"))
		return;

	cli_start_send_channel_request(channel, "auth-agent-req@openssh.com");
	/* Don't want replies */
	buf_putbyte(ses.writepayload, 0);
	encrypt_packet();
}

/* Returned keys are prepended to ret_list, which will
   be updated. */
static void cli_load_agent_keys(m_list *ret_list) {
	/* agent_fd will be closed after successful auth */
	cli_opts.agent_fd = connect_agent();
	if (cli_opts.agent_fd < 0) {
		return;
	}

	agent_get_key_list(ret_list);
}

static void agent_buf_sign(buffer *sigblob, sign_key *key,
		const unsigned char *data, unsigned int len) {
	buffer *request_data = NULL;
	buffer *response = NULL;
	unsigned int siglen;
	int packet_type;

	/* Request format
	byte                    SSH2_AGENTC_SIGN_REQUEST
	string                  key_blob
	string                  data
	uint32                  flags
	*/
	request_data = buf_new(MAX_PUBKEY_SIZE + len + 12);
	buf_put_pub_key(request_data, key, key->type);

	buf_putstring(request_data, (char *)data, len);
	buf_putint(request_data, 0);

	response = agent_request(SSH2_AGENTC_SIGN_REQUEST, request_data);

	if (!response) {
		goto fail;
	}

	packet_type = buf_getbyte(response);
	if (packet_type != SSH2_AGENT_SIGN_RESPONSE) {
		goto fail;
	}

	/* Response format
	byte                    SSH2_AGENT_SIGN_RESPONSE
	string                  signature_blob
	*/
	siglen = buf_getint(response);
	buf_putbytes(sigblob, buf_getptr(response, siglen), siglen);
	goto cleanup;

fail:
	/* XXX don't fail badly here. instead propagate a failure code back up to
	   the cli auth pubkey code, and just remove this key from the list of
	   ones to try. */
	dropbear_exit("Agent failed signing key");

cleanup:
	if (request_data) {
		buf_free(request_data);
	}
	if (response) {
		buf_free(response);
	}
}

#endif


/* lists mapping ssh types of algorithms to internal values */
/* Mappings for ciphers, parameters are
   {&cipher_desc, keysize, blocksize} */
/* NOTE: if keysize > 2*SHA1_HASH_SIZE, code such as hashkeys()
   needs revisiting */

#ifdef DROPBEAR_AES256
static const struct dropbear_cipher dropbear_aes256 =
	{&aes_desc, 32, 16};
#endif
#ifdef DROPBEAR_AES128
static const struct dropbear_cipher dropbear_aes128 =
	{&aes_desc, 16, 16};
#endif
#ifdef DROPBEAR_TWOFISH256
static const struct dropbear_cipher dropbear_twofish256 =
	{&twofish_desc, 32, 16};
#endif
#ifdef DROPBEAR_TWOFISH128
static const struct dropbear_cipher dropbear_twofish128 =
	{&twofish_desc, 16, 16};
#endif
#ifdef DROPBEAR_3DES
static const struct dropbear_cipher dropbear_3des =
	{&des3_desc, 24, 8};
#endif

/* used to indicate no encryption, as defined in rfc2410 */
static const struct dropbear_cipher dropbear_nocipher =
	{NULL, 16, 8};

static int void_start(int cipher, const unsigned char *IV,
			const unsigned char *key,
			int keylen, int num_rounds, void *cipher_state) {
	(void)&cipher;
	(void)&IV;
	(void)&key;
	(void)&keylen;
	(void)&num_rounds;
	(void)&cipher_state;
	return CRYPT_OK;
}

static int void_cipher(const unsigned char* in, unsigned char* out,
		unsigned long len, void *cipher_state) {
	(void)&cipher_state;
	if (in != out)
		memmove(out, in, len);
	return CRYPT_OK;
}

/* A few void* s are required to silence warnings
 * about the symmetric_CBC vs symmetric_CTR cipher_state pointer */
static const struct dropbear_cipher_mode dropbear_mode_cbc =
	{(void*)cbc_start, (void*)cbc_encrypt, (void*)cbc_decrypt};
static const struct dropbear_cipher_mode dropbear_mode_none =
	{void_start, void_cipher, void_cipher};
#ifdef DROPBEAR_ENABLE_CTR_MODE
/* a wrapper to make ctr_start and cbc_start look the same */
static int dropbear_big_endian_ctr_start(int cipher,
		const unsigned char *IV,
		const unsigned char *key, int keylen,
		int num_rounds, symmetric_CTR *ctr) {
	return ctr_start(cipher, IV, key, keylen, num_rounds, CTR_COUNTER_BIG_ENDIAN, ctr);
}
static const struct dropbear_cipher_mode dropbear_mode_ctr =
	{(void*)dropbear_big_endian_ctr_start, (void*)ctr_encrypt, (void*)ctr_decrypt};
#endif

/* Mapping of ssh hashes to libtomcrypt hashes, including keysize etc.
   {&hash_desc, keysize, hashsize} */

#ifdef DROPBEAR_SHA1_HMAC
static const struct dropbear_hash dropbear_sha1 =
	{&sha1_desc, 20, 20};
#endif
#ifdef DROPBEAR_SHA1_96_HMAC
static const struct dropbear_hash dropbear_sha1_96 =
	{&sha1_desc, 20, 12};
#endif
#ifdef DROPBEAR_MD5_HMAC
static const struct dropbear_hash dropbear_md5 =
	{&md5_desc, 16, 16};
#endif

static const struct dropbear_hash dropbear_nohash =
	{NULL, 16, 0}; /* used initially */


/* The following map ssh names to internal values.
 * The ordering here is important for the client - the first mode
 * that is also supported by the server will get used. */

static algo_type sshciphers[] = {
#ifdef DROPBEAR_ENABLE_CTR_MODE
#ifdef DROPBEAR_AES128
	{"aes128-ctr", 0, &dropbear_aes128, 1, &dropbear_mode_ctr},
#endif
#ifdef DROPBEAR_3DES
	{"3des-ctr", 0, &dropbear_3des, 1, &dropbear_mode_ctr},
#endif
#ifdef DROPBEAR_AES256
	{"aes256-ctr", 0, &dropbear_aes256, 1, &dropbear_mode_ctr},
#endif
#endif /* DROPBEAR_ENABLE_CTR_MODE */

/* CBC modes are always enabled */
#ifdef DROPBEAR_AES128
	{"aes128-cbc", 0, &dropbear_aes128, 1, &dropbear_mode_cbc},
#endif
#ifdef DROPBEAR_3DES
	{"3des-cbc", 0, &dropbear_3des, 1, &dropbear_mode_cbc},
#endif
#ifdef DROPBEAR_AES256
	{"aes256-cbc", 0, &dropbear_aes256, 1, &dropbear_mode_cbc},
#endif
#ifdef DROPBEAR_TWOFISH256
	{"twofish256-cbc", 0, &dropbear_twofish256, 1, &dropbear_mode_cbc},
	{"twofish-cbc", 0, &dropbear_twofish256, 1, &dropbear_mode_cbc},
#endif
#ifdef DROPBEAR_TWOFISH128
	{"twofish128-cbc", 0, &dropbear_twofish128, 1, &dropbear_mode_cbc},
#endif
	{NULL, 0, NULL, 0, NULL}
};

static algo_type sshhashes[] = {
#ifdef DROPBEAR_SHA1_96_HMAC
	{"hmac-sha1-96", 0, &dropbear_sha1_96, 1, NULL},
#endif
#ifdef DROPBEAR_SHA1_HMAC
	{"hmac-sha1", 0, &dropbear_sha1, 1, NULL},
#endif
#ifdef DROPBEAR_MD5_HMAC
	{"hmac-md5", 0, &dropbear_md5, 1, NULL},
#endif
	{NULL, 0, NULL, 0, NULL}
};

#ifndef DISABLE_ZLIB
static algo_type ssh_compress[] = {
	{"zlib", DROPBEAR_COMP_ZLIB, NULL, 1, NULL},
	{"zlib@openssh.com", DROPBEAR_COMP_ZLIB_DELAY, NULL, 1, NULL},
	{"none", DROPBEAR_COMP_NONE, NULL, 1, NULL},
	{NULL, 0, NULL, 0, NULL}
};
#endif

static algo_type ssh_nocompress[] = {
	{"none", DROPBEAR_COMP_NONE, NULL, 1, NULL},
	{NULL, 0, NULL, 0, NULL}
};

static algo_type sshhostkey[] = {
#ifdef DROPBEAR_RSA
	{"ssh-rsa", DROPBEAR_SIGNKEY_RSA, NULL, 1, NULL},
#endif
#ifdef DROPBEAR_DSS
	{"ssh-dss", DROPBEAR_SIGNKEY_DSS, NULL, 1, NULL},
#endif
	{NULL, 0, NULL, 0, NULL}
};

static algo_type sshkex[] = {
	{"diffie-hellman-group1-sha1", DROPBEAR_KEX_DH_GROUP1, NULL, 1, NULL},
	{"diffie-hellman-group14-sha1", DROPBEAR_KEX_DH_GROUP14, NULL, 1, NULL},
	{NULL, 0, NULL, 0, NULL}
};


static void buf_put_algolist(buffer * buf, algo_type localalgos[]);

static algo_type * cli_buf_match_algo(buffer* buf, algo_type localalgos[],
		int *goodguess);


/*
 * The chosen [encryption | MAC | compression] algorithm to each
 * direction MUST be the first algorithm  on the client's list
 * that is also on the server's list.
 */
static algo_type * cli_buf_match_algo(buffer* buf, algo_type localalgos[],
		int *goodguess) {

	char * algolist = NULL;
	char * remotealgos[MAX_PROPOSED_ALGO];
	unsigned int len;
	unsigned int count, i, j;
	algo_type * ret = NULL;

	*goodguess = 0;

	/* get the comma-separated list from the buffer ie "algo1,algo2,algo3" */
	algolist = buf_getstring(buf, &len);
	if (len > MAX_PROPOSED_ALGO*(MAX_NAME_LEN+1))
		goto out; /* just a sanity check, no other use */

	/* remotealgos will contain a list of the strings parsed out */
	/* We will have at least one string (even if it's just "") */
	remotealgos[0] = algolist;
	count = 1;
	/* Iterate through, replacing ','s with NULs, to split it into
	 * words. */
	for (i = 0; i < len; i++) {
		if (algolist[i] == '\0') {
			/* someone is trying something strange */
			goto out;
		}
		if (algolist[i] == ',') {
			algolist[i] = '\0';
			remotealgos[count] = &algolist[i+1];
			count++;
		}
		if (count >= MAX_PROPOSED_ALGO) {
			break;
		}
	}

	/* iterate and find the first match */

	for (j = 0; localalgos[j].name != NULL; j++) {
		if (localalgos[j].usable) {
		len = strlen(localalgos[j].name);
			for (i = 0; i < count; i++) {
				if (len == strlen(remotealgos[i])
						&& strncmp(localalgos[j].name,
							remotealgos[i], len) == 0) {
					if (i == 0 && j == 0) {
						/* was a good guess */
						*goodguess = 1;
					}
					ret = &localalgos[j];
					goto out;
				}
			}
		}
	}

out:
	m_free(algolist);
	return ret;
}


/* Send a "none" auth request to get available methods */
static void cli_auth_getmethods(void) {

	buf_putbyte(ses.writepayload, SSH_MSG_USERAUTH_REQUEST);
	buf_putstring(ses.writepayload, cli_opts.username,
			strlen(cli_opts.username));
	buf_putstring(ses.writepayload, SSH_SERVICE_CONNECTION,
			SSH_SERVICE_CONNECTION_LEN);
	buf_putstring(ses.writepayload, "none", 4); /* 'none' method */

	encrypt_packet();
}

/* Operates in-place turning dirty (untrusted potentially containing control
 * characters) text into clean text.
 * Note: this is safe only with ascii - other charsets could have problems. */
static void cleantext(char* dirtytext) {

	unsigned int i, j;
	unsigned char c;

	j = 0;
	for (i = 0; dirtytext[i] != '\0'; i++) {

		c = (unsigned char )dirtytext[i];
		/* We can ignore '\r's */
		if ( (c >= ' ' && c <= '~') || c == '\n' || c == '\t') {
			dirtytext[j] = c;
			j++;
		}
	}
	/* Null terminate */
	dirtytext[j] = '\0';
}


static void recv_msg_userauth_banner(void) {

	char* banner = NULL;
	unsigned int bannerlen;
	unsigned int i, linecount;

	if (ses.authstate.authdone)
		return;

	banner = buf_getstring(ses.payload, &bannerlen);
	buf_eatstring(ses.payload); /* The language string */

	if (bannerlen > MAX_BANNER_SIZE)
		goto out;

	cleantext(banner);

	/* Limit to 25 lines */
	linecount = 1;
	for (i = 0; i < bannerlen; i++) {
		if (banner[i] == '\n') {
			if (linecount >= MAX_BANNER_LINES) {
				banner[i] = '\0';
				break;
			}
			linecount++;
		}
	}

	fprintf(stderr, "%s\n", banner);

out:
	m_free(banner);
}

static void send_msg_userauth_pubkey(sign_key *key, int type, int realsign);

static void recv_msg_userauth_pk_ok(void) {
	m_list_elem *iter;
	buffer* keybuf = NULL;
	char* algotype = NULL;
	unsigned int algolen;
	int keytype;
	unsigned int remotelen;

	algotype = buf_getstring(ses.payload, &algolen);
	keytype = signkey_type_from_name(algotype, algolen);
	m_free(algotype);

	keybuf = buf_new(MAX_PUBKEY_SIZE);

	remotelen = buf_getint(ses.payload);

	/* Iterate through our keys, find which one it was that matched, and
	 * send a real request with that key */
	for (iter = cli_opts.privkeys->first; iter; iter = iter->next) {
		sign_key *key = (sign_key*)iter->item;
		if (key->type != keytype) {
			/* Types differed */
			continue;
		}

		/* Now we compare the contents of the key */
		keybuf->pos = keybuf->len = 0;
		buf_put_pub_key(keybuf, key, keytype);
		buf_setpos(keybuf, 0);
		buf_incrpos(keybuf, 4); /* first int is the length of the remainder (ie
								   remotelen) which has already been taken from
								   the remote buffer */


		if (keybuf->len-4 != remotelen) {
			/* Lengths differed */
			continue;
		}
		if (memcmp(buf_getptr(keybuf, remotelen),
					buf_getptr(ses.payload, remotelen), remotelen) != 0) {
			/* Data didn't match this key */
			continue;
		}

		/* Success */
		break;
	}
	buf_free(keybuf);

	if (iter != NULL) {
		/* XXX TODO: if it's an encrypted key, here we ask for their
		 * password */
		send_msg_userauth_pubkey((sign_key*)iter->item, keytype, 1);
	}
}

/* A helper for getpass() that exits if the user cancels. The returned
 * password is statically allocated by getpass() */
static char* getpass_or_cancel(char* prompt)
{
	char* password = NULL;

#ifdef __BIONIC__
# define PASSWD_STATIC_SIZE BUFSIZ
	static char passwd[BUFSIZ];
	char *ret;
	int i;
	struct termios old, new;

	tcgetattr(STDIN_FILENO, &old);
	tcflush(STDIN_FILENO, TCIFLUSH);

	ret = passwd;
	memset(ret, 0, PASSWD_STATIC_SIZE);

	fputs(prompt, stdout);
	fflush(stdout);

	tcgetattr(STDIN_FILENO, &new);
	new.c_iflag &= ~(IUCLC|IXON|IXOFF|IXANY);
	new.c_lflag &= ~(ECHO|ECHOE|ECHOK|ECHONL|TOSTOP);
	tcsetattr(STDIN_FILENO, TCSANOW, &new);

	if (read(STDIN_FILENO, passwd, PASSWD_STATIC_SIZE-1) <= 0) {
		ret = NULL;
	} else {
		for(i = 0; i < PASSWD_STATIC_SIZE && passwd[i]; i++) {
			if (passwd[i] == '\r' || passwd[i] == '\n') {
				passwd[i] = 0;
				break;
			}
		}
	}

	tcsetattr(STDIN_FILENO, TCSANOW, &old);
	fputs("\n", stdout);
	fflush(stdout);
	password = ret;
#else
	password = getpass(prompt);
#endif

	/* 0x03 is a ctrl-c character in the buffer. */
	if (password == NULL || strchr(password, '\3') != NULL) {
		dropbear_close("Interrupted.");
	}
	return password;
}


#ifdef ENABLE_CLI_INTERACT_AUTH

static char* get_response(char* prompt)
{
	FILE* tty = NULL;
	char* response = NULL;
	/* not a password, but a reasonable limit */
	char buf[DROPBEAR_MAX_CLI_PASS];
	char* ret = NULL;

	fprintf(stderr, "%s", prompt);

	tty = fopen(_PATH_TTY, "r");
	if (tty) {
		ret = fgets(buf, sizeof(buf), tty);
		fclose(tty);
	} else {
		ret = fgets(buf, sizeof(buf), stdin);
	}

	if (ret == NULL) {
		response = m_strdup("");
	} else {
		unsigned int buflen = strlen(buf);
		/* fgets includes newlines */
		if (buflen > 0 && buf[buflen-1] == '\n')
			buf[buflen-1] = '\0';
		response = m_strdup(buf);
	}

	m_burn(buf, sizeof(buf));

	return response;
}

static void cli_auth_interactive(void) {

	buf_putbyte(ses.writepayload, SSH_MSG_USERAUTH_REQUEST);

	/* username */
	buf_putstring(ses.writepayload, cli_opts.username,
			strlen(cli_opts.username));

	/* service name */
	buf_putstring(ses.writepayload, SSH_SERVICE_CONNECTION,
			SSH_SERVICE_CONNECTION_LEN);

	/* method */
	buf_putstring(ses.writepayload, AUTH_METHOD_INTERACT,
			AUTH_METHOD_INTERACT_LEN);

	/* empty language tag */
	buf_putstring(ses.writepayload, "", 0);

	/* empty submethods */
	buf_putstring(ses.writepayload, "", 0);

	encrypt_packet();
	cli_ses.interact_request_received = 0;
}
#endif  /* ENABLE_CLI_INTERACT_AUTH */

static void recv_msg_userauth_info_request(void) {

	char *name = NULL;
	char *instruction = NULL;
	unsigned int num_prompts = 0;
	unsigned int i;

	char *prompt = NULL;
	unsigned int echo = 0;
	char *response = NULL;

	/* Let the user know what password/host they are authing for */
	if (!cli_ses.interact_request_received) {
		fprintf(stderr, "Login for %s@%s\n", cli_opts.username,
				cli_opts.remotehost);
	}
	cli_ses.interact_request_received = 1;

	name = buf_getstring(ses.payload, NULL);
	instruction = buf_getstring(ses.payload, NULL);

	/* language tag */
	buf_eatstring(ses.payload);

	num_prompts = buf_getint(ses.payload);

	if (num_prompts >= DROPBEAR_MAX_CLI_INTERACT_PROMPTS)
		dropbear_exit("Too many prompts received for keyboard-interactive");

	/* we'll build the response as we go */
	buf_putbyte(ses.writepayload, SSH_MSG_USERAUTH_INFO_RESPONSE);
	buf_putint(ses.writepayload, num_prompts);

	if (strlen(name) > 0) {
		cleantext(name);
		fprintf(stderr, "%s", name);
	}
	m_free(name);

	if (strlen(instruction) > 0) {
		cleantext(instruction);
		fprintf(stderr, "%s", instruction);
	}
	m_free(instruction);

	for (i = 0; i < num_prompts; i++) {
		unsigned int response_len = 0;

		prompt = buf_getstring(ses.payload, NULL);
		cleantext(prompt);

		echo = buf_getbool(ses.payload);

		if (!echo) {
			char* p = getpass_or_cancel(prompt);
			response = m_strdup(p);
			m_burn(p, strlen(p));
		} else {
			response = get_response(prompt);
		}

		response_len = strlen(response);
		buf_putstring(ses.writepayload, response, response_len);
		m_burn(response, response_len);
		m_free(prompt);
		m_free(response);
	}

	encrypt_packet();
}

/* This handles the message-specific types which
 * all have a value of 60. These are
 * SSH_MSG_USERAUTH_PASSWD_CHANGEREQ,
 * SSH_MSG_USERAUTH_PK_OK, &
 * SSH_MSG_USERAUTH_INFO_REQUEST. */
static void recv_msg_userauth_specific_60(void) {

#ifdef ENABLE_CLI_PUBKEY_AUTH
	if (cli_ses.lastauthtype == AUTH_TYPE_PUBKEY) {
		recv_msg_userauth_pk_ok();
		return;
	}
#endif

#ifdef ENABLE_CLI_INTERACT_AUTH
	if (cli_ses.lastauthtype == AUTH_TYPE_INTERACT) {
		recv_msg_userauth_info_request();
		return;
	}
#endif

#ifdef ENABLE_CLI_PASSWORD_AUTH
	if (cli_ses.lastauthtype == AUTH_TYPE_PASSWORD) {
		/* Eventually there could be proper password-changing
		 * support. However currently few servers seem to
		 * implement it, and password auth is last-resort
		 * regardless - keyboard-interactive is more likely
		 * to be used anyway. */
		dropbear_close("Your password has expired.");
	}
#endif

	dropbear_exit("Unexpected userauth packet");
}

#ifdef ENABLE_CLI_PUBKEY_AUTH

/* Called when we receive a SSH_MSG_USERAUTH_FAILURE for a pubkey request.
 * We use it to remove the key we tried from the list */
static void cli_pubkeyfail(void) {
	m_list_elem *iter;
	for (iter = cli_opts.privkeys->first; iter; iter = iter->next) {
		sign_key *iter_key = (sign_key*)iter->item;

		if (iter_key == cli_ses.lastprivkey)
		{
			/* found the failing key */
			list_remove(iter);
			sign_key_free(iter_key);
			cli_ses.lastprivkey = NULL;
			return;
		}
	}
}


static void cli_buf_put_sign(buffer* buf, sign_key *key, int type,
			const unsigned char *data, unsigned int len)
{
	if (key->source == SIGNKEY_SOURCE_AGENT) {
		/* Format the agent signature ourselves, as buf_put_sign would. */
		buffer *sigblob;
		sigblob = buf_new(MAX_PUBKEY_SIZE);
		agent_buf_sign(sigblob, key, data, len);
		buf_setpos(sigblob, 0);
		buf_putstring(buf, (char *)buf_getptr(sigblob, sigblob->len),
				sigblob->len);

		buf_free(sigblob);
	} else {
		buf_put_sign(buf, key, type, data, len);
	}

}

/* TODO: make it take an agent reference to use as well */
static void send_msg_userauth_pubkey(sign_key *key, int type, int realsign) {

	const char *algoname = NULL;
	int algolen;
	buffer* sigbuf = NULL;

	buf_putbyte(ses.writepayload, SSH_MSG_USERAUTH_REQUEST);

	buf_putstring(ses.writepayload, cli_opts.username,
			strlen(cli_opts.username));

	buf_putstring(ses.writepayload, SSH_SERVICE_CONNECTION,
			SSH_SERVICE_CONNECTION_LEN);

	buf_putstring(ses.writepayload, AUTH_METHOD_PUBKEY,
			AUTH_METHOD_PUBKEY_LEN);

	buf_putbyte(ses.writepayload, realsign);

	algoname = signkey_name_from_type(type, &algolen);

	buf_putstring(ses.writepayload, algoname, algolen);
	buf_put_pub_key(ses.writepayload, key, type);

	if (realsign) {
		/* We put the signature as well - this contains string(session id), then
		 * the contents of the write payload to this point */
		sigbuf = buf_new(4 + SHA1_HASH_SIZE + ses.writepayload->len);
		buf_putstring(sigbuf, ses.session_id, SHA1_HASH_SIZE);
		buf_putbytes(sigbuf, ses.writepayload->data, ses.writepayload->len);
		cli_buf_put_sign(ses.writepayload, key, type, sigbuf->data, sigbuf->len);
		buf_free(sigbuf); /* Nothing confidential in the buffer */
	}

	encrypt_packet();
}

/* Returns 1 if a key was tried */
static int cli_auth_pubkey(void) {

	if (!cli_opts.agent_keys_loaded) {
		/* get the list of available keys from the agent */
		cli_load_agent_keys(cli_opts.privkeys);
		cli_opts.agent_keys_loaded = 1;
	}

	if (cli_opts.privkeys->first) {
		sign_key * key = (sign_key*)cli_opts.privkeys->first->item;
		/* Send a trial request */
		send_msg_userauth_pubkey(key, key->type, 0);
		cli_ses.lastprivkey = key;
		return 1;
	} else {
		/* no more keys left */
		return 0;
	}
}

static void cli_auth_pubkey_cleanup(void) {

#ifdef ENABLE_CLI_AGENTFWD
	m_close(cli_opts.agent_fd);
	cli_opts.agent_fd = -1;
#endif

	while (cli_opts.privkeys->first) {
		sign_key * key = list_remove(cli_opts.privkeys->first);
		sign_key_free(key);
	}
}
#endif /* Pubkey auth */

static void recv_msg_userauth_failure(void) {

	char * methods = NULL;
	char * tok = NULL;
	unsigned int methlen = 0;
	unsigned int partial = 0;
	unsigned int i = 0;

	if (cli_ses.state != USERAUTH_REQ_SENT) {
		/* Perhaps we should be more fatal? */
		dropbear_exit("Unexpected userauth failure");
	}

#ifdef ENABLE_CLI_PUBKEY_AUTH
	/* If it was a pubkey auth request, we should cross that key
	 * off the list. */
	if (cli_ses.lastauthtype == AUTH_TYPE_PUBKEY) {
		cli_pubkeyfail();
	}
#endif

#ifdef ENABLE_CLI_INTERACT_AUTH
	/* If we get a failure message for keyboard interactive without
	 * receiving any request info packet, then we don't bother trying
	 * keyboard interactive again */
	if (cli_ses.lastauthtype == AUTH_TYPE_INTERACT
			&& !cli_ses.interact_request_received) {
		cli_ses.auth_interact_failed = 1;
	}
#endif

	cli_ses.lastauthtype = AUTH_TYPE_NONE;

	methods = buf_getstring(ses.payload, &methlen);

	partial = buf_getbool(ses.payload);

	if (partial)
		dropbear_log("Authentication partially succeeded, more attempts required");
	 else
		ses.authstate.failcount++;

	ses.authstate.authdone=0;
	ses.authstate.authtypes=0;

	/* Split with nulls rather than commas */
	for (i = 0; i < methlen; i++) {
		if (methods[i] == ',')
			methods[i] = '\0';
	}

	tok = methods; /* tok stores the next method we'll compare */
	for (i = 0; i <= methlen; i++) {
		if (methods[i] == '\0') {
#ifdef ENABLE_CLI_PUBKEY_AUTH
			if (strncmp(AUTH_METHOD_PUBKEY, tok,
				AUTH_METHOD_PUBKEY_LEN) == 0) {
				ses.authstate.authtypes |= AUTH_TYPE_PUBKEY;
			}
#endif
#ifdef ENABLE_CLI_INTERACT_AUTH
			if (strncmp(AUTH_METHOD_INTERACT, tok,
				AUTH_METHOD_INTERACT_LEN) == 0) {
				ses.authstate.authtypes |= AUTH_TYPE_INTERACT;
			}
#endif
#ifdef ENABLE_CLI_PASSWORD_AUTH
			if (strncmp(AUTH_METHOD_PASSWORD, tok,
				AUTH_METHOD_PASSWORD_LEN) == 0) {
				ses.authstate.authtypes |= AUTH_TYPE_PASSWORD;
			}
#endif
			tok = &methods[i+1]; /* Must make sure we don't use it after the
									last loop, since it'll point to something
									undefined */
		}
	}

	m_free(methods);

	cli_ses.state = USERAUTH_FAIL_RCVD;
}

static void recv_msg_userauth_success(void) {
	/* Note: in delayed-zlib mode, setting authdone here
	 * will enable compression in the transport layer */
	ses.authstate.authdone = 1;
	cli_ses.state = USERAUTH_SUCCESS_RCVD;
	cli_ses.lastauthtype = AUTH_TYPE_NONE;

#ifdef ENABLE_CLI_PUBKEY_AUTH
	cli_auth_pubkey_cleanup();
#endif
}

#ifdef ENABLE_CLI_PASSWORD_AUTH

static void cli_auth_password() {

	char* password = NULL;
	char prompt[80];

	snprintf(prompt, sizeof(prompt), "%s@%s's password: ",
				cli_opts.username, cli_opts.remotehost);
	password = getpass_or_cancel(prompt);

	buf_putbyte(ses.writepayload, SSH_MSG_USERAUTH_REQUEST);

	buf_putstring(ses.writepayload, cli_opts.username,
			strlen(cli_opts.username));

	buf_putstring(ses.writepayload, SSH_SERVICE_CONNECTION,
			SSH_SERVICE_CONNECTION_LEN);

	buf_putstring(ses.writepayload, AUTH_METHOD_PASSWORD,
			AUTH_METHOD_PASSWORD_LEN);

	buf_putbyte(ses.writepayload, 0); /* FALSE - so says the spec */

	buf_putstring(ses.writepayload, password, strlen(password));

	encrypt_packet();
	m_burn(password, strlen(password));
}

static void cli_auth_interactive(void);


static void cli_auth_try(void) {

	int finished = 0;

	/* Order to try is pubkey, interactive, password.
	 * As soon as "finished" is set for one, we don't do any more. */
#ifdef ENABLE_CLI_PUBKEY_AUTH
	if (ses.authstate.authtypes & AUTH_TYPE_PUBKEY) {
		finished = cli_auth_pubkey();
		cli_ses.lastauthtype = AUTH_TYPE_PUBKEY;
	}
#endif

#ifdef ENABLE_CLI_INTERACT_AUTH
	if (!finished && ses.authstate.authtypes & AUTH_TYPE_INTERACT) {
		if (cli_ses.auth_interact_failed) {
			finished = 0;
		} else {
			cli_auth_interactive();
			cli_ses.lastauthtype = AUTH_TYPE_INTERACT;
			finished = 1;
		}
	}
#endif

#ifdef ENABLE_CLI_PASSWORD_AUTH
	if (!finished && ses.authstate.authtypes & AUTH_TYPE_PASSWORD) {
		cli_auth_password();
		finished = 1;
		cli_ses.lastauthtype = AUTH_TYPE_PASSWORD;
	}
#endif

	if (!finished)
		dropbear_exit("No auth methods could be used.");
}


#endif  /* ENABLE_CLI_PASSWORD_AUTH */


/* Returns the channel structure corresponding to the channel in the current
 * data packet (ses.payload must be positioned appropriately).
 * A valid channel is always returns, it will fail fatally with an unknown
 * channel */
static struct Channel* getchannel_msg(const char* kind) {

	unsigned int chan;

	chan = buf_getint(ses.payload);
	if (chan >= ses.chansize || ses.channels[chan] == NULL) {
		if (kind)
			dropbear_exit("%s for unknown channel %d", kind, chan);
		 else
			dropbear_exit("Unknown channel %d", chan);
	}
	return ses.channels[chan];
}

static struct Channel* getchannel(void) {
	return getchannel_msg(NULL);
}

static int cli_initchansess(struct Channel *channel);
static void cli_chansessreq(struct Channel *channel);
static void cli_closechansess(struct Channel *channel);

static const struct ChanType clichansess = {
	0, /* sepfds */
	"session", /* name */
	cli_initchansess, /* inithandler */
	NULL, /* checkclosehandler */
	cli_chansessreq, /* reqhandler */
	cli_closechansess, /* closehandler */
};

/* We receive channel data - only used by the client chansession code*/
static void recv_msg_channel_extended_data(void) {

	struct Channel *channel;
	unsigned int datatype;

	channel = getchannel();

	if (channel->type != &clichansess)
		return; /* we just ignore it */

	datatype = buf_getint(ses.payload);

	if (datatype != SSH_EXTENDED_DATA_STDERR)
		return;

	common_recv_msg_channel_data(channel, channel->errfd, channel->extrabuf);
}

#define TERMCODE_NONE 0
#define TERMCODE_CONTROL 1
#define TERMCODE_INPUT 2
#define TERMCODE_OUTPUT 3
#define TERMCODE_LOCAL 4
#define TERMCODE_CONTROLCHAR 5

#define MAX_TERMCODE 93

struct TermCode {
	unsigned int mapcode;
	unsigned char type;
};

static const struct TermCode termcodes[MAX_TERMCODE+1] = {
		{0, 0}, /* TTY_OP_END */
		{VINTR, TERMCODE_CONTROLCHAR}, /* control character codes */
		{VQUIT, TERMCODE_CONTROLCHAR},
		{VERASE, TERMCODE_CONTROLCHAR},
		{VKILL, TERMCODE_CONTROLCHAR},
		{VEOF, TERMCODE_CONTROLCHAR},
		{VEOL, TERMCODE_CONTROLCHAR},
		{VEOL2, TERMCODE_CONTROLCHAR},
		{VSTART, TERMCODE_CONTROLCHAR},
		{VSTOP, TERMCODE_CONTROLCHAR},
		{VSUSP, TERMCODE_CONTROLCHAR},
#ifdef VDSUSP
		{VDSUSP, TERMCODE_CONTROLCHAR},
#else
		{0, 0},
#endif
#ifdef VREPRINT
		{VREPRINT, TERMCODE_CONTROLCHAR},
#else
		{0, 0},
#endif
#ifdef AIX
		{CERASE, TERMCODE_CONTROLCHAR},
#else
		{VWERASE, TERMCODE_CONTROLCHAR},
#endif
		{VLNEXT, TERMCODE_CONTROLCHAR},
#ifdef VFLUSH
		{VFLUSH, TERMCODE_CONTROLCHAR},
#else
		{0, 0},
#endif
#ifdef VSWTCH
		{VSWTCH, TERMCODE_CONTROLCHAR},
#else
		{0, 0},
#endif
#ifdef VSTATUS
		{VSTATUS, TERMCODE_CONTROLCHAR},
#else
		{0, 0},
#endif
#ifdef AIX
		{CKILL, TERMCODE_CONTROLCHAR},
#elif defined(VDISCARD)
		{VDISCARD, TERMCODE_CONTROLCHAR},
#else
		{0, 0},
#endif
		{0, 0}, /* 19 */
		{0, 0},
		{0, 0},
		{0, 0},
		{0, 0},
		{0, 0},
		{0, 0},
		{0, 0},
		{0, 0},
		{0, 0},
		{0, 0}, /* 29 */
		{IGNPAR, TERMCODE_INPUT}, /* input flags */
		{PARMRK, TERMCODE_INPUT},
		{INPCK, TERMCODE_INPUT},
		{ISTRIP, TERMCODE_INPUT},
		{INLCR, TERMCODE_INPUT},
		{IGNCR, TERMCODE_INPUT},
		{ICRNL, TERMCODE_INPUT},
#ifdef IUCLC
		{IUCLC, TERMCODE_INPUT},
#else
		{0, 0},
#endif
		{IXON, TERMCODE_INPUT},
		{IXANY, TERMCODE_INPUT},
		{IXOFF, TERMCODE_INPUT},
#ifdef IMAXBEL
		{IMAXBEL, TERMCODE_INPUT},
#else
		{0, 0},
#endif
		{0, 0}, /* 42 */
		{0, 0},
		{0, 0},
		{0, 0},
		{0, 0},
		{0, 0},
		{0, 0},
		{0, 0}, /* 49 */
		{ISIG, TERMCODE_LOCAL}, /* local flags */
		{ICANON, TERMCODE_LOCAL},
#ifdef XCASE
		{XCASE, TERMCODE_LOCAL},
#else
		{0, 0},
#endif
		{ECHO, TERMCODE_LOCAL},
		{ECHOE, TERMCODE_LOCAL},
		{ECHOK, TERMCODE_LOCAL},
		{ECHONL, TERMCODE_LOCAL},
		{NOFLSH, TERMCODE_LOCAL},
		{TOSTOP, TERMCODE_LOCAL},
		{IEXTEN, TERMCODE_LOCAL},
		{ECHOCTL, TERMCODE_LOCAL},
		{ECHOKE, TERMCODE_LOCAL},
#ifdef PENDIN
		{PENDIN, TERMCODE_LOCAL},
#else
		{0, 0},
#endif
		{0, 0}, /* 63 */
		{0, 0},
		{0, 0},
		{0, 0},
		{0, 0},
		{0, 0},
		{0, 0}, /* 69 */
		{OPOST, TERMCODE_OUTPUT}, /* output flags */
#ifdef OLCUC
		{OLCUC, TERMCODE_OUTPUT},
#else
		{0, 0},
#endif
		{ONLCR, TERMCODE_OUTPUT},
#ifdef OCRNL
		{OCRNL, TERMCODE_OUTPUT},
#else
		{0, 0},
#endif
#ifdef ONOCR
		{ONOCR, TERMCODE_OUTPUT},
#else
		{0, 0},
#endif
#ifdef ONLRET
		{ONLRET, TERMCODE_OUTPUT},
#else
		{0, 0},
#endif
		{0, 0}, /* 76 */
		{0, 0},
		{0, 0},
		{0, 0},
		{0, 0},
		{0, 0},
		{0, 0},
		{0, 0},
		{0, 0},
		{0, 0},
		{0, 0},
		{0, 0},
		{0, 0},
		{0, 0}, /* 89 */
		{CS7, TERMCODE_CONTROL},
		{CS8, TERMCODE_CONTROL},
		{PARENB, TERMCODE_CONTROL},
		{PARODD, TERMCODE_CONTROL}
		/* 94 */
};


static void send_chansess_pty_req(struct Channel *channel);
static void send_chansess_shell_req(struct Channel *channel);

static void cli_tty_setup();

static void cli_chansessreq(struct Channel *channel) {

	char* type = NULL;
	int wantreply;

	type = buf_getstring(ses.payload, NULL);
	wantreply = buf_getbool(ses.payload);

	if (strcmp(type, "exit-status") == 0) {
		cli_ses.retval = buf_getint(ses.payload);
	} else if (strcmp(type, "exit-signal") == 0) {
		;
	} else {
		send_msg_channel_failure(channel);
		goto out;
	}

out:
	m_free(type);
}


static void cli_tty_cleanup(void) {

	if (cli_ses.tty_raw_mode == 0)
		return;

	if (tcsetattr(STDIN_FILENO, TCSADRAIN, &cli_ses.saved_tio) == -1) {
		dropbear_log("Failed restoring TTY");
	} else {
		cli_ses.tty_raw_mode = 0;
	}
}

/* If the main session goes, we close it up */
static void cli_closechansess(struct Channel *channel) {

	(void)&channel;
	/* This channel hasn't gone yet, so we have > 1 */
	if (ses.chancount > 1) {
		dropbear_log("Waiting for other channels to close...");
	}

	cli_tty_cleanup(); /* Restore tty modes etc */

}

static void
cli_start_send_channel_request(struct Channel *channel, char *type) {

	buf_putbyte(ses.writepayload, SSH_MSG_CHANNEL_REQUEST);
	buf_putint(ses.writepayload, channel->remotechan);

	buf_putstring(ses.writepayload, type, strlen(type));

}

/* Taken from OpenSSH's sshtty.c:
 * RCSID("OpenBSD: sshtty.c,v 1.5 2003/09/19 17:43:35 markus Exp "); */
static void cli_tty_setup() {

	struct termios tio;

	if (cli_ses.tty_raw_mode == 1)
		return;

	if (tcgetattr(STDIN_FILENO, &tio) == -1)
		dropbear_exit("Failed to set raw TTY mode");

	/* make a copy */
	cli_ses.saved_tio = tio;

	tio.c_iflag |= IGNPAR;
	tio.c_iflag &= ~(ISTRIP | INLCR | IGNCR | ICRNL | IXON | IXANY | IXOFF);
#ifdef IUCLC
	tio.c_iflag &= ~IUCLC;
#endif
	tio.c_lflag &= ~(ISIG | ICANON | ECHO | ECHOE | ECHOK | ECHONL);
#ifdef IEXTEN
	tio.c_lflag &= ~IEXTEN;
#endif
	tio.c_oflag &= ~OPOST;
	tio.c_cc[VMIN] = 1;
	tio.c_cc[VTIME] = 0;
	if (tcsetattr(STDIN_FILENO, TCSADRAIN, &tio) == -1)
		dropbear_exit("Failed to set raw TTY mode");
	cli_ses.tty_raw_mode = 1;
}


static void put_termcodes() {

	struct termios tio;
	unsigned int sshcode;
	const struct TermCode *termcode;
	unsigned int value;
	unsigned int mapcode;

	unsigned int bufpos1, bufpos2;

	if (tcgetattr(STDIN_FILENO, &tio) == -1) {
		dropbear_log("Failed reading termmodes");
		buf_putint(ses.writepayload, 1); /* Just the terminator */
		buf_putbyte(ses.writepayload, 0); /* TTY_OP_END */
		return;
	}

	bufpos1 = ses.writepayload->pos;
	buf_putint(ses.writepayload, 0); /* A placeholder for the final length */

	/* As with Dropbear server, we ignore baud rates for now */
	for (sshcode = 1; sshcode < MAX_TERMCODE; sshcode++) {

		termcode = &termcodes[sshcode];
		mapcode = termcode->mapcode;

		switch (termcode->type) {

			case TERMCODE_NONE:
				continue;

			case TERMCODE_CONTROLCHAR:
				value = tio.c_cc[mapcode];
				break;

			case TERMCODE_INPUT:
				value = tio.c_iflag & mapcode;
				break;

			case TERMCODE_OUTPUT:
				value = tio.c_oflag & mapcode;
				break;

			case TERMCODE_LOCAL:
				value = tio.c_lflag & mapcode;
				break;

			case TERMCODE_CONTROL:
				value = tio.c_cflag & mapcode;
				break;

			default:
				continue;

		}

		/* If we reach here, we have something to say */
		buf_putbyte(ses.writepayload, sshcode);
		buf_putint(ses.writepayload, value);
	}

	buf_putbyte(ses.writepayload, 0); /* THE END, aka TTY_OP_END */

	/* Put the string length at the start of the buffer */
	bufpos2 = ses.writepayload->pos;

	buf_setpos(ses.writepayload, bufpos1); /* Jump back */
	buf_putint(ses.writepayload, bufpos2 - bufpos1 - 4); /* len(termcodes) */
	buf_setpos(ses.writepayload, bufpos2); /* Back where we were */
}

static void put_winsize() {

	struct winsize ws;

	if (ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) < 0) {
		/* Some sane defaults */
		ws.ws_row = 25;
		ws.ws_col = 80;
		ws.ws_xpixel = 0;
		ws.ws_ypixel = 0;
	}

	buf_putint(ses.writepayload, ws.ws_col); /* Cols */
	buf_putint(ses.writepayload, ws.ws_row); /* Rows */
	buf_putint(ses.writepayload, ws.ws_xpixel); /* Width */
	buf_putint(ses.writepayload, ws.ws_ypixel); /* Height */

}

static void sigwinch_handler(int unused)
{
	(void)&unused;
	cli_ses.winchange = 1;
}

static void cli_chansess_winchange() {

	unsigned int i;
	struct Channel *channel = NULL;

	for (i = 0; i < ses.chansize; i++) {
		channel = ses.channels[i];
		if (channel != NULL && channel->type == &clichansess) {
			buf_putbyte(ses.writepayload, SSH_MSG_CHANNEL_REQUEST);
			buf_putint(ses.writepayload, channel->remotechan);
			buf_putstring(ses.writepayload, "window-change", 13);
			buf_putbyte(ses.writepayload, 0); /* FALSE says the spec */
			put_winsize();
			encrypt_packet();
		}
	}
	cli_ses.winchange = 0;
}

static void send_chansess_pty_req(struct Channel *channel) {

	char* term = NULL;

	cli_start_send_channel_request(channel, "pty-req");

	/* Don't want replies */
	buf_putbyte(ses.writepayload, 0);

	/* Get the terminal */
	term = getenv("TERM");
	if (term == NULL)
		term = "vt100"; /* Seems a safe default */
	buf_putstring(ses.writepayload, term, strlen(term));

	/* Window size */
	put_winsize();

	/* Terminal mode encoding */
	put_termcodes();

	encrypt_packet();

	/* Set up a window-change handler */
	if (signal(SIGWINCH, sigwinch_handler) == SIG_ERR)
		dropbear_exit("Signal error");
}

static void send_chansess_shell_req(struct Channel *channel) {

	char* reqtype = NULL;

	if (cli_opts.cmd) {
		if (cli_opts.is_subsystem) {
			reqtype = "subsystem";
		} else {
			reqtype = "exec";
		}
	} else {
		reqtype = "shell";
	}

	cli_start_send_channel_request(channel, reqtype);

	/* XXX TODO */
	buf_putbyte(ses.writepayload, 0); /* Don't want replies */
	if (cli_opts.cmd)
		buf_putstring(ses.writepayload, cli_opts.cmd, strlen(cli_opts.cmd));

	encrypt_packet();
}

/* Shared for normal client channel and netcat-alike */
static int cli_init_stdpipe_sess(struct Channel *channel) {
	channel->writefd = STDOUT_FILENO;
	setnonblocking(STDOUT_FILENO);

	channel->readfd = STDIN_FILENO;
	setnonblocking(STDIN_FILENO);

	channel->errfd = STDERR_FILENO;
	setnonblocking(STDERR_FILENO);

	channel->extrabuf = cbuf_new(opts.recv_window);
	return 0;
}

static int cli_initchansess(struct Channel *channel) {

	cli_init_stdpipe_sess(channel);

#ifdef ENABLE_CLI_AGENTFWD
	if (cli_opts.agent_fwd) {
		cli_setup_agent(channel);
	}
#endif

	if (cli_opts.wantpty) {
		send_chansess_pty_req(channel);
	}

	send_chansess_shell_req(channel);

	if (cli_opts.wantpty) {
		cli_tty_setup();
	}

	return 0; /* Success */
}

static void cli_send_chansess_request(void)
{
	if (send_msg_channel_open_init(STDIN_FILENO, &clichansess)
			== DROPBEAR_FAILURE) {
		dropbear_exit("Couldn't open initial channel");
	}

	/* No special channel request data */
	encrypt_packet();
}

static void send_msg_kexinit();
static void recv_msg_kexinit();
static void send_msg_newkeys();
static void recv_msg_newkeys();
static void kexfirstinitialise();
static void gen_kexdh_vals(mp_int *dh_pub, mp_int *dh_priv);
static void kexdh_comb_key(mp_int *dh_pub_us, mp_int *dh_priv, mp_int *dh_pub_them,
		sign_key *hostkey);

#ifndef DISABLE_ZLIB
static int is_compress_trans();
static int is_compress_recv();
#endif

static void send_msg_kexdh_init(); /* client */
static void recv_msg_kexdh_reply(); /* client */


#define MAX_KEXHASHBUF 2000

static void m_mp_init_multi(mp_int *mp, ...);
static void sha1_process_mp(hash_state *hs, mp_int *mp);

static void checkhostkey(unsigned char* keyblob, unsigned int keybloblen);
#define MAX_KNOWNHOSTS_LINE 4500

static void send_msg_kexdh_init() {

	cli_ses.dh_e = (mp_int*)m_malloc(sizeof(mp_int));
	cli_ses.dh_x = (mp_int*)m_malloc(sizeof(mp_int));
	m_mp_init_multi(cli_ses.dh_e, cli_ses.dh_x, NULL);

	gen_kexdh_vals(cli_ses.dh_e, cli_ses.dh_x);

	buf_putbyte(ses.writepayload, SSH_MSG_KEXDH_INIT);
	buf_putmpint(ses.writepayload, cli_ses.dh_e);
	encrypt_packet();
	ses.requirenext = SSH_MSG_KEXDH_REPLY;
}

/* Handle a diffie-hellman key exchange reply. */
static void recv_msg_kexdh_reply() {

	DEF_MP_INT(dh_f);
	sign_key *hostkey = NULL;
	unsigned int keybloblen;
	unsigned char* keyblob = NULL;
	int type;


	if (cli_ses.kex_state != KEXDH_INIT_SENT)
		dropbear_exit("Received out-of-order kexdhreply");
	m_mp_init(&dh_f);
	type = ses.newkeys->algo_hostkey;

	hostkey = new_sign_key();
	keybloblen = buf_getint(ses.payload);

	keyblob = buf_getptr(ses.payload, keybloblen);
	if (!ses.kexstate.donefirstkex) {
		/* Only makes sense the first time */
		checkhostkey(keyblob, keybloblen);
	}

	if (buf_get_pub_key(ses.payload, hostkey, &type) != DROPBEAR_SUCCESS)
		dropbear_exit("Bad KEX packet");

	if (buf_getmpint(ses.payload, &dh_f) != DROPBEAR_SUCCESS)
		dropbear_exit("Bad KEX packet");

	kexdh_comb_key(cli_ses.dh_e, cli_ses.dh_x, &dh_f, hostkey);
	mp_clear(&dh_f);
	mp_clear_multi(cli_ses.dh_e, cli_ses.dh_x, NULL);
	m_free(cli_ses.dh_e);
	m_free(cli_ses.dh_x);

	if (buf_verify(ses.payload, hostkey, ses.hash, SHA1_HASH_SIZE)
			!= DROPBEAR_SUCCESS) {
		dropbear_exit("Bad hostkey signature");
	}

	sign_key_free(hostkey);
	hostkey = NULL;

	send_msg_newkeys();
	ses.requirenext = SSH_MSG_NEWKEYS;
}

static void ask_to_confirm(unsigned char* keyblob, unsigned int keybloblen) {

	char* fp = NULL;
	FILE *tty = NULL;
	char response = 'z';

	fp = sign_key_fingerprint(keyblob, keybloblen);
	if (cli_opts.always_accept_key) {
		fprintf(stderr, "\nHost '%s' key accepted unconditionally.\n(fingerprint %s)\n",
				cli_opts.remotehost,
				fp);
		m_free(fp);
		return;
	}
	fprintf(stderr, "\nHost '%s' is not in the trusted hosts file.\n(fingerprint %s)\nDo you want to continue connecting? (y/n) ",
			cli_opts.remotehost,
			fp);
	m_free(fp);

	tty = fopen(_PATH_TTY, "r");
	if (tty) {
		response = getc(tty);
		fclose(tty);
	} else {
		response = getc(stdin);
	}

	if (response == 'y') {
		return;
	}

	dropbear_exit("Didn't validate host key");
}

static FILE* open_known_hosts_file(int * readonly)
{
	FILE * hostsfile = NULL;
	char * filename = NULL;
	char * homedir = NULL;

	homedir = getenv("HOME");

	if (!homedir) {
		struct passwd * pw = NULL;
		pw = getpwuid(getuid());
		if (pw) {
			homedir = pw->pw_dir;
		}
	}

	if (homedir) {
		unsigned int len;
		len = strlen(homedir);
		filename = m_malloc(len + 18); /* "/.ssh/known_hosts" and null-terminator*/

		snprintf(filename, len+18, "%s/.ssh", homedir);
		/* Check that ~/.ssh exists - easiest way is just to mkdir */
		if (mkdir(filename, S_IRWXU) != 0) {
			if (errno != EEXIST) {
				dropbear_log("Warning: failed creating %s/.ssh: %s",
						homedir, strerror(errno));
				goto out;
			}
		}

		snprintf(filename, len+18, "%s/.ssh/known_hosts", homedir);
		hostsfile = fopen(filename, "a+");

		if (hostsfile != NULL) {
			*readonly = 0;
			fseek(hostsfile, 0, SEEK_SET);
		} else {
			/* We mightn't have been able to open it if it was read-only */
			if (errno == EACCES || errno == EROFS) {
					*readonly = 1;
					hostsfile = fopen(filename, "r");
			}
		}
	}

	if (hostsfile == NULL) {
		dropbear_log("Failed to open %s/.ssh/known_hosts",
				homedir);
		goto out;
	}

out:
	m_free(filename);
	return hostsfile;
}

static void checkhostkey(unsigned char* keyblob, unsigned int keybloblen) {

	FILE *hostsfile = NULL;
	int readonly = 0;
	unsigned int hostlen;
	unsigned long len;
	const char *algoname = NULL;
	char * fingerprint = NULL;
	buffer * line = NULL;
	int algolen, ret;

	hostsfile = open_known_hosts_file(&readonly);
	if (!hostsfile) {
		ask_to_confirm(keyblob, keybloblen);
		/* ask_to_confirm will exit upon failure */
		return;
	}

	line = buf_new(MAX_KNOWNHOSTS_LINE);
	hostlen = strlen(cli_opts.remotehost);
	algoname = signkey_name_from_type(ses.newkeys->algo_hostkey, &algolen);

	do {
		if (buf_getline(line, hostsfile) == DROPBEAR_FAILURE)
			break;

		/* The line is too short to be sensible */
		/* "30" is 'enough to hold ssh-dss plus the spaces, ie so we don't
		 * buf_getfoo() past the end and die horribly - the base64 parsing
		 * code is what tiptoes up to the end nicely */
		if (line->len < (hostlen+30) )
			continue;

		/* Compare hostnames */
		if (strncmp(cli_opts.remotehost, (char *)buf_getptr(line, hostlen),
					hostlen) != 0)
			continue;

		buf_incrpos(line, hostlen);
		if (buf_getbyte(line) != ' ') {
			/* there wasn't a space after the hostname, something dodgy */
			continue;
		}

		if (strncmp((char *)buf_getptr(line, algolen), algoname, algolen) != 0)
			continue;

		buf_incrpos(line, algolen);
		if (buf_getbyte(line) != ' ')
			continue;

		/* Now we're at the interesting hostkey */
		ret = cmp_base64_key(keyblob, keybloblen, algoname, algolen,
						line, &fingerprint);

		if (ret == DROPBEAR_SUCCESS) {
			/* Good matching key */
			goto out;
		}

		/* The keys didn't match. eep. Note that we're "leaking"
		   the fingerprint strings here, but we're exiting anyway */
		dropbear_exit("\n\nHost key mismatch for %s !\n"
					"Fingerprint is %s\n"
					"Expected %s\n"
					"If you know that the host key is correct you can\nremove the bad entry from ~/.ssh/known_hosts",
					cli_opts.remotehost,
					sign_key_fingerprint(keyblob, keybloblen),
					fingerprint ? fingerprint : "UNKNOWN");
	} while (1); /* keep going 'til something happens */

	/* Key doesn't exist yet */
	ask_to_confirm(keyblob, keybloblen);

	/* If we get here, they said yes */

	if (readonly)
		goto out;

	if (!cli_opts.always_accept_key) {
		/* put the new entry in the file */
		fseek(hostsfile, 0, SEEK_END); /* In case it wasn't opened append */
		buf_setpos(line, 0);
		buf_setlen(line, 0);
		buf_putbytes(line, (unsigned char *)cli_opts.remotehost, hostlen);
		buf_putbyte(line, ' ');
		buf_putbytes(line, (unsigned char *)algoname, algolen);
		buf_putbyte(line, ' ');
		len = line->size - line->pos;
		/* The only failure with base64 is buffer_overflow, but buf_getwriteptr
		 * will die horribly in the case anyway */
		base64_encode(keyblob, keybloblen, buf_getwriteptr(line, len), &len);
		buf_incrwritepos(line, len);
		buf_putbyte(line, '\n');
		buf_setpos(line, 0);
		fwrite(buf_getptr(line, line->len), line->len, 1, hostsfile);
		/* We ignore errors, since there's not much we can do about them */
	}

out:
	if (hostsfile != NULL) {
		fclose(hostsfile);
	}
	if (line != NULL) {
		buf_free(line);
	}
	m_free(fingerprint);
}

struct TCPListener {

	/* For a direct-tcpip request, it's the addr/port we want the other
	 * end to connect to */
	char *sendaddr;
	unsigned int sendport;

	/* This is the address/port that we listen on. The address has special
	 * meanings as per the rfc, "" for all interfaces, "localhost" for
	 * localhost, or a normal interface name. */
	char *listenaddr;
	unsigned int listenport;

	const struct ChanType *chantype;
	enum {direct, forwarded} tcp_type;
};

/* A forwarding entry */
struct TCPFwdEntry {
	const char* connectaddr;
	unsigned int connectport;
	const char* listenaddr;
	unsigned int listenport;
	unsigned int have_reply; /* is set to 1 after a reply has been received
								when setting up the forwarding */
};

static void setup_localtcp();
static void setup_remotetcp();
static void cli_recv_msg_request_success();
static void cli_recv_msg_request_failure();

#ifdef ENABLE_CLI_REMOTETCPFWD
static int newtcpforwarded(struct Channel * channel);

static const struct ChanType cli_chan_tcpremote = {
	1, /* sepfds */
	"forwarded-tcpip",
	newtcpforwarded,
	NULL,
	NULL,
	NULL
};
#endif


/* Common */
static int listen_tcpfwd(struct TCPListener* tcpinfo);


static m_list * list_new();
/* returns the item for the element removed */


static void printhelp();
static void parse_hostname(const char* orighostarg);
#ifdef ENABLE_CLI_PUBKEY_AUTH
static void loadidentityfile(const char* filename);
#endif
#ifdef ENABLE_CLI_ANYTCPFWD
static void addforward(const char* str, m_list *fwdlist);
#endif

static void printhelp() {

	fprintf(stderr, "Dropbear client v%s\n"
					"Usage: %s [options] [user@]host[/port] [command]\n"
					"Options are:\n"
					"-p <remoteport>\n"
					"-l <username>\n"
					"-t    Allocate a pty\n"
					"-T    Don't allocate a pty\n"
					"-N    Don't run a remote command\n"
					"-f    Run in background after auth\n"
					"-y    Always accept remote host key if unknown\n"
					"-s    Request a subsystem (use for sftp)\n"
#ifdef ENABLE_CLI_PUBKEY_AUTH
					"-i <identityfile>   (multiple allowed)\n"
#endif
#ifdef ENABLE_CLI_AGENTFWD
					"-A    Enable agent auth forwarding\n"
#endif
#ifdef ENABLE_CLI_LOCALTCPFWD
					"-L <[listenaddress:]listenport:remotehost:remoteport> Local port forwarding\n"
					"-g    Allow remote hosts to connect to forwarded ports\n"
#endif
#ifdef ENABLE_CLI_REMOTETCPFWD
					"-R <[listenaddress:]listenport:remotehost:remoteport> Remote port forwarding\n"
#endif
					"-W <receive_window_buffer> (default %d, larger may be faster, max 1MB)\n"
					"-K <keepalive>  (0 is never, default %d)\n"
					"-I <idle_timeout>  (0 is never, default %d)\n"
					,DROPBEAR_VERSION, cli_opts.progname,
					DEFAULT_RECV_WINDOW, DEFAULT_KEEPALIVE, DEFAULT_IDLE_TIMEOUT);

}

static void fill_own_user(void) {
	uid_t uid;
	struct passwd *pw = NULL;

	uid = getuid();

	pw = getpwuid(uid);
	if (pw == NULL || pw->pw_name == NULL)
		dropbear_exit("Unknown own user");

	cli_opts.own_user = m_strdup(pw->pw_name);
}

static void cli_getopts(int argc, char ** argv) {
	unsigned int i, j;
	char ** next = 0;
	unsigned int cmdlen;
#ifdef ENABLE_CLI_PUBKEY_AUTH
	int nextiskey = 0; /* A flag if the next argument is a keyfile */
#endif
#ifdef ENABLE_CLI_LOCALTCPFWD
	int nextislocal = 0;
#endif
#ifdef ENABLE_CLI_REMOTETCPFWD
	int nextisremote = 0;
#endif
	char* dummy = NULL; /* Not used for anything real */

	char* recv_window_arg = NULL;
	char* keepalive_arg = NULL;
	char* idle_timeout_arg = NULL;
	char *host_arg = NULL;

	/* see printhelp() for options */
	cli_opts.progname = argv[0];
	cli_opts.remotehost = NULL;
	cli_opts.remoteport = NULL;
	cli_opts.username = NULL;
	cli_opts.cmd = NULL;
	cli_opts.no_cmd = 0;
	cli_opts.backgrounded = 0;
	cli_opts.wantpty = 9; /* 9 means "it hasn't been touched", gets set later */
	cli_opts.always_accept_key = 0;
	cli_opts.is_subsystem = 0;
#ifdef ENABLE_CLI_PUBKEY_AUTH
	cli_opts.privkeys = list_new();
#endif
#ifdef ENABLE_CLI_LOCALTCPFWD
	cli_opts.localfwds = list_new();
	opts.listen_fwd_all = 0;
#endif
#ifdef ENABLE_CLI_REMOTETCPFWD
	cli_opts.remotefwds = list_new();
#endif
#ifdef ENABLE_CLI_AGENTFWD
	cli_opts.agent_fwd = 0;
	cli_opts.agent_keys_loaded = 0;
#endif
#ifndef DISABLE_ZLIB
	opts.enable_compress = 1;
#endif
	/* not yet
	opts.ipv4 = 1;
	opts.ipv6 = 1;
	*/
	opts.recv_window = DEFAULT_RECV_WINDOW;

	fill_own_user();

	/* Iterate all the arguments */
	for (i = 1; i < (unsigned int)argc; i++) {
#ifdef ENABLE_CLI_PUBKEY_AUTH
		if (nextiskey) {
			/* Load a hostkey since the previous argument was "-i" */
			loadidentityfile(argv[i]);
			nextiskey = 0;
			continue;
		}
#endif
#ifdef ENABLE_CLI_REMOTETCPFWD
		if (nextisremote) {
			addforward(argv[i], cli_opts.remotefwds);
			nextisremote = 0;
			continue;
		}
#endif
#ifdef ENABLE_CLI_LOCALTCPFWD
		if (nextislocal) {
			addforward(argv[i], cli_opts.localfwds);
			nextislocal = 0;
			continue;
		}
#endif
		if (next) {
			/* The previous flag set a value to assign */
			*next = argv[i];
			if (*next == NULL)
				dropbear_exit("Invalid null argument");
			next = NULL;
			continue;
		}

		if (argv[i][0] == '-') {
			/* A flag *waves* */

			switch (argv[i][1]) {
				case 'y': /* always accept the remote hostkey */
					cli_opts.always_accept_key = 1;
					break;
				case 'p': /* remoteport */
					next = &cli_opts.remoteport;
					break;
#ifdef ENABLE_CLI_PUBKEY_AUTH
				case 'i': /* an identityfile */
					/* Keep scp happy when it changes "-i file" to "-ifile" */
					if (strlen(argv[i]) > 2) {
						loadidentityfile(&argv[i][2]);
					} else  {
						nextiskey = 1;
					}
					break;
#endif
				case 't': /* we want a pty */
					cli_opts.wantpty = 1;
					break;
				case 'T': /* don't want a pty */
					cli_opts.wantpty = 0;
					break;
				case 'N':
					cli_opts.no_cmd = 1;
					break;
				case 'f':
					cli_opts.backgrounded = 1;
					break;
				case 's':
					cli_opts.is_subsystem = 1;
					break;
#ifdef ENABLE_CLI_LOCALTCPFWD
				case 'L':
					nextislocal = 1;
					break;
				case 'g':
					opts.listen_fwd_all = 1;
					break;
#endif
#ifdef ENABLE_CLI_REMOTETCPFWD
				case 'R':
					nextisremote = 1;
					break;
#endif
				case 'l':
					next = &cli_opts.username;
					break;
				case 'h':
					printhelp();
					exit(EXIT_SUCCESS);
					break;
				case 'u':
					/* backwards compatibility with old urandom option */
					break;
				case 'W':
					next = &recv_window_arg;
					break;
				case 'K':
					next = &keepalive_arg;
					break;
				case 'I':
					next = &idle_timeout_arg;
					break;
#ifdef ENABLE_CLI_AGENTFWD
				case 'A':
					cli_opts.agent_fwd = 1;
					break;
#endif
				case 'F':
				case 'e':
				case 'c':
				case 'm':
				case 'D':
#ifndef ENABLE_CLI_REMOTETCPFWD
				case 'R':
#endif
#ifndef ENABLE_CLI_LOCALTCPFWD
				case 'L':
#endif
				case 'o':
				case 'b':
					next = &dummy;
				default:
					fprintf(stderr,
						"WARNING: Ignoring unknown argument '%s'\n", argv[i]);
					break;
			} /* Switch */

			/* Now we handle args where they might be "-luser" (no spaces)*/
			if (next && strlen(argv[i]) > 2) {
				*next = &argv[i][2];
				next = NULL;
			}

			continue; /* next argument */

		} else {
			/* Either the hostname or commands */

			if (host_arg == NULL) {
				host_arg = argv[i];
			} else {

				/* this is part of the commands to send - after this we
				 * don't parse any more options, and flags are sent as the
				 * command */
				cmdlen = 0;
				for (j = i; j < (unsigned int)argc; j++) {
					cmdlen += strlen(argv[j]) + 1; /* +1 for spaces */
				}
				/* Allocate the space */
				cli_opts.cmd = m_malloc(cmdlen);
				cli_opts.cmd[0] = '\0';

				/* Append all the bits */
				for (j = i; j < (unsigned int)argc; j++) {
					strcat(cli_opts.cmd, argv[j]);
					strcat(cli_opts.cmd, " ");
				}
				/* It'll be null-terminated here */

				/* We've eaten all the options and flags */
				break;
			}
		}
	}

	/* And now a few sanity checks and setup */

	if (host_arg == NULL) {
		printhelp();
		exit(EXIT_FAILURE);
	}

	if (cli_opts.remoteport == NULL) {
		cli_opts.remoteport = "22";
	}

	/* If not explicitly specified with -t or -T, we don't want a pty if
	 * there's a command, but we do otherwise */
	if (cli_opts.wantpty == 9) {
		if (cli_opts.cmd == NULL) {
			cli_opts.wantpty = 1;
		} else {
			cli_opts.wantpty = 0;
		}
	}

	if (cli_opts.backgrounded && cli_opts.cmd == NULL
			&& cli_opts.no_cmd == 0) {
		dropbear_exit("Command required for -f");
	}

	if (recv_window_arg) {
		opts.recv_window = atol(recv_window_arg);
		if (opts.recv_window == 0 || opts.recv_window > MAX_RECV_WINDOW) {
			dropbear_exit("Bad recv window '%s'", recv_window_arg);
		}
	}
	if (keepalive_arg) {
		unsigned int val;
		if (m_str_to_uint(keepalive_arg, &val) == DROPBEAR_FAILURE)
			dropbear_exit("Bad keepalive '%s'", keepalive_arg);
		opts.keepalive_secs = val;
	}

	if (idle_timeout_arg) {
		unsigned int val;
		if (m_str_to_uint(idle_timeout_arg, &val) == DROPBEAR_FAILURE)
			dropbear_exit("Bad idle_timeout '%s'", idle_timeout_arg);
		opts.idle_timeout_secs = val;
	}

	/* The hostname gets set up last, since
	 * in multi-hop mode it will require knowledge
	 * of other flags such as -i */
	parse_hostname(host_arg);
}

/* returns success or failure, and the keytype in *type. If we want
 * to restrict the type, type can contain a type to return */
static int readhostkey(const char * filename, sign_key * hostkey, int *type) {

	int ret = DROPBEAR_FAILURE;
	buffer *buf;

	buf = buf_new(MAX_PRIVKEY_SIZE);

	if (buf_readfile(buf, filename) == DROPBEAR_FAILURE)
		goto out;
	buf_setpos(buf, 0);
	if (buf_get_priv_key(buf, hostkey, type) == DROPBEAR_FAILURE) {
		goto out;
	}

	ret = DROPBEAR_SUCCESS;
out:

	buf_burn(buf);
	buf_free(buf);
	return ret;
}

#ifdef ENABLE_CLI_PUBKEY_AUTH
static void loadidentityfile(const char* filename) {
	sign_key *key;
	int keytype;

	key = new_sign_key();
	keytype = DROPBEAR_SIGNKEY_ANY;
	if ( readhostkey(filename, key, &keytype) != DROPBEAR_SUCCESS ) {
		fprintf(stderr, "Failed loading keyfile '%s'\n", filename);
		sign_key_free(key);
	} else {
		key->type = keytype;
		key->source = SIGNKEY_SOURCE_RAW_FILE;
		key->filename = m_strdup(filename);
		list_append(cli_opts.privkeys, key);
	}
}
#endif

/* Parses a [user@]hostname[/port] argument. */
static void parse_hostname(const char* orighostarg) {
	char *userhostarg = NULL;
	char *port = NULL;

	userhostarg = m_strdup(orighostarg);

	cli_opts.remotehost = strchr(userhostarg, '@');
	if (cli_opts.remotehost == NULL) {
		/* no username portion, the cli-auth.c code can figure the
		 * local user's name */
		cli_opts.remotehost = userhostarg;
	} else {
		cli_opts.remotehost[0] = '\0'; /* Split the user/host */
		cli_opts.remotehost++;
		cli_opts.username = userhostarg;
	}

	if (cli_opts.username == NULL)
		cli_opts.username = m_strdup(cli_opts.own_user);

	port = strchr(cli_opts.remotehost, '/');
	if (port) {
		*port = '\0';
		cli_opts.remoteport = port+1;
	}

	if (cli_opts.remotehost[0] == '\0')
		dropbear_exit("Bad hostname");
}


#ifdef ENABLE_CLI_ANYTCPFWD
/* Turn a "[listenaddr:]listenport:remoteaddr:remoteport" string into into a forwarding
 * set, and add it to the forwarding list */
static void addforward(const char* origstr, m_list *fwdlist) {

	char *part1 = NULL, *part2 = NULL, *part3 = NULL, *part4 = NULL;
	char * listenaddr = NULL;
	char * listenport = NULL;
	char * connectaddr = NULL;
	char * connectport = NULL;
	struct TCPFwdEntry* newfwd = NULL;
	char * str = NULL;

	/* We need to split the original argument up. This var
	   is never free()d. */
	str = m_strdup(origstr);

	part1 = str;

	part2 = strchr(str, ':');
	if (part2 == NULL)
		goto fail;
	*part2 = '\0';
	part2++;

	part3 = strchr(part2, ':');
	if (part3 == NULL)
		goto fail;
	*part3 = '\0';
	part3++;

	part4 = strchr(part3, ':');
	if (part4) {
		*part4 = '\0';
		part4++;
	}

	if (part4) {
		listenaddr = part1;
		listenport = part2;
		connectaddr = part3;
		connectport = part4;
	} else {
		listenaddr = NULL;
		listenport = part1;
		connectaddr = part2;
		connectport = part3;
	}

	newfwd = m_malloc(sizeof(struct TCPFwdEntry));

	/* Now we check the ports - note that the port ints are unsigned,
	 * the check later only checks for >= MAX_PORT */
	if (m_str_to_uint(listenport, &newfwd->listenport) == DROPBEAR_FAILURE)
		goto fail;

	if (m_str_to_uint(connectport, &newfwd->connectport) == DROPBEAR_FAILURE)
		goto fail;

	newfwd->listenaddr = listenaddr;
	newfwd->connectaddr = connectaddr;

	if (newfwd->listenport > 65535)
		goto badport;

	if (newfwd->connectport > 65535)
		goto badport;

	newfwd->have_reply = 0;
	list_append(fwdlist, newfwd);

	return;

fail:
	dropbear_exit("Bad TCP forward '%s'", origstr);

badport:
	dropbear_exit("Bad TCP port in '%s'", origstr);
}
#endif

static void send_msg_service_request();
static void recv_msg_service_accept();


static void send_msg_service_request(char* servicename) {

	buf_putbyte(ses.writepayload, SSH_MSG_SERVICE_REQUEST);
	buf_putstring(ses.writepayload, servicename, strlen(servicename));

	encrypt_packet();
}

/* This just sets up the state variables right for the main client session loop
 * to deal with */
static void recv_msg_service_accept() {

	char* servicename;
	unsigned int len;

	servicename = buf_getstring(ses.payload, &len);

	/* ssh-userauth */
	if (cli_ses.state == SERVICE_AUTH_REQ_SENT
			&& len == SSH_SERVICE_USERAUTH_LEN
			&& strncmp(SSH_SERVICE_USERAUTH, servicename, len) == 0) {

		cli_ses.state = SERVICE_AUTH_ACCEPT_RCVD;
		m_free(servicename);
		return;
	}

	/* ssh-connection */
	if (cli_ses.state == SERVICE_CONN_REQ_SENT
			&& len == SSH_SERVICE_CONNECTION_LEN
			&& strncmp(SSH_SERVICE_CONNECTION, servicename, len) == 0) {

		if (ses.authstate.authdone != 1)
			dropbear_exit("Request for connection before auth");

		cli_ses.state = SERVICE_CONN_ACCEPT_RCVD;
		m_free(servicename);
		return;
	}

	dropbear_exit("Unrecognised service accept");
}

static void cli_remoteclosed();
static void cli_sessionloop();
static void cli_session_init();
static void cli_finished();



static const struct ChanType *cli_chantypes[] = {
#ifdef ENABLE_CLI_REMOTETCPFWD
	&cli_chan_tcpremote,
#endif
#ifdef ENABLE_CLI_AGENTFWD
	&cli_chan_agent,
#endif
	NULL /* Null termination */
};

static void send_msg_ignore(void) {
	buf_putbyte(ses.writepayload, SSH_MSG_IGNORE);
	buf_putstring(ses.writepayload, "", 0);
	encrypt_packet();
}

/* Check all timeouts which are required. Currently these are the time for
 * user authentication, and the automatic rekeying. */
static void checktimeouts(void) {

	time_t now;

	now = time(NULL);

	if (ses.connect_time != 0 && now - ses.connect_time >= AUTH_TIMEOUT) {
			dropbear_close("Timeout before auth");
	}

	/* we can't rekey if we haven't done remote ident exchange yet */
	if (ses.remoteident == NULL)
		return;

	if (!ses.kexstate.sentkexinit
			&& (now - ses.kexstate.lastkextime >= KEX_REKEY_TIMEOUT
			|| ses.kexstate.datarecv+ses.kexstate.datatrans >= KEX_REKEY_DATA)) {
		send_msg_kexinit();
	}

	if (opts.keepalive_secs > 0
			&& now - ses.last_trx_packet_time >= opts.keepalive_secs) {
		send_msg_ignore();
	}

	if (opts.idle_timeout_secs > 0 && ses.last_packet_time > 0
			&& now - ses.last_packet_time >= opts.idle_timeout_secs) {
		dropbear_close("Idle timeout");
	}
}

/* returns the length including null-terminating zero on success,
 * or -1 on failure */
static int ident_readln(int fd, char* buf, int count) {

	char in;
	int pos = 0;
	int num = 0;
	fd_set fds;
	struct timeval timeout;

	if (count < 1) {
		return -1;
	}

	FD_ZERO(&fds);

	/* select since it's a non-blocking fd */

	/* leave space to null-terminate */
	while (pos < count-1) {

		FD_SET(fd, &fds);

		timeout.tv_sec = 1;
		timeout.tv_usec = 0;
		if (select(fd+1, &fds, NULL, NULL, &timeout) < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}

		checktimeouts();

		/* Have to go one byte at a time, since we don't want to read past
		 * the end, and have to somehow shove bytes back into the normal
		 * packet reader */
		if (FD_ISSET(fd, &fds)) {
			num = read(fd, &in, 1);
			/* a "\n" is a newline, "\r" we want to read in and keep going
			 * so that it won't be read as part of the next line */
			if (num < 0) {
				/* error */
				if (errno == EINTR)
					continue; /* not a real error */
				return -1;
			}
			if (num == 0) {
				/* EOF */
				return -1;
			}
			if (in == '\n') {
				/* end of ident string */
				break;
			}
			/* we don't want to include '\r's */
			if (in != '\r') {
				buf[pos] = in;
				pos++;
			}
		}
	}

	buf[pos] = '\0';
	return pos+1;
}


static void session_identification(void) {

	/* max length of 255 chars */
	char linebuf[256];
	int len = 0;
	char done = 0;
	int i;

	/* write our version string, this blocks */
	if (atomicio(write, ses.sock_out, LOCAL_IDENT "\r\n",
				strlen(LOCAL_IDENT "\r\n")) == DROPBEAR_FAILURE) {
		ses.remoteclosed();
	}

	/* If they send more than 50 lines, something is wrong */
	for (i = 0; i < 50; i++) {
		len = ident_readln(ses.sock_in, linebuf, sizeof(linebuf));

		if (len < 0 && errno != EINTR) {
			/* It failed */
			break;
		}

		if (len >= 4 && memcmp(linebuf, "SSH-", 4) == 0) {
			/* start of line matches */
			done = 1;
			break;
		}
	}

	if (!done) {
		ses.remoteclosed();
	} else {
		/* linebuf is already null terminated */
		ses.remoteident = m_malloc(len);
		memcpy(ses.remoteident, linebuf, len);
	}

	/* Shall assume that 2.x will be backwards compatible. */
	if (strncmp(ses.remoteident, "SSH-2.", 6) != 0
			&& strncmp(ses.remoteident, "SSH-1.99-", 9) != 0) {
		dropbear_exit("Incompatible remote version '%s'", ses.remoteident);
	}
}


static int donerandinit;

/* this is used to generate unique output from the same hashpool */
static uint32_t counter;
/* the max value for the counter, so it won't integer overflow */
#define MAX_COUNTER 1<<30

static unsigned char hashpool[SHA1_HASH_SIZE];

#define INIT_SEED_SIZE 32 /* 256 bits */

/* The basic setup is we read some data from /dev/(u)random or prngd and hash it
 * into hashpool. To read data, we hash together current hashpool contents,
 * and a counter. We feed more data in by hashing the current pool and new
 * data into the pool.
 *
 * It is important to ensure that counter doesn't wrap around before we
 * feed in new entropy.
 *
 */

static void readrand(unsigned char* buf, unsigned int buflen) {

	static int already_blocked = 0;
	int readfd;
	unsigned int readpos;
	int readlen;

#ifdef DROPBEAR_RANDOM_DEV
	readfd = open(DROPBEAR_RANDOM_DEV, O_RDONLY);
	if (readfd < 0)
		dropbear_exit("Couldn't open random device");
#endif

	/* read the actual random data */
	readpos = 0;
	do {
		if (!already_blocked)
		{
			int ret;
			struct timeval timeout;
			fd_set read_fds;

			timeout.tv_sec = 2; /* two seconds should be enough */
			timeout.tv_usec = 0;

			FD_ZERO(&read_fds);
			FD_SET(readfd, &read_fds);
			ret = select(readfd + 1, &read_fds, NULL, NULL, &timeout);
			if (ret == 0)
			{
				dropbear_log("Warning: Reading the random source seems to have blocked.\nIf you experience problems, you probably need to find a better entropy source.");
				already_blocked = 1;
			}
		}
		readlen = read(readfd, &buf[readpos], buflen - readpos);
		if (readlen <= 0) {
			if (readlen < 0 && errno == EINTR) {
				continue;
			}
			dropbear_exit("Error reading random source");
		}
		readpos += readlen;
	} while (readpos < buflen);

	close (readfd);
}

/* initialise the prng from /dev/(u)random or prngd */
static void seedrandom(void) {

	unsigned char readbuf[INIT_SEED_SIZE];

	hash_state hs;

	/* initialise so that things won't warn about
	 * hashing an undefined buffer */
	if (!donerandinit) {
		m_burn(hashpool, sizeof(hashpool));
	}

	/* get the seed data */
	readrand(readbuf, sizeof(readbuf));

	/* hash in the new seed data */
	sha1_init(&hs);
	sha1_process(&hs, (void*)hashpool, sizeof(hashpool));
	sha1_process(&hs, (void*)readbuf, sizeof(readbuf));
	sha1_done(&hs, hashpool);

	counter = 0;
	donerandinit = 1;
}

static void cli_session(int sock_in, int sock_out) ATTRIB_NORETURN;
static void cli_session(int sock_in, int sock_out) {

	seedrandom();

	common_session_init(sock_in, sock_out);

	chaninitialise(cli_chantypes);

	/* Set up cli_ses vars */
	cli_session_init();

	/* Ready to go */
	sessinitdone = 1;

	/* Exchange identification */
	session_identification();

	send_msg_kexinit();

	session_loop(cli_sessionloop);

	/* Not reached */
}

/* Sorted in decreasing frequency will be more efficient - data and window
 * should be first */
static const packettype cli_packettypes[] = {
	/* TYPE, FUNCTION */
	{SSH_MSG_CHANNEL_DATA, recv_msg_channel_data},
	{SSH_MSG_CHANNEL_EXTENDED_DATA, recv_msg_channel_extended_data},
	{SSH_MSG_CHANNEL_WINDOW_ADJUST, recv_msg_channel_window_adjust},
	{SSH_MSG_USERAUTH_FAILURE, recv_msg_userauth_failure}, /* client */
	{SSH_MSG_USERAUTH_SUCCESS, recv_msg_userauth_success}, /* client */
	{SSH_MSG_KEXINIT, recv_msg_kexinit},
	{SSH_MSG_KEXDH_REPLY, recv_msg_kexdh_reply}, /* client */
	{SSH_MSG_NEWKEYS, recv_msg_newkeys},
	{SSH_MSG_SERVICE_ACCEPT, recv_msg_service_accept}, /* client */
	{SSH_MSG_CHANNEL_REQUEST, recv_msg_channel_request},
	{SSH_MSG_CHANNEL_OPEN, recv_msg_channel_open},
	{SSH_MSG_CHANNEL_EOF, recv_msg_channel_eof},
	{SSH_MSG_CHANNEL_CLOSE, recv_msg_channel_close},
	{SSH_MSG_CHANNEL_OPEN_CONFIRMATION, recv_msg_channel_open_confirmation},
	{SSH_MSG_CHANNEL_OPEN_FAILURE, recv_msg_channel_open_failure},
	{SSH_MSG_USERAUTH_BANNER, recv_msg_userauth_banner}, /* client */
	{SSH_MSG_USERAUTH_SPECIFIC_60, recv_msg_userauth_specific_60}, /* client */
#ifdef  ENABLE_CLI_REMOTETCPFWD
	{SSH_MSG_REQUEST_SUCCESS, cli_recv_msg_request_success}, /* client */
	{SSH_MSG_REQUEST_FAILURE, cli_recv_msg_request_failure}, /* client */
#endif
	{0, 0} /* End */
};


static void cli_session_init() {

	cli_ses.state = STATE_NOTHING;
	cli_ses.kex_state = KEX_NOTHING;

	cli_ses.tty_raw_mode = 0;
	cli_ses.winchange = 0;

	/* We store std{in,out,err}'s flags, so we can set them back on exit
	 * (otherwise busybox's ash isn't happy */
	cli_ses.stdincopy = dup(STDIN_FILENO);
	cli_ses.stdinflags = fcntl(STDIN_FILENO, F_GETFL, 0);
	cli_ses.stdoutcopy = dup(STDOUT_FILENO);
	cli_ses.stdoutflags = fcntl(STDOUT_FILENO, F_GETFL, 0);
	cli_ses.stderrcopy = dup(STDERR_FILENO);
	cli_ses.stderrflags = fcntl(STDERR_FILENO, F_GETFL, 0);

	cli_ses.retval = EXIT_SUCCESS; /* Assume it's clean if we don't get a
									  specific exit status */

	/* Auth */
	cli_ses.lastprivkey = NULL;
	cli_ses.lastauthtype = 0;

	/* For printing "remote host closed" for the user */
	ses.remoteclosed = cli_remoteclosed;
	ses.buf_match_algo = cli_buf_match_algo;

	/* packet handlers */
	ses.packettypes = cli_packettypes;

	ses.isserver = 0;
}

/* This function drives the progress of the session - it initiates KEX,
 * service, userauth and channel requests */
static void cli_sessionloop() {

	if (ses.lastpacket == SSH_MSG_KEXINIT && cli_ses.kex_state == KEX_NOTHING) {
		cli_ses.kex_state = KEXINIT_RCVD;
	}

	if (cli_ses.kex_state == KEXINIT_RCVD) {

		/* We initiate the KEXDH. If DH wasn't the correct type, the KEXINIT
		 * negotiation would have failed. */
		send_msg_kexdh_init();
		cli_ses.kex_state = KEXDH_INIT_SENT;
		return;
	}

	/* A KEX has finished, so we should go back to our KEX_NOTHING state */
	if (cli_ses.kex_state != KEX_NOTHING && ses.kexstate.recvkexinit == 0
			&& ses.kexstate.sentkexinit == 0) {
		cli_ses.kex_state = KEX_NOTHING;
	}

	/* We shouldn't do anything else if a KEX is in progress */
	if (cli_ses.kex_state != KEX_NOTHING)
		return;

	/* We should exit if we haven't donefirstkex: we shouldn't reach here
	 * in normal operation */
	if (ses.kexstate.donefirstkex == 0)
		return;

	switch (cli_ses.state) {

		case STATE_NOTHING:
			/* We've got the transport layer sorted, we now need to request
			 * userauth */
			send_msg_service_request(SSH_SERVICE_USERAUTH);
			cli_ses.state = SERVICE_AUTH_REQ_SENT;
			return;

		/* userauth code */
		case SERVICE_AUTH_ACCEPT_RCVD:
			cli_auth_getmethods();
			cli_ses.state = USERAUTH_REQ_SENT;
			return;

		case USERAUTH_FAIL_RCVD:
			cli_auth_try();
			cli_ses.state = USERAUTH_REQ_SENT;
			return;

		case USERAUTH_SUCCESS_RCVD:

			if (cli_opts.backgrounded) {
				int devnull;
				/* keeping stdin open steals input from the terminal and
				   is confusing, though stdout/stderr could be useful. */
				devnull = open(_PATH_DEVNULL, O_RDONLY);
				if (devnull < 0) {
					dropbear_exit("Opening /dev/null: %d %s",
							errno, strerror(errno));
				}
				dup2(devnull, STDIN_FILENO);
				if (daemon(0, 1) < 0) {
					dropbear_exit("Backgrounding failed: %d %s",
							errno, strerror(errno));
				}
			}

#ifdef ENABLE_CLI_LOCALTCPFWD
			setup_localtcp();
#endif
#ifdef ENABLE_CLI_REMOTETCPFWD
			setup_remotetcp();
#endif

			if (!cli_opts.no_cmd) {
				cli_send_chansess_request();
			}
			cli_ses.state = SESSION_RUNNING;
			return;

		case SESSION_RUNNING:
			if (ses.chancount < 1 && !cli_opts.no_cmd) {
				cli_finished();
			}

			if (cli_ses.winchange) {
				cli_chansess_winchange();
			}
			return;

		/* XXX more here needed */


	default:
		break;
	}
}

static void cli_session_cleanup(void) {

	if (!sessinitdone) {
		return;
	}

	/* Set std{in,out,err} back to non-blocking - busybox ash dies nastily if
	 * we don't revert the flags */
	fcntl(cli_ses.stdincopy, F_SETFL, cli_ses.stdinflags);
	fcntl(cli_ses.stdoutcopy, F_SETFL, cli_ses.stdoutflags);
	fcntl(cli_ses.stderrcopy, F_SETFL, cli_ses.stderrflags);

	cli_tty_cleanup();

}

/* Remove a channel entry */
static void delete_channel(struct Channel *channel) {

	ses.channels[channel->index] = NULL;
	m_free(channel);
	ses.chancount--;

}

/* Remove a channel entry, this is only executed after both sides have sent
 * channel close */
static void remove_channel(struct Channel * channel) {

	cbuf_free(channel->writebuf);
	channel->writebuf = NULL;

	if (channel->extrabuf) {
		cbuf_free(channel->extrabuf);
		channel->extrabuf = NULL;
	}


	/* close the FDs in case they haven't been done
	 * yet (they might have been shutdown etc) */
	close(channel->writefd);
	close(channel->readfd);
	close(channel->errfd);

	channel->typedata = NULL;

	delete_channel(channel);
}

/* Clean up channels, freeing allocated memory */
static void chancleanup(void) {
	unsigned int i;

	for (i = 0; i < ses.chansize; i++) {
		if (ses.channels[i] != NULL)
			remove_channel(ses.channels[i]);
	}
	m_free(ses.channels);
}


/* clean up a session on exit */
static void common_session_cleanup(void) {

	/* we can't cleanup if we don't know the session state */
	if (!sessinitdone)
		return;

	m_free(ses.session_id);
	m_burn(ses.keys, sizeof(struct key_context));
	m_free(ses.keys);

	chancleanup();
}


static void cli_finished() {

	cli_session_cleanup();
	common_session_cleanup();
	fprintf(stderr, "Connection to %s@%s:%s closed.\n", cli_opts.username,
			cli_opts.remotehost, cli_opts.remoteport);
	exit(cli_ses.retval);
}


/* called when the remote side closes the connection */
static void cli_remoteclosed() {

	/* XXX TODO perhaps print a friendlier message if we get this but have
	 * already sent/received disconnect message(s) ??? */
	m_close(ses.sock_in);
	m_close(ses.sock_out);
	ses.sock_in = -1;
	ses.sock_out = -1;
	dropbear_exit("Remote closed the connection");
}



#ifdef ENABLE_CLI_LOCALTCPFWD
static int cli_localtcp(const char* listenaddr,
		unsigned int listenport,
		const char* remoteaddr,
		unsigned int remoteport);
static const struct ChanType cli_chan_tcplocal = {
	1, /* sepfds */
	"direct-tcpip",
	NULL,
	NULL,
	NULL,
	NULL
};
#endif

#ifdef ENABLE_CLI_LOCALTCPFWD
static void setup_localtcp() {
	m_list_elem *iter;
	int ret;

	for (iter = cli_opts.localfwds->first; iter; iter = iter->next) {
		struct TCPFwdEntry * fwd = (struct TCPFwdEntry*)iter->item;
		ret = cli_localtcp(
				fwd->listenaddr,
				fwd->listenport,
				fwd->connectaddr,
				fwd->connectport);
		if (ret == DROPBEAR_FAILURE) {
			dropbear_log("Failed local port forward %s:%d:%s:%d",
					fwd->listenaddr,
					fwd->listenport,
					fwd->connectaddr,
					fwd->connectport);
		}
	}
}

static int cli_localtcp(const char* listenaddr,
		unsigned int listenport,
		const char* remoteaddr,
		unsigned int remoteport) {

	struct TCPListener* tcpinfo = NULL;
	int ret;

	tcpinfo = (struct TCPListener*)m_malloc(sizeof(struct TCPListener));

	tcpinfo->sendaddr = m_strdup(remoteaddr);
	tcpinfo->sendport = remoteport;

	if (listenaddr)
	{
		tcpinfo->listenaddr = m_strdup(listenaddr);
	}
	else
	{
		if (opts.listen_fwd_all) {
			tcpinfo->listenaddr = m_strdup("");
		} else {
			tcpinfo->listenaddr = m_strdup("localhost");
		}
	}
	tcpinfo->listenport = listenport;

	tcpinfo->chantype = &cli_chan_tcplocal;
	tcpinfo->tcp_type = direct;

	ret = listen_tcpfwd(tcpinfo);

	if (ret == DROPBEAR_FAILURE) {
		m_free(tcpinfo);
	}
	return ret;
}
#endif /* ENABLE_CLI_LOCALTCPFWD */

#ifdef  ENABLE_CLI_REMOTETCPFWD
static void send_msg_global_request_remotetcp(const char *addr, int port) {

	buf_putbyte(ses.writepayload, SSH_MSG_GLOBAL_REQUEST);
	buf_putstring(ses.writepayload, "tcpip-forward", 13);
	buf_putbyte(ses.writepayload, 1); /* want_reply */
	buf_putstring(ses.writepayload, addr, strlen(addr));
	buf_putint(ses.writepayload, port);

	encrypt_packet();
}

/* The only global success/failure messages are for remotetcp.
 * Since there isn't any identifier in these messages, we have to rely on them
 * being in the same order as we sent the requests. This is the ordering
 * of the cli_opts.remotefwds list.
 * If the requested remote port is 0 the listen port will be
 * dynamically allocated by the server and the port number will be returned
 * to client and the port number reported to the user. */
static void cli_recv_msg_request_success() {
	/* We just mark off that we have received the reply,
	 * so that we can report failure for later ones. */
	m_list_elem * iter = NULL;
	for (iter = cli_opts.remotefwds->first; iter; iter = iter->next) {
		struct TCPFwdEntry *fwd = (struct TCPFwdEntry*)iter->item;
		if (!fwd->have_reply) {
			fwd->have_reply = 1;
			if (fwd->listenport == 0) {
				/* The server should let us know which port was allocated if we requestd port 0 */
				int allocport = buf_getint(ses.payload);
				if (allocport > 0) {
					dropbear_log("Allocated port %d for remote forward to %s:%d",
							allocport, fwd->connectaddr, fwd->connectport);
				}
			}
			return;
		}
	}
}

static void cli_recv_msg_request_failure() {
	m_list_elem *iter;
	for (iter = cli_opts.remotefwds->first; iter; iter = iter->next) {
		struct TCPFwdEntry *fwd = (struct TCPFwdEntry*)iter->item;
		if (!fwd->have_reply) {
			fwd->have_reply = 1;
			dropbear_log("Remote TCP forward request failed (port %d -> %s:%d)", fwd->listenport, fwd->connectaddr, fwd->connectport);
			return;
		}
	}
}

static void setup_remotetcp() {
	m_list_elem *iter;

	for (iter = cli_opts.remotefwds->first; iter; iter = iter->next) {
		struct TCPFwdEntry *fwd = (struct TCPFwdEntry*)iter->item;
		if (!fwd->listenaddr)
		{
			// we store the addresses so that we can compare them
			// when the server sends them back
			if (opts.listen_fwd_all) {
				fwd->listenaddr = m_strdup("");
			} else {
				fwd->listenaddr = m_strdup("localhost");
			}
		}
		send_msg_global_request_remotetcp(fwd->listenaddr, fwd->listenport);
	}
}

static int newtcpforwarded(struct Channel * channel) {

	char *origaddr = NULL;
	unsigned int origport;
	m_list_elem * iter = NULL;
	struct TCPFwdEntry *fwd;
	char portstring[NI_MAXSERV];
	int sock;
	int err = SSH_OPEN_ADMINISTRATIVELY_PROHIBITED;

	origaddr = buf_getstring(ses.payload, NULL);
	origport = buf_getint(ses.payload);

	/* Find which port corresponds */
	for (iter = cli_opts.remotefwds->first; iter; iter = iter->next) {
		fwd = (struct TCPFwdEntry*)iter->item;
		if (origport == fwd->listenport
				&& (strcmp(origaddr, fwd->listenaddr) == 0)) {
			break;
		}
	}

	if (iter == NULL) {
		/* We didn't request forwarding on that port */
		cleantext(origaddr);
		dropbear_log("Server sent unrequested forward from \"%s:%d\"",
				origaddr, origport);
		goto out;
	}

	snprintf(portstring, sizeof(portstring), "%d", fwd->connectport);
	sock = connect_remote(fwd->connectaddr, portstring, 1, NULL);
	if (sock < 0) {
		err = SSH_OPEN_CONNECT_FAILED;
		goto out;
	}

	ses.maxfd = MAX(ses.maxfd, sock);

	/* We don't set readfd, that will get set after the connection's
	 * progress succeeds */
	channel->writefd = sock;
	channel->initconn = 1;

	err = SSH_OPEN_IN_PROGRESS;

out:
	m_free(origaddr);
	return err;
}
#endif /* ENABLE_CLI_REMOTETCPFWD */



/* Output a comma separated list of algorithms to a buffer */
static void buf_put_algolist(buffer * buf, algo_type localalgos[]) {

	unsigned int i, len;
	unsigned int donefirst = 0;
	buffer *algolist = NULL;

	algolist = buf_new(160);
	for (i = 0; localalgos[i].name != NULL; i++) {
		if (localalgos[i].usable) {
			if (donefirst)
				buf_putbyte(algolist, ',');
			donefirst = 1;
			len = strlen(localalgos[i].name);
			buf_putbytes(algolist, (unsigned char *)localalgos[i].name, len);
		}
	}
	buf_putstring(buf, (char *)algolist->data, algolist->len);
	buf_free(algolist);
}

/* Handle the multiplexed channels, such as sessions, x11, agent connections */

static void send_msg_channel_open_failure(unsigned int remotechan, int reason,
		const char *text, const char *lang);
static void send_msg_channel_open_confirmation(struct Channel* channel,
		unsigned int recvwindow,
		unsigned int recvmaxpacket);
static void writechannel(struct Channel* channel, int fd, circbuffer *cbuf);
static void send_msg_channel_window_adjust(struct Channel *channel,
		unsigned int incr);
static void send_msg_channel_data(struct Channel *channel, int isextended);
static void send_msg_channel_eof(struct Channel *channel);
static void send_msg_channel_close(struct Channel *channel);
static void check_in_progress(struct Channel *channel);
static unsigned int write_pending(struct Channel * channel);
static void check_close(struct Channel *channel);
static void close_chan_fd(struct Channel *channel, int fd, int how);

#define FD_UNINIT (-2)
#define FD_CLOSED (-1)

#define ERRFD_IS_READ(channel) ((channel)->extrabuf == NULL)
#define ERRFD_IS_WRITE(channel) (!ERRFD_IS_READ(channel))

static void listeners_initialise(void) {
	/* just one slot to start with */
	ses.listeners = (struct Listener**)m_malloc(sizeof(struct Listener*));
	ses.listensize = 1;
	ses.listeners[0] = NULL;
}

/* Initialise all the channels */
static void chaninitialise(const struct ChanType *chantypes[]) {

	/* may as well create space for a single channel */
	ses.channels = (struct Channel**)m_malloc(sizeof(struct Channel*));
	ses.chansize = 1;
	ses.channels[0] = NULL;
	ses.chancount = 0;

	ses.chantypes = chantypes;

#ifdef USING_LISTENERS
	listeners_initialise();
#endif

}


/* Create a new channel entry, send a reply confirm or failure */
/* If remotechan, transwindow and transmaxpacket are not know (for a new
 * outgoing connection, with them to be filled on confirmation), they should
 * all be set to 0 */
static struct Channel* newchannel(unsigned int remotechan,
		const struct ChanType *type,
		unsigned int transwindow, unsigned int transmaxpacket) {

	struct Channel * newchan;
	unsigned int i, j;

	/* first see if we can use existing channels */
	for (i = 0; i < ses.chansize; i++) {
		if (ses.channels[i] == NULL) {
			break;
		}
	}

	/* otherwise extend the list */
	if (i == ses.chansize) {
		if (ses.chansize >= MAX_CHANNELS)
			return NULL;

		/* extend the channels */
		ses.channels = (struct Channel**)m_realloc(ses.channels,
				(ses.chansize+CHAN_EXTEND_SIZE)*sizeof(struct Channel*));

		ses.chansize += CHAN_EXTEND_SIZE;

		/* set the new channels to null */
		for (j = i; j < ses.chansize; j++) {
			ses.channels[j] = NULL;
		}

	}

	newchan = (struct Channel*)m_malloc(sizeof(struct Channel));
	newchan->type = type;
	newchan->index = i;
	newchan->sent_close = newchan->recv_close = 0;
	newchan->sent_eof = newchan->recv_eof = 0;
	newchan->close_handler_done = 0;

	newchan->remotechan = remotechan;
	newchan->transwindow = transwindow;
	newchan->transmaxpacket = transmaxpacket;

	newchan->typedata = NULL;
	newchan->writefd = FD_UNINIT;
	newchan->readfd = FD_UNINIT;
	newchan->errfd = FD_CLOSED; /* this isn't always set to start with */
	newchan->initconn = 0;
	newchan->await_open = 0;
	newchan->flushing = 0;

	newchan->writebuf = cbuf_new(opts.recv_window);
	newchan->extrabuf = NULL; /* The user code can set it up */
	newchan->recvwindow = opts.recv_window;
	newchan->recvdonelen = 0;
	newchan->recvmaxpacket = RECV_MAX_PAYLOAD_LEN;

	ses.channels[i] = newchan;
	ses.chancount++;

	return newchan;
}

static void handle_listeners(fd_set * readfds) {

	unsigned int i, j;
	struct Listener *listener;
	int sock;

	/* check each in turn */
	for (i = 0; i < ses.listensize; i++) {
		listener = ses.listeners[i];
		if (listener != NULL) {
			for (j = 0; j < listener->nsocks; j++) {
				sock = listener->socks[j];
				if (FD_ISSET(sock, readfds)) {
					listener->acceptor(listener, sock);
				}
			}
		}
	}
} /* Woo brace matching */


/* Iterate through the channels, performing IO if available */
static void channelio(fd_set *readfds, fd_set *writefds) {

	struct Channel *channel;
	unsigned int i;

	/* foreach channel */
	for (i = 0; i < ses.chansize; i++) {

		channel = ses.channels[i];
		if (channel == NULL) {
			/* only process in-use channels */
			continue;
		}

		/* read data and send it over the wire */
		if (channel->readfd >= 0 && FD_ISSET(channel->readfd, readfds))
			send_msg_channel_data(channel, 0);

		/* read stderr data and send it over the wire */
		if (ERRFD_IS_READ(channel) && channel->errfd >= 0
			&& FD_ISSET(channel->errfd, readfds))
				send_msg_channel_data(channel, 1);

		/* write to program/pipe stdin */
		if (channel->writefd >= 0 && FD_ISSET(channel->writefd, writefds)) {
			if (channel->initconn) {
				/* XXX should this go somewhere cleaner? */
				check_in_progress(channel);
				continue; /* Important not to use the channel after
							 check_in_progress(), as it may be NULL */
			}
			writechannel(channel, channel->writefd, channel->writebuf);
		}

		/* stderr for client mode */
		if (ERRFD_IS_WRITE(channel)
				&& channel->errfd >= 0 && FD_ISSET(channel->errfd, writefds)) {
			writechannel(channel, channel->errfd, channel->extrabuf);
		}

		/* handle any channel closing etc */
		check_close(channel);

	}

	/* Listeners such as TCP, X11, agent-auth */
#ifdef USING_LISTENERS
	handle_listeners(readfds);
#endif
}


/* Returns true if there is data remaining to be written to stdin or
 * stderr of a channel's endpoint. */
static unsigned int write_pending(struct Channel * channel) {

	if (channel->writefd >= 0 && cbuf_getused(channel->writebuf) > 0) {
		return 1;
	} else if (channel->errfd >= 0 && channel->extrabuf &&
			cbuf_getused(channel->extrabuf) > 0) {
		return 1;
	}
	return 0;
}


/* EOF/close handling */
static void check_close(struct Channel *channel) {
	int close_allowed = 0;

	if (!channel->flushing
		&& !channel->close_handler_done
		&& channel->type->check_close
		&& channel->type->check_close(channel))
	{
		channel->flushing = 1;
	}

	/* if a type-specific check_close is defined we will only exit
	   once that has been triggered. this is only used for a server "session"
	   channel, to ensure that the shell has exited (and the exit status
	   retrieved) before we close things up. */
	if (!channel->type->check_close
		|| channel->close_handler_done
		|| channel->type->check_close(channel)) {
		close_allowed = 1;
	}

	if (channel->recv_close && !write_pending(channel) && close_allowed) {
		if (!channel->sent_close)
			send_msg_channel_close(channel);
		remove_channel(channel);
		return;
	}

	if (channel->recv_eof && !write_pending(channel)) {
		close_chan_fd(channel, channel->writefd, SHUT_WR);
	}

	/* Special handling for flushing read data after an exit. We
	   read regardless of whether the select FD was set,
	   and if there isn't data available, the channel will get closed. */
	if (channel->flushing) {
		if (channel->readfd >= 0 && channel->transwindow > 0)
			send_msg_channel_data(channel, 0);
		if (ERRFD_IS_READ(channel) && channel->errfd >= 0
			&& channel->transwindow > 0) {
			send_msg_channel_data(channel, 1);
		}
	}

	/* If we're not going to send any more data, send EOF */
	if (!channel->sent_eof
			&& channel->readfd == FD_CLOSED
			&& (ERRFD_IS_WRITE(channel) || channel->errfd == FD_CLOSED)) {
		send_msg_channel_eof(channel);
	}

	/* And if we can't receive any more data from them either, close up */
	if (channel->readfd == FD_CLOSED
			&& (ERRFD_IS_WRITE(channel) || channel->errfd == FD_CLOSED)
			&& !channel->sent_close
			&& close_allowed
			&& !write_pending(channel)) {
		send_msg_channel_close(channel);
	}
}

/* Check whether a deferred (EINPROGRESS) connect() was successful, and
 * if so, set up the channel properly. Otherwise, the channel is cleaned up, so
 * it is important that the channel reference isn't used after a call to this
 * function */
static void check_in_progress(struct Channel *channel) {

	int val;
	socklen_t vallen = sizeof(val);

	if (getsockopt(channel->writefd, SOL_SOCKET, SO_ERROR, &val, &vallen)
			|| val != 0) {
		send_msg_channel_open_failure(channel->remotechan,
				SSH_OPEN_CONNECT_FAILED, "", "");
		close(channel->writefd);
		delete_channel(channel);
	} else {
		send_msg_channel_open_confirmation(channel, channel->recvwindow,
				channel->recvmaxpacket);
		channel->readfd = channel->writefd;
		channel->initconn = 0;
	}
}


/* Send the close message and set the channel as closed */
static void send_msg_channel_close(struct Channel *channel) {

	if (channel->type->closehandler
			&& !channel->close_handler_done) {
		channel->type->closehandler(channel);
		channel->close_handler_done = 1;
	}

	buf_putbyte(ses.writepayload, SSH_MSG_CHANNEL_CLOSE);
	buf_putint(ses.writepayload, channel->remotechan);

	encrypt_packet();

	channel->sent_eof = 1;
	channel->sent_close = 1;
	close_chan_fd(channel, channel->readfd, SHUT_RD);
	close_chan_fd(channel, channel->errfd, SHUT_RDWR);
	close_chan_fd(channel, channel->writefd, SHUT_WR);
}

/* call this when trans/eof channels are closed */
static void send_msg_channel_eof(struct Channel *channel) {

	buf_putbyte(ses.writepayload, SSH_MSG_CHANNEL_EOF);
	buf_putint(ses.writepayload, channel->remotechan);

	encrypt_packet();

	channel->sent_eof = 1;
}

/* Called to write data out to the local side of the channel.
 * Only called when we know we can write to a channel, writes as much as
 * possible */
static void writechannel(struct Channel* channel, int fd, circbuffer *cbuf) {

	int len, maxlen;

	maxlen = cbuf_readlen(cbuf);

	/* Write the data out */
	len = write(fd, cbuf_readptr(cbuf, maxlen), maxlen);
	if (len <= 0) {
		if (len < 0 && errno != EINTR) {
			close_chan_fd(channel, fd, SHUT_WR);
		}
		return;
	}

	cbuf_incrread(cbuf, len);
	channel->recvdonelen += len;

	/* Window adjust handling */
	if (channel->recvdonelen >= RECV_WINDOWEXTEND) {
		/* Set it back to max window */
		send_msg_channel_window_adjust(channel, channel->recvdonelen);
		channel->recvwindow += channel->recvdonelen;
		channel->recvdonelen = 0;
	}

	dropbear_assert(channel->recvwindow <= opts.recv_window);
	dropbear_assert(channel->recvwindow <= cbuf_getavail(channel->writebuf));
	dropbear_assert(channel->extrabuf == NULL ||
			channel->recvwindow <= cbuf_getavail(channel->extrabuf));
}

static void set_listener_fds(fd_set * readfds) {

	unsigned int i, j;
	struct Listener *listener;

	/* check each in turn */
	for (i = 0; i < ses.listensize; i++) {
		listener = ses.listeners[i];
		if (listener != NULL) {
			for (j = 0; j < listener->nsocks; j++) {
				FD_SET(listener->socks[j], readfds);
			}
		}
	}
}


/* Set the file descriptors for the main select in session.c
 * This avoid channels which don't have any window available, are closed, etc*/
static void setchannelfds(fd_set *readfds, fd_set *writefds) {

	unsigned int i;
	struct Channel * channel;

	for (i = 0; i < ses.chansize; i++) {

		channel = ses.channels[i];
		if (channel == NULL) {
			continue;
		}

		/* Stuff to put over the wire */
		if (channel->transwindow > 0) {

			if (channel->readfd >= 0) {
				FD_SET(channel->readfd, readfds);
			}

			if (ERRFD_IS_READ(channel) && channel->errfd >= 0) {
					FD_SET(channel->errfd, readfds);
			}
		}

		/* Stuff from the wire */
		if ((channel->writefd >= 0 && cbuf_getused(channel->writebuf) > 0 )
				|| channel->initconn) {
				FD_SET(channel->writefd, writefds);
		}

		if (ERRFD_IS_WRITE(channel) && channel->errfd >= 0
				&& cbuf_getused(channel->extrabuf) > 0 ) {
				FD_SET(channel->errfd, writefds);
		}

	} /* foreach channel */

#ifdef USING_LISTENERS
	set_listener_fds(readfds);
#endif

}

/* handle the channel EOF event, by closing the channel filedescriptor. The
 * channel isn't closed yet, it is left until the incoming (from the program
 * etc) FD is also EOF */
static void recv_msg_channel_eof(void) {

	struct Channel * channel;

	channel = getchannel_msg("EOF");
	channel->recv_eof = 1;
	check_close(channel);
}


/* Handle channel closure(), respond in kind and close the channels */
static void recv_msg_channel_close(void) {

	struct Channel * channel;

	channel = getchannel_msg("Close");
	channel->recv_eof = 1;
	channel->recv_close = 1;
	check_close(channel);
}



/* Handle channel specific requests, passing off to corresponding handlers
 * such as chansession or x11fwd */
static void recv_msg_channel_request(void) {

	struct Channel *channel;

	channel = getchannel();

	if (channel->sent_close)
		return;

	if (channel->type->reqhandler
			&& !channel->close_handler_done) {
		channel->type->reqhandler(channel);
	} else {
		send_msg_channel_failure(channel);
	}
}

/* Reads data from the server's program/shell/etc, and puts it in a
 * channel_data packet to send.
 * chan is the remote channel, isextended is 0 if it is normal data, 1
 * if it is extended data. if it is extended, then the type is in
 * exttype */
static void send_msg_channel_data(struct Channel *channel, int isextended) {

	int len;
	size_t maxlen, size_pos;
	int fd;

	dropbear_assert(!channel->sent_close);

	if (isextended) {
		fd = channel->errfd;
	} else {
		fd = channel->readfd;
	}
	dropbear_assert(fd >= 0);

	maxlen = MIN(channel->transwindow, channel->transmaxpacket);
	/* -(1+4+4) is SSH_MSG_CHANNEL_DATA, channel number, string length, and
	 * exttype if is extended */
	maxlen = MIN(maxlen,
			ses.writepayload->size - 1 - 4 - 4 - (isextended ? 4 : 0));
	if (maxlen == 0)
		return;

	buf_putbyte(ses.writepayload,
			isextended ? SSH_MSG_CHANNEL_EXTENDED_DATA : SSH_MSG_CHANNEL_DATA);
	buf_putint(ses.writepayload, channel->remotechan);
	if (isextended) {
		buf_putint(ses.writepayload, SSH_EXTENDED_DATA_STDERR);
	}
	/* a dummy size first ...*/
	size_pos = ses.writepayload->pos;
	buf_putint(ses.writepayload, 0);

	/* read the data */
	len = read(fd, buf_getwriteptr(ses.writepayload, maxlen), maxlen);
	if (len <= 0) {
		if (len == 0 || errno != EINTR) {
			/* This will also get hit in the case of EAGAIN. The only
			time we expect to receive EAGAIN is when we're flushing a FD,
			in which case it can be treated the same as EOF */
			close_chan_fd(channel, fd, SHUT_RD);
		}
		ses.writepayload->len = ses.writepayload->pos = 0;
		return;
	}
	buf_incrwritepos(ses.writepayload, len);
	/* ... real size here */
	buf_setpos(ses.writepayload, size_pos);
	buf_putint(ses.writepayload, len);

	channel->transwindow -= len;

	encrypt_packet();

	/* If we receive less data than we requested when flushing, we've
	   reached the equivalent of EOF */
	if (channel->flushing && len < (ssize_t)maxlen)
		close_chan_fd(channel, fd, SHUT_RD);
}

/* We receive channel data */
static void recv_msg_channel_data(void) {
	struct Channel *channel;

	channel = getchannel();

	common_recv_msg_channel_data(channel, channel->writefd, channel->writebuf);
}

/* Shared for data and stderr data - when we receive data, put it in a buffer
 * for writing to the local file descriptor */
static void common_recv_msg_channel_data(struct Channel *channel, int fd,
		circbuffer * cbuf) {

	unsigned int datalen;
	unsigned int maxdata;
	unsigned int buflen;
	unsigned int len;

	if (channel->recv_eof)
		dropbear_exit("Received data after eof");

	if (fd < 0) {
		/* If we have encountered failed write, the far side might still
		 * be sending data without having yet received our close notification.
		 * We just drop the data. */
		return;
	}

	datalen = buf_getint(ses.payload);

	maxdata = cbuf_getavail(cbuf);

	/* Whilst the spec says we "MAY ignore data past the end" this could
	 * lead to corrupted file transfers etc (chunks missed etc). It's better to
	 * just die horribly */
	if (datalen > maxdata)
		dropbear_exit("Oversized packet");

	/* We may have to run throught twice, if the buffer wraps around. Can't
	 * just "leave it for next time" like with writechannel, since this
	 * is payload data */
	len = datalen;
	while (len > 0) {
		buflen = cbuf_writelen(cbuf);
		buflen = MIN(buflen, len);

		memcpy(cbuf_writeptr(cbuf, buflen),
				buf_getptr(ses.payload, buflen), buflen);
		cbuf_incrwrite(cbuf, buflen);
		buf_incrpos(ses.payload, buflen);
		len -= buflen;
	}

	dropbear_assert(channel->recvwindow >= datalen);
	channel->recvwindow -= datalen;
	dropbear_assert(channel->recvwindow <= opts.recv_window);
}

/* Increment the outgoing data window for a channel - the remote end limits
 * the amount of data which may be transmitted, this window is decremented
 * as data is sent, and incremented upon receiving window-adjust messages */
static void recv_msg_channel_window_adjust(void) {

	struct Channel * channel;
	unsigned int incr;

	channel = getchannel();

	incr = buf_getint(ses.payload);
	incr = MIN(incr, TRANS_MAX_WIN_INCR);

	channel->transwindow += incr;
	channel->transwindow = MIN(channel->transwindow, TRANS_MAX_WINDOW);

}

/* Increment the incoming data window for a channel, and let the remote
 * end know */
static void send_msg_channel_window_adjust(struct Channel* channel,
		unsigned int incr) {

	buf_putbyte(ses.writepayload, SSH_MSG_CHANNEL_WINDOW_ADJUST);
	buf_putint(ses.writepayload, channel->remotechan);
	buf_putint(ses.writepayload, incr);

	encrypt_packet();
}

/* Handle a new channel request, performing any channel-type-specific setup */
static void recv_msg_channel_open(void) {

	char *type;
	unsigned int typelen;
	unsigned int remotechan, transwindow, transmaxpacket;
	struct Channel *channel;
	const struct ChanType **cp;
	const struct ChanType *chantype;
	unsigned int errtype = SSH_OPEN_UNKNOWN_CHANNEL_TYPE;
	int ret;


	/* get the packet contents */
	type = buf_getstring(ses.payload, &typelen);

	remotechan = buf_getint(ses.payload);
	transwindow = buf_getint(ses.payload);
	transwindow = MIN(transwindow, TRANS_MAX_WINDOW);
	transmaxpacket = buf_getint(ses.payload);
	transmaxpacket = MIN(transmaxpacket, TRANS_MAX_PAYLOAD_LEN);

	/* figure what type of packet it is */
	if (typelen > MAX_NAME_LEN) {
		goto failure;
	}

	/* Get the channel type. Client and server style invokation will set up a
	 * different list for ses.chantypes at startup. We just iterate through
	 * this list and find the matching name */
	for (cp = &ses.chantypes[0], chantype = (*cp);
			chantype != NULL;
			cp++, chantype = (*cp)) {
		if (strcmp(type, chantype->name) == 0) {
			break;
		}
	}

	if (chantype == NULL)
		goto failure;

	/* create the channel */
	channel = newchannel(remotechan, chantype, transwindow, transmaxpacket);

	if (channel == NULL)
		goto failure;

	if (channel->type->inithandler) {
		ret = channel->type->inithandler(channel);
		if (ret == SSH_OPEN_IN_PROGRESS) {
			/* We'll send the confirmation later */
			goto cleanup;
		}
		if (ret > 0) {
			errtype = ret;
			delete_channel(channel);
			goto failure;
		}
	}

	/* success */
	send_msg_channel_open_confirmation(channel, channel->recvwindow,
			channel->recvmaxpacket);
	goto cleanup;

failure:
	send_msg_channel_open_failure(remotechan, errtype, "", "");

cleanup:
	m_free(type);
}

/* Send a failure message */
static void send_msg_channel_failure(struct Channel *channel) {

	buf_putbyte(ses.writepayload, SSH_MSG_CHANNEL_FAILURE);
	buf_putint(ses.writepayload, channel->remotechan);

	encrypt_packet();
}

/* Send a channel open failure message, with a corresponding reason
 * code (usually resource shortage or unknown chan type) */
static void send_msg_channel_open_failure(unsigned int remotechan,
		int reason, const char *text, const char *lang) {

	buf_putbyte(ses.writepayload, SSH_MSG_CHANNEL_OPEN_FAILURE);
	buf_putint(ses.writepayload, remotechan);
	buf_putint(ses.writepayload, reason);
	buf_putstring(ses.writepayload, text, strlen(text));
	buf_putstring(ses.writepayload, lang, strlen(lang));

	encrypt_packet();
}

/* Confirm a channel open, and let the remote end know what number we've
 * allocated and the receive parameters */
static void send_msg_channel_open_confirmation(struct Channel* channel,
		unsigned int recvwindow,
		unsigned int recvmaxpacket) {

	buf_putbyte(ses.writepayload, SSH_MSG_CHANNEL_OPEN_CONFIRMATION);
	buf_putint(ses.writepayload, channel->remotechan);
	buf_putint(ses.writepayload, channel->index);
	buf_putint(ses.writepayload, recvwindow);
	buf_putint(ses.writepayload, recvmaxpacket);

	encrypt_packet();
}

/* close a fd, how is SHUT_RD or SHUT_WR */
static void close_chan_fd(struct Channel *channel, int fd, int how) {

	int closein = 0, closeout = 0;

	if (channel->type->sepfds) {
		shutdown(fd, how);
		if (how == 0) {
			closeout = 1;
		} else {
			closein = 1;
		}
	} else {
		close(fd);
		closein = closeout = 1;
	}

	if (closeout && (fd == channel->readfd)) {
		channel->readfd = FD_CLOSED;
	}
	if (closeout && ERRFD_IS_READ(channel) && (fd == channel->errfd)) {
		channel->errfd = FD_CLOSED;
	}

	if (closein && fd == channel->writefd) {
		channel->writefd = FD_CLOSED;
	}
	if (closein && ERRFD_IS_WRITE(channel) && (fd == channel->errfd)) {
		channel->errfd = FD_CLOSED;
	}

	/* if we called shutdown on it and all references are gone, then we
	 * need to close() it to stop it lingering */
	if (channel->type->sepfds && channel->readfd == FD_CLOSED
		&& channel->writefd == FD_CLOSED && channel->errfd == FD_CLOSED) {
		close(fd);
	}
}


/* Create a new channel, and start the open request. This is intended
 * for X11, agent, tcp forwarding, and should be filled with channel-specific
 * options, with the calling function calling encrypt_packet() after
 * completion. It is mandatory for the caller to encrypt_packet() if
 * DROPBEAR_SUCCESS is returned */
static int send_msg_channel_open_init(int fd, const struct ChanType *type) {

	struct Channel* chan;

	chan = newchannel(0, type, 0, 0);
	if (!chan) {
		return DROPBEAR_FAILURE;
	}

	/* set fd non-blocking */
	setnonblocking(fd);

	chan->writefd = chan->readfd = fd;
	ses.maxfd = MAX(ses.maxfd, fd);

	chan->await_open = 1;

	/* now open the channel connection */
	buf_putbyte(ses.writepayload, SSH_MSG_CHANNEL_OPEN);
	buf_putstring(ses.writepayload, type->name, strlen(type->name));
	buf_putint(ses.writepayload, chan->index);
	buf_putint(ses.writepayload, opts.recv_window);
	buf_putint(ses.writepayload, RECV_MAX_PAYLOAD_LEN);

	return DROPBEAR_SUCCESS;
}

/* Confirmation that our channel open request (for forwardings) was
 * successful*/
static void recv_msg_channel_open_confirmation(void) {

	struct Channel * channel;
	int ret;

	channel = getchannel();

	if (!channel->await_open)
		dropbear_exit("Unexpected channel reply");
	channel->await_open = 0;

	channel->remotechan =  buf_getint(ses.payload);
	channel->transwindow = buf_getint(ses.payload);
	channel->transmaxpacket = buf_getint(ses.payload);

	/* Run the inithandler callback */
	if (channel->type->inithandler) {
		ret = channel->type->inithandler(channel);
		if (ret > 0)
			remove_channel(channel);
	}
}

/* Notification that our channel open request failed */
static void recv_msg_channel_open_failure(void) {

	struct Channel * channel;

	channel = getchannel();

	if (!channel->await_open)
		dropbear_exit("Unexpected channel reply");
	channel->await_open = 0;

	remove_channel(channel);
}

/* diffie-hellman-group1-sha1 value for p */
#define DH_P_1_LEN 128
static const unsigned char dh_p_1[DH_P_1_LEN] = {
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2,
    0x21, 0x68, 0xC2, 0x34, 0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
	0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74, 0x02, 0x0B, 0xBE, 0xA6,
	0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
	0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D,
	0xF2, 0x5F, 0x14, 0x37, 0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
	0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6, 0xF4, 0x4C, 0x42, 0xE9,
	0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
	0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11,
	0x7C, 0x4B, 0x1F, 0xE6, 0x49, 0x28, 0x66, 0x51, 0xEC, 0xE6, 0x53, 0x81,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

/* diffie-hellman-group14-sha1 value for p */
#define DH_P_14_LEN 256
static const unsigned char dh_p_14[DH_P_14_LEN] = {
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2,
    0x21, 0x68, 0xC2, 0x34, 0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
	0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74, 0x02, 0x0B, 0xBE, 0xA6,
	0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
	0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D,
	0xF2, 0x5F, 0x14, 0x37, 0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
	0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6, 0xF4, 0x4C, 0x42, 0xE9,
	0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
	0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11,
	0x7C, 0x4B, 0x1F, 0xE6, 0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
	0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05, 0x98, 0xDA, 0x48, 0x36,
	0x1C, 0x55, 0xD3, 0x9A, 0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
	0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96, 0x1C, 0x62, 0xF3, 0x56,
	0x20, 0x85, 0x52, 0xBB, 0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
	0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04, 0xF1, 0x74, 0x6C, 0x08,
	0xCA, 0x18, 0x21, 0x7C, 0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
	0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03, 0x9B, 0x27, 0x83, 0xA2,
	0xEC, 0x07, 0xA2, 0x8F, 0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9,
	0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18, 0x39, 0x95, 0x49, 0x7C,
	0xEA, 0x95, 0x6A, 0xE5, 0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
	0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAC, 0xAA, 0x68, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF};

/* Same for group1 and group14 */
static const int DH_G_VAL = 2;

static void kexinitialise();
static void gen_new_keys();
#ifndef DISABLE_ZLIB
static void gen_new_zstreams();
#endif
static void read_kex_algos();
/* helper function for gen_new_keys */
static void hashkeys(unsigned char *out, int outlen,
		const hash_state * hs, unsigned const char X);


/* return len bytes of pseudo-random data */
static void genrandom(unsigned char* buf, unsigned int len) {

	hash_state hs;
	unsigned char hash[SHA1_HASH_SIZE];
	unsigned int copylen;

	if (!donerandinit)
		dropbear_exit("seedrandom not done");

	while (len > 0) {
		sha1_init(&hs);
		sha1_process(&hs, (void*)hashpool, sizeof(hashpool));
		sha1_process(&hs, (void*)&counter, sizeof(counter));
		sha1_done(&hs, hash);

		counter++;
		if (counter > MAX_COUNTER) {
			seedrandom();
		}

		copylen = MIN(len, SHA1_HASH_SIZE);
		memcpy(buf, hash, copylen);
		len -= copylen;
		buf += copylen;
	}
	m_burn(hash, sizeof(hash));
}

/* Send our list of algorithms we can use */
static void send_msg_kexinit() {

	buf_putbyte(ses.writepayload, SSH_MSG_KEXINIT);

	/* cookie */
	genrandom(buf_getwriteptr(ses.writepayload, 16), 16);
	buf_incrwritepos(ses.writepayload, 16);

	/* kex algos */
	buf_put_algolist(ses.writepayload, sshkex);

	/* server_host_key_algorithms */
	buf_put_algolist(ses.writepayload, sshhostkey);

	/* encryption_algorithms_client_to_server */
	buf_put_algolist(ses.writepayload, sshciphers);

	/* encryption_algorithms_server_to_client */
	buf_put_algolist(ses.writepayload, sshciphers);

	/* mac_algorithms_client_to_server */
	buf_put_algolist(ses.writepayload, sshhashes);

	/* mac_algorithms_server_to_client */
	buf_put_algolist(ses.writepayload, sshhashes);

	/* compression_algorithms_client_to_server */
	buf_put_algolist(ses.writepayload, ses.compress_algos);

	/* compression_algorithms_server_to_client */
	buf_put_algolist(ses.writepayload, ses.compress_algos);

	/* languages_client_to_server */
	buf_putstring(ses.writepayload, "", 0);

	/* languages_server_to_client */
	buf_putstring(ses.writepayload, "", 0);

	/* first_kex_packet_follows - unimplemented for now */
	buf_putbyte(ses.writepayload, 0x00);

	/* reserved unit32 */
	buf_putint(ses.writepayload, 0);

	/* set up transmitted kex packet buffer for hashing.
	 * This is freed after the end of the kex */
	ses.transkexinit = buf_newcopy(ses.writepayload);

	encrypt_packet();
	ses.dataallowed = 0; /* don't send other packets during kex */

	ses.kexstate.sentkexinit = 1;
}

/* *** NOTE regarding (send|recv)_msg_newkeys ***
 * Changed by mihnea from the original kex.c to set dataallowed after a
 * completed key exchange, no matter the order in which it was performed.
 * This enables client mode without affecting server functionality.
 */

/* Bring new keys into use after a key exchange, and let the client know*/
static void send_msg_newkeys() {

	/* generate the kexinit request */
	buf_putbyte(ses.writepayload, SSH_MSG_NEWKEYS);
	encrypt_packet();


	/* set up our state */
	if (ses.kexstate.recvnewkeys) {
		gen_new_keys();
		kexinitialise(); /* we've finished with this kex */
		ses.dataallowed = 1; /* we can send other packets again now */
		ses.kexstate.donefirstkex = 1;
	} else {
		ses.kexstate.sentnewkeys = 1;
	}
}

/* Bring the new keys into use after a key exchange */
static void recv_msg_newkeys() {

	/* simply check if we've sent SSH_MSG_NEWKEYS, and if so,
	 * switch to the new keys */
	if (ses.kexstate.sentnewkeys) {
		gen_new_keys();
		kexinitialise(); /* we've finished with this kex */
		ses.dataallowed = 1; /* we can send other packets again now */
		ses.kexstate.donefirstkex = 1;
	} else {
		ses.kexstate.recvnewkeys = 1;
	}
}


/* Set up the kex for the first time */
static void kexfirstinitialise() {
	ses.kexstate.donefirstkex = 0;

#ifndef DISABLE_ZLIB
	if (opts.enable_compress) {
		ses.compress_algos = ssh_compress;
	} else
#endif
	{
		ses.compress_algos = ssh_nocompress;
	}
	kexinitialise();
}

/* Reset the kex state, ready for a new negotiation */
static void kexinitialise() {

	/* sent/recv'd MSG_KEXINIT */
	ses.kexstate.sentkexinit = 0;
	ses.kexstate.recvkexinit = 0;

	/* sent/recv'd MSG_NEWKEYS */
	ses.kexstate.recvnewkeys = 0;
	ses.kexstate.sentnewkeys = 0;

	/* first_packet_follows */
	ses.kexstate.firstfollows = 0;

	ses.kexstate.datatrans = 0;
	ses.kexstate.datarecv = 0;

	ses.kexstate.lastkextime = time(NULL);

}

/* Helper function for gen_new_keys, creates a hash. It makes a copy of the
 * already initialised hash_state hs, which should already have processed
 * the dh_K and hash, since these are common. X is the letter 'A', 'B' etc.
 * out must have at least min(SHA1_HASH_SIZE, outlen) bytes allocated.
 * The output will only be expanded once, as we are assured that
 * outlen <= 2*SHA1_HASH_SIZE for all known hashes.
 *
 * See Section 7.2 of rfc4253 (ssh transport) for details */
static void hashkeys(unsigned char *out, int outlen,
		const hash_state * hs, const unsigned char X) {

	hash_state hs2;
	unsigned char k2[SHA1_HASH_SIZE]; /* used to extending */

	memcpy(&hs2, hs, sizeof(hash_state));
	sha1_process(&hs2, &X, 1);
	sha1_process(&hs2, (unsigned char *)ses.session_id, SHA1_HASH_SIZE);
	sha1_done(&hs2, out);
	if (SHA1_HASH_SIZE < outlen) {
		/* need to extend */
		memcpy(&hs2, hs, sizeof(hash_state));
		sha1_process(&hs2, out, SHA1_HASH_SIZE);
		sha1_done(&hs2, k2);
		memcpy(&out[SHA1_HASH_SIZE], k2, outlen - SHA1_HASH_SIZE);
	}
}

/* Generate the actual encryption/integrity keys, using the results of the
 * key exchange, as specified in section 7.2 of the transport rfc 4253.
 * This occurs after the DH key-exchange.
 *
 * ses.newkeys is the new set of keys which are generated, these are only
 * taken into use after both sides have sent a newkeys message */

/* Originally from kex.c, generalized for cli/svr mode --mihnea */
static void gen_new_keys() {

	unsigned char C2S_IV[MAX_IV_LEN];
	unsigned char C2S_key[MAX_KEY_LEN];
	unsigned char S2C_IV[MAX_IV_LEN];
	unsigned char S2C_key[MAX_KEY_LEN];
	/* unsigned char key[MAX_KEY_LEN]; */
	unsigned char *trans_IV, *trans_key, *recv_IV, *recv_key;

	hash_state hs;
	unsigned int C2S_keysize, S2C_keysize;
	char mactransletter, macrecvletter; /* Client or server specific */
	int recv_cipher = 0, trans_cipher = 0;

	/* the dh_K and hash are the start of all hashes, we make use of that */

	sha1_init(&hs);
	sha1_process_mp(&hs, ses.dh_K);
	mp_clear(ses.dh_K);
	m_free(ses.dh_K);
	sha1_process(&hs, ses.hash, SHA1_HASH_SIZE);
	m_burn(ses.hash, SHA1_HASH_SIZE);

	trans_IV    = C2S_IV;
	recv_IV     = S2C_IV;
	trans_key   = C2S_key;
	recv_key    = S2C_key;
	C2S_keysize = ses.newkeys->trans.algo_crypt->keysize;
	S2C_keysize = ses.newkeys->recv.algo_crypt->keysize;
	mactransletter = 'E';
	macrecvletter = 'F';

	hashkeys(C2S_IV, SHA1_HASH_SIZE, &hs, 'A');
	hashkeys(S2C_IV, SHA1_HASH_SIZE, &hs, 'B');
	hashkeys(C2S_key, C2S_keysize, &hs, 'C');
	hashkeys(S2C_key, S2C_keysize, &hs, 'D');

	recv_cipher = find_cipher(ses.newkeys->recv.algo_crypt->cipherdesc->name);
	if (recv_cipher < 0)
	    dropbear_exit("Crypto error");
	if (ses.newkeys->recv.crypt_mode->start(recv_cipher,
			recv_IV, recv_key,
			ses.newkeys->recv.algo_crypt->keysize, 0,
			&ses.newkeys->recv.cipher_state) != CRYPT_OK) {
		dropbear_exit("Crypto error");
	}

	trans_cipher = find_cipher(ses.newkeys->trans.algo_crypt->cipherdesc->name);
	if (trans_cipher < 0)
	    dropbear_exit("Crypto error");
	if (ses.newkeys->trans.crypt_mode->start(trans_cipher,
			trans_IV, trans_key,
			ses.newkeys->trans.algo_crypt->keysize, 0,
			&ses.newkeys->trans.cipher_state) != CRYPT_OK) {
		dropbear_exit("Crypto error");
	}

	/* MAC keys */
	hashkeys(ses.newkeys->trans.mackey,
			ses.newkeys->trans.algo_mac->keysize, &hs, mactransletter);
	hashkeys(ses.newkeys->recv.mackey,
			ses.newkeys->recv.algo_mac->keysize, &hs, macrecvletter);
	ses.newkeys->trans.hash_index = find_hash(ses.newkeys->trans.algo_mac->hashdesc->name),
	ses.newkeys->recv.hash_index = find_hash(ses.newkeys->recv.algo_mac->hashdesc->name),

#ifndef DISABLE_ZLIB
	gen_new_zstreams();
#endif

	/* Switch over to the new keys */
	m_burn(ses.keys, sizeof(struct key_context));
	m_free(ses.keys);
	ses.keys = ses.newkeys;
	ses.newkeys = NULL;

	m_burn(C2S_IV, sizeof(C2S_IV));
	m_burn(C2S_key, sizeof(C2S_key));
	m_burn(S2C_IV, sizeof(S2C_IV));
	m_burn(S2C_key, sizeof(S2C_key));
}

#ifndef DISABLE_ZLIB

static int is_compress_trans() {
	return ses.keys->trans.algo_comp == DROPBEAR_COMP_ZLIB
		|| (ses.authstate.authdone
			&& ses.keys->trans.algo_comp == DROPBEAR_COMP_ZLIB_DELAY);
}

static int is_compress_recv() {
	return ses.keys->recv.algo_comp == DROPBEAR_COMP_ZLIB
		|| (ses.authstate.authdone
			&& ses.keys->recv.algo_comp == DROPBEAR_COMP_ZLIB_DELAY);
}

/* Set up new zlib compression streams, close the old ones. Only
 * called from gen_new_keys() */
static void gen_new_zstreams() {

	/* create new zstreams */
	if (ses.newkeys->recv.algo_comp == DROPBEAR_COMP_ZLIB
			|| ses.newkeys->recv.algo_comp == DROPBEAR_COMP_ZLIB_DELAY) {
		ses.newkeys->recv.zstream = (z_streamp)m_malloc(sizeof(z_stream));
		ses.newkeys->recv.zstream->zalloc = Z_NULL;
		ses.newkeys->recv.zstream->zfree = Z_NULL;

		if (inflateInit(ses.newkeys->recv.zstream) != Z_OK)
			dropbear_exit("zlib error");
	} else {
		ses.newkeys->recv.zstream = NULL;
	}

	if (ses.newkeys->trans.algo_comp == DROPBEAR_COMP_ZLIB
			|| ses.newkeys->trans.algo_comp == DROPBEAR_COMP_ZLIB_DELAY) {
		ses.newkeys->trans.zstream = (z_streamp)m_malloc(sizeof(z_stream));
		ses.newkeys->trans.zstream->zalloc = Z_NULL;
		ses.newkeys->trans.zstream->zfree = Z_NULL;

		if (deflateInit2(ses.newkeys->trans.zstream, Z_DEFAULT_COMPRESSION,
					Z_DEFLATED, DROPBEAR_ZLIB_WINDOW_BITS,
					DROPBEAR_ZLIB_MEM_LEVEL, Z_DEFAULT_STRATEGY)
				!= Z_OK) {
			dropbear_exit("zlib error");
		}
	} else {
		ses.newkeys->trans.zstream = NULL;
	}

	/* clean up old keys */
	if (ses.keys->recv.zstream != NULL) {
		if (inflateEnd(ses.keys->recv.zstream) == Z_STREAM_ERROR) {
			/* Z_DATA_ERROR is ok, just means that stream isn't ended */
			dropbear_exit("Crypto error");
		}
		m_free(ses.keys->recv.zstream);
	}
	if (ses.keys->trans.zstream != NULL) {
		if (deflateEnd(ses.keys->trans.zstream) == Z_STREAM_ERROR) {
			/* Z_DATA_ERROR is ok, just means that stream isn't ended */
			dropbear_exit("Crypto error");
		}
		m_free(ses.keys->trans.zstream);
	}
}
#endif /* DISABLE_ZLIB */


/* Executed upon receiving a kexinit message from the client to initiate
 * key exchange. If we haven't already done so, we send the list of our
 * preferred algorithms. The client's requested algorithms are processed,
 * and we calculate the first portion of the key-exchange-hash for used
 * later in the key exchange. No response is sent, as the client should
 * initiate the diffie-hellman key exchange */

/* Originally from kex.c, generalized for cli/svr mode --mihnea  */
/* Belongs in common_kex.c where it should be moved after review */
static void recv_msg_kexinit() {

	unsigned int kexhashbuf_len = 0;
	unsigned int remote_ident_len = 0;
	unsigned int local_ident_len = 0;

	if (!ses.kexstate.sentkexinit) {
		/* we need to send a kex packet */
		send_msg_kexinit();
	}

	/* start the kex hash */
	local_ident_len = strlen(LOCAL_IDENT);
	remote_ident_len = strlen(ses.remoteident);

	kexhashbuf_len = local_ident_len + remote_ident_len
		+ ses.transkexinit->len + ses.payload->len
		+ KEXHASHBUF_MAX_INTS;

	ses.kexhashbuf = buf_new(kexhashbuf_len);

	/* read the peer's choice of algos */
	read_kex_algos();

	/* V_C, the client's version string (CR and NL excluded) */
	buf_putstring(ses.kexhashbuf, LOCAL_IDENT, local_ident_len);
	/* V_S, the server's version string (CR and NL excluded) */
	buf_putstring(ses.kexhashbuf, ses.remoteident, remote_ident_len);

	/* I_C, the payload of the client's SSH_MSG_KEXINIT */
	buf_putstring(ses.kexhashbuf, (char *)ses.transkexinit->data, ses.transkexinit->len);
	/* I_S, the payload of the server's SSH_MSG_KEXINIT */
	buf_setpos(ses.payload, 0);
	buf_putstring(ses.kexhashbuf, (char *)ses.payload->data, ses.payload->len);


	buf_free(ses.transkexinit);
	ses.transkexinit = NULL;
	/* the rest of ses.kexhashbuf will be done after DH exchange */

	ses.kexstate.recvkexinit = 1;
}

static void load_dh_p(mp_int * dh_p)
{
	switch (ses.newkeys->algo_kex) {
		case DROPBEAR_KEX_DH_GROUP1:
			bytes_to_mp(dh_p, dh_p_1, DH_P_1_LEN);
			break;
		case DROPBEAR_KEX_DH_GROUP14:
			bytes_to_mp(dh_p, dh_p_14, DH_P_14_LEN);
			break;
	}
}


/* Generates a random mp_int.
 * max is a *mp_int specifying an upper bound.
 * rand must be an initialised *mp_int for the result.
 * the result rand satisfies:  0 < rand < max
 * */
static void gen_random_mpint(mp_int *max, mp_int *rand) {

	unsigned char *randbuf = NULL;
	unsigned int len = 0;
	const unsigned char masks[] = {0xff, 0x01, 0x03, 0x07, 0x0f, 0x1f, 0x3f, 0x7f};

	const int size_bits = mp_count_bits(max);

	len = size_bits / 8;
	if ((size_bits % 8) != 0) {
		len += 1;
	}

	randbuf = (unsigned char*)m_malloc(len);
	do {
		genrandom(randbuf, len);
		/* Mask out the unrequired bits - mp_read_unsigned_bin expects
		 * MSB first.*/
		randbuf[0] &= masks[size_bits % 8];

		bytes_to_mp(rand, randbuf, len);

		/* keep regenerating until we get one satisfying
		 * 0 < rand < max    */
	} while (mp_cmp(rand, max) != MP_LT);
	m_burn(randbuf, len);
	m_free(randbuf);
}

/* Initialises and generate one side of the diffie-hellman key exchange values.
 * See the transport rfc 4253 section 8 for details */
/* dh_pub and dh_priv MUST be already initialised */
static void gen_kexdh_vals(mp_int *dh_pub, mp_int *dh_priv) {

	DEF_MP_INT(dh_p);
	DEF_MP_INT(dh_q);
	DEF_MP_INT(dh_g);

	m_mp_init_multi(&dh_g, &dh_p, &dh_q, NULL);

	/* read the prime and generator*/
	load_dh_p(&dh_p);

	if (mp_set_int(&dh_g, DH_G_VAL) != MP_OKAY)
		dropbear_exit("Diffie-Hellman error");

	/* calculate q = (p-1)/2 */
	/* dh_priv is just a temp var here */
	if (mp_sub_d(&dh_p, 1, dh_priv) != MP_OKAY)
		dropbear_exit("Diffie-Hellman error");
	if (mp_div_2(dh_priv, &dh_q) != MP_OKAY)
		dropbear_exit("Diffie-Hellman error");

	/* Generate a private portion 0 < dh_priv < dh_q */
	gen_random_mpint(&dh_q, dh_priv);

	/* f = g^y mod p */
	if (mp_exptmod(&dh_g, dh_priv, &dh_p, dh_pub) != MP_OKAY)
		dropbear_exit("Diffie-Hellman error");
	mp_clear_multi(&dh_g, &dh_p, &dh_q, NULL);
}

/* This function is fairly common between client/server, with some substitution
 * of dh_e/dh_f etc. Hence these arguments:
 * dh_pub_us is 'e' for the client, 'f' for the server. dh_pub_them is
 * vice-versa. dh_priv is the x/y value corresponding to dh_pub_us */
static void kexdh_comb_key(mp_int *dh_pub_us, mp_int *dh_priv, mp_int *dh_pub_them,
		sign_key *hostkey) {

	mp_int dh_p;
	mp_int *dh_e = NULL, *dh_f = NULL;
	hash_state hs;

	/* read the prime and generator*/
	m_mp_init(&dh_p);
	load_dh_p(&dh_p);

	/* Check that dh_pub_them (dh_e or dh_f) is in the range [1, p-1] */
	if (mp_cmp(dh_pub_them, &dh_p) != MP_LT
			|| mp_cmp_d(dh_pub_them, 0) != MP_GT) {
		dropbear_exit("Diffie-Hellman error");
	}

	/* K = e^y mod p = f^x mod p */
	ses.dh_K = (mp_int*)m_malloc(sizeof(mp_int));
	m_mp_init(ses.dh_K);
	if (mp_exptmod(dh_pub_them, dh_priv, &dh_p, ses.dh_K) != MP_OKAY)
		dropbear_exit("Diffie-Hellman error");

	/* clear no longer needed vars */
	mp_clear_multi(&dh_p, NULL);

	/* From here on, the code needs to work with the _same_ vars on each side,
	 * not vice-versaing for client/server */
	dh_e = dh_pub_us;
	dh_f = dh_pub_them;

	/* Create the remainder of the hash buffer, to generate the exchange hash */
	/* K_S, the host key */
	buf_put_pub_key(ses.kexhashbuf, hostkey, ses.newkeys->algo_hostkey);
	/* e, exchange value sent by the client */
	buf_putmpint(ses.kexhashbuf, dh_e);
	/* f, exchange value sent by the server */
	buf_putmpint(ses.kexhashbuf, dh_f);
	/* K, the shared secret */
	buf_putmpint(ses.kexhashbuf, ses.dh_K);

	/* calculate the hash H to sign */
	sha1_init(&hs);
	buf_setpos(ses.kexhashbuf, 0);
	sha1_process(&hs, buf_getptr(ses.kexhashbuf, ses.kexhashbuf->len),
			ses.kexhashbuf->len);
	sha1_done(&hs, ses.hash);

	buf_burn(ses.kexhashbuf);
	buf_free(ses.kexhashbuf);
	ses.kexhashbuf = NULL;

	/* first time around, we set the session_id to H */
	if (ses.session_id == NULL) {
		/* create the session_id, this never needs freeing */
		ses.session_id = m_malloc(SHA1_HASH_SIZE);
		memcpy(ses.session_id, ses.hash, SHA1_HASH_SIZE);
	}
}

/* read the other side's algo list. buf_match_algo is a callback to match
 * algos for the client or server. */
static void read_kex_algos() {

	/* for asymmetry */
	algo_type * c2s_hash_algo = NULL;
	algo_type * s2c_hash_algo = NULL;
	algo_type * c2s_cipher_algo = NULL;
	algo_type * s2c_cipher_algo = NULL;
	algo_type * c2s_comp_algo = NULL;
	algo_type * s2c_comp_algo = NULL;
	/* the generic one */
	algo_type * algo = NULL;

	/* which algo couldn't match */
	char * erralgo = NULL;

	int goodguess = 0;
	int allgood = 1; /* we AND this with each goodguess and see if its still
						true after */

	buf_incrpos(ses.payload, 16); /* start after the cookie */

	ses.newkeys = (struct key_context*)m_malloc(sizeof(struct key_context));

	/* kex_algorithms */
	algo = ses.buf_match_algo(ses.payload, sshkex, &goodguess);
	allgood &= goodguess;
	if (algo == NULL) {
		erralgo = "kex";
		goto error;
	}
	ses.newkeys->algo_kex = algo->val;

	/* server_host_key_algorithms */
	algo = ses.buf_match_algo(ses.payload, sshhostkey, &goodguess);
	allgood &= goodguess;
	if (algo == NULL) {
		erralgo = "hostkey";
		goto error;
	}
	ses.newkeys->algo_hostkey = algo->val;

	/* encryption_algorithms_client_to_server */
	c2s_cipher_algo = ses.buf_match_algo(ses.payload, sshciphers, &goodguess);
	if (c2s_cipher_algo == NULL) {
		erralgo = "enc c->s";
		goto error;
	}
	/* encryption_algorithms_server_to_client */
	s2c_cipher_algo = ses.buf_match_algo(ses.payload, sshciphers, &goodguess);
	if (s2c_cipher_algo == NULL) {
		erralgo = "enc s->c";
		goto error;
	}
	/* mac_algorithms_client_to_server */
	c2s_hash_algo = ses.buf_match_algo(ses.payload, sshhashes, &goodguess);
	if (c2s_hash_algo == NULL) {
		erralgo = "mac c->s";
		goto error;
	}
	/* mac_algorithms_server_to_client */
	s2c_hash_algo = ses.buf_match_algo(ses.payload, sshhashes, &goodguess);
	if (s2c_hash_algo == NULL) {
		erralgo = "mac s->c";
		goto error;
	}
	/* compression_algorithms_client_to_server */
	c2s_comp_algo = ses.buf_match_algo(ses.payload, ses.compress_algos, &goodguess);
	if (c2s_comp_algo == NULL) {
		erralgo = "comp c->s";
		goto error;
	}
	/* compression_algorithms_server_to_client */
	s2c_comp_algo = ses.buf_match_algo(ses.payload, ses.compress_algos, &goodguess);
	if (s2c_comp_algo == NULL) {
		erralgo = "comp s->c";
		goto error;
	}
	/* languages_client_to_server */
	buf_eatstring(ses.payload);

	/* languages_server_to_client */
	buf_eatstring(ses.payload);

	/* first_kex_packet_follows */
	if (buf_getbool(ses.payload)) {
		ses.kexstate.firstfollows = 1;
		/* if the guess wasn't good, we ignore the packet sent */
		if (!allgood) {
			ses.ignorenext = 1;
		}
	}

	/* Handle the asymmetry */
	ses.newkeys->recv.algo_crypt =
			(struct dropbear_cipher*)s2c_cipher_algo->data;
	ses.newkeys->trans.algo_crypt =
			(struct dropbear_cipher*)c2s_cipher_algo->data;
	ses.newkeys->recv.crypt_mode =
			(struct dropbear_cipher_mode*)s2c_cipher_algo->mode;
	ses.newkeys->trans.crypt_mode =
			(struct dropbear_cipher_mode*)c2s_cipher_algo->mode;
	ses.newkeys->recv.algo_mac =
			(struct dropbear_hash*)s2c_hash_algo->data;
	ses.newkeys->trans.algo_mac =
			(struct dropbear_hash*)c2s_hash_algo->data;
	ses.newkeys->recv.algo_comp = s2c_comp_algo->val;
	ses.newkeys->trans.algo_comp = c2s_comp_algo->val;

	/* reserved for future extensions */
	buf_getint(ses.payload);
	return;

error:
	dropbear_exit("No matching algo %s", erralgo);
}

static int isempty(struct Queue* queue) {

	return (queue->head == NULL);
}



#ifdef DROPBEAR_DSS

#define DSS_SIGNATURE_SIZE 4+SSH_SIGNKEY_DSS_LEN+4+2*SHA1_HASH_SIZE


static void buf_put_dss_sign(buffer* buf, dropbear_dss_key *key, const unsigned char* data,
		unsigned int len);
static void buf_put_dss_pub_key(buffer* buf, dropbear_dss_key *key);
static void dss_key_free(dropbear_dss_key *key);

#endif /* DROPBEAR_DSS */

static long select_timeout();




/* called only at the start of a session, set up initial state */
static void common_session_init(int sock_in, int sock_out) {

	ses.sock_in = sock_in;
	ses.sock_out = sock_out;
	ses.maxfd = MAX(sock_in, sock_out);

	ses.connect_time = 0;
	ses.last_trx_packet_time = 0;
	ses.last_packet_time = 0;

	if (pipe(ses.signal_pipe) < 0)
		dropbear_exit("Signal pipe failed");
	setnonblocking(ses.signal_pipe[0]);
	setnonblocking(ses.signal_pipe[1]);

	ses.maxfd = MAX(ses.maxfd, ses.signal_pipe[0]);
	ses.maxfd = MAX(ses.maxfd, ses.signal_pipe[1]);

	kexfirstinitialise(); /* initialise the kex state */

	ses.writepayload = buf_new(TRANS_MAX_PAYLOAD_LEN);
	ses.transseq = 0;

	ses.readbuf = NULL;
	ses.payload = NULL;
	ses.recvseq = 0;

	initqueue(&ses.writequeue);

	ses.requirenext = SSH_MSG_KEXINIT;
	ses.dataallowed = 1; /* we can send data until we actually
							send the SSH_MSG_KEXINIT */
	ses.ignorenext = 0;
	ses.lastpacket = 0;
	ses.reply_queue_head = NULL;
	ses.reply_queue_tail = NULL;

	/* set all the algos to none */
	ses.keys = (struct key_context*)m_malloc(sizeof(struct key_context));
	ses.newkeys = NULL;
	ses.keys->recv.algo_crypt = &dropbear_nocipher;
	ses.keys->trans.algo_crypt = &dropbear_nocipher;
	ses.keys->recv.crypt_mode = &dropbear_mode_none;
	ses.keys->trans.crypt_mode = &dropbear_mode_none;

	ses.keys->recv.algo_mac = &dropbear_nohash;
	ses.keys->trans.algo_mac = &dropbear_nohash;

	ses.keys->algo_kex = -1;
	ses.keys->algo_hostkey = -1;
	ses.keys->recv.algo_comp = DROPBEAR_COMP_NONE;
	ses.keys->trans.algo_comp = DROPBEAR_COMP_NONE;

#ifndef DISABLE_ZLIB
	ses.keys->recv.zstream = NULL;
	ses.keys->trans.zstream = NULL;
#endif

	/* key exchange buffers */
	ses.session_id = NULL;
	ses.kexhashbuf = NULL;
	ses.transkexinit = NULL;
	ses.dh_K = NULL;
	ses.remoteident = NULL;

	ses.chantypes = NULL;

	ses.allowprivport = 0;
}

static void session_loop(void(*loophandler)()) {

	fd_set readfd, writefd;
	struct timeval timeout;
	int val;

	/* main loop, select()s for all sockets in use */
	for(;;) {

		timeout.tv_sec = select_timeout();
		timeout.tv_usec = 0;
		FD_ZERO(&writefd);
		FD_ZERO(&readfd);
		dropbear_assert(ses.payload == NULL);
		if (ses.sock_in != -1) {
			FD_SET(ses.sock_in, &readfd);
		}
		if (ses.sock_out != -1 && !isempty(&ses.writequeue)) {
			FD_SET(ses.sock_out, &writefd);
		}

		/* We get woken up when signal handlers write to this pipe.
		   SIGCHLD in svr-chansession is the only one currently. */
		FD_SET(ses.signal_pipe[0], &readfd);

		/* set up for channels which require reading/writing */
		if (ses.dataallowed) {
			setchannelfds(&readfd, &writefd);
		}
		val = select(ses.maxfd+1, &readfd, &writefd, NULL, &timeout);

		if (val < 0 && errno != EINTR)
			dropbear_exit("Error in select");

		if (val <= 0) {
			/* If we were interrupted or the select timed out, we still
			 * want to iterate over channels etc for reading, to handle
			 * server processes exiting etc.
			 * We don't want to read/write FDs. */
			FD_ZERO(&writefd);
			FD_ZERO(&readfd);
		}

		/* We'll just empty out the pipe if required. We don't do
		any thing with the data, since the pipe's purpose is purely to
		wake up the select() above. */
		if (FD_ISSET(ses.signal_pipe[0], &readfd)) {
			char x;
			while (read(ses.signal_pipe[0], &x, 1) > 0) {}
		}

		/* check for auth timeout, rekeying required etc */
		checktimeouts();

		/* process session socket's incoming/outgoing data */
		if (ses.sock_out != -1) {
			if (FD_ISSET(ses.sock_out, &writefd) && !isempty(&ses.writequeue)) {
				write_packet();
			}
		}

		if (ses.sock_in != -1) {
			if (FD_ISSET(ses.sock_in, &readfd)) {
				read_packet();
			}

			/* Process the decrypted packet. After this, the read buffer
			 * will be ready for a new packet */
			if (ses.payload != NULL) {
				process_packet();
			}
		}

		/* if required, flush out any queued reply packets that
		were being held up during a KEX */
		maybe_flush_reply_queue();

		/* process pipes etc for the channels, ses.dataallowed == 0
		 * during rekeying ) */
		if (ses.dataallowed) {
			channelio(&readfd, &writefd);
		}

		if (loophandler) {
			loophandler();
		}

	} /* for(;;) */

	/* Not reached */
}

static long select_timeout() {
	/* determine the minimum timeout that might be required, so
	as to avoid waking when unneccessary */
	long ret = LONG_MAX;
	if (KEX_REKEY_TIMEOUT > 0)
		ret = MIN(KEX_REKEY_TIMEOUT, ret);
	if (AUTH_TIMEOUT > 0)
		ret = MIN(AUTH_TIMEOUT, ret);
	if (opts.keepalive_secs > 0)
		ret = MIN(opts.keepalive_secs, ret);
    if (opts.idle_timeout_secs > 0)
	ret = MIN(opts.idle_timeout_secs, ret);
	return ret;
}

#define MAX_FMT 100

static void cli_dropbear_exit(int exitcode, const char* format, va_list param) ATTRIB_NORETURN;

/* the "format" string must be <= 100 characters */
static void dropbear_close(const char* format, ...)
{
	va_list param;

	va_start(param, format);
	cli_dropbear_exit(EXIT_SUCCESS, format, param);
	va_end(param);
}

static void dropbear_exit(const char* format, ...)
{
	va_list param;

	va_start(param, format);
	cli_dropbear_exit(EXIT_FAILURE, format, param);
	va_end(param);
}

static void cli_dropbear_log(const char* format, va_list param) {

	char printbuf[1024];

	vsnprintf(printbuf, sizeof(printbuf), format, param);

	fprintf(stderr, "%s: %s\n", cli_opts.progname, printbuf);

}

/* this is what can be called to write arbitrary log messages */
static void dropbear_log(const char* format, ...) {

	va_list param;

	va_start(param, format);
	cli_dropbear_log(format, param);
	va_end(param);
}


static void set_sock_priority(int sock) {

	int val;

	/* disable nagle */
	val = 1;
	setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (void*)&val, sizeof(val));

	/* set the TOS bit for either ipv4 or ipv6 */
#ifdef IPTOS_LOWDELAY
	val = IPTOS_LOWDELAY;
#if defined(IPPROTO_IPV6) && defined(IPV6_TCLASS)
	setsockopt(sock, IPPROTO_IPV6, IPV6_TCLASS, (void*)&val, sizeof(val));
#endif
	setsockopt(sock, IPPROTO_IP, IP_TOS, (void*)&val, sizeof(val));
#endif

#ifdef SO_PRIORITY
	/* linux specific, sets QoS class.
	 * 6 looks to be optimal for interactive traffic (see tc-prio(8) ). */
	val = 6;
	setsockopt(sock, SOL_SOCKET, SO_PRIORITY, (void*) &val, sizeof(val));
#endif

}

/* Listen on address:port.
 * Special cases are address of "" listening on everything,
 * and address of NULL listening on localhost only.
 * Returns the number of sockets bound on success, or -1 on failure. On
 * failure, if errstring wasn't NULL, it'll be a newly malloced error
 * string.*/
static int dropbear_listen(const char* address, const char* port,
		int *socks, unsigned int sockcount, char **errstring, int *maxfd) {

	struct addrinfo hints, *res = NULL, *res0 = NULL;
	int err;
	unsigned int nsock;
	struct linger linger;
	int val;
	int sock;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC; /* TODO: let them flag v4 only etc */
	hints.ai_socktype = SOCK_STREAM;

	/* for calling getaddrinfo:
	 address == NULL and !AI_PASSIVE: local loopback
	 address == NULL and AI_PASSIVE: all interfaces
	 address != NULL: whatever the address says */
	if (!address) {
		;
	} else {
		if (address[0] == '\0')
			address = NULL;
		hints.ai_flags = AI_PASSIVE;
	}
	err = getaddrinfo(address, port, &hints, &res0);

	if (err) {
		if (errstring != NULL && *errstring == NULL) {
			int len;
			len = 20 + strlen(gai_strerror(err));
			*errstring = (char*)m_malloc(len);
			snprintf(*errstring, len, "Error resolving: %s", gai_strerror(err));
		}
		if (res0) {
			freeaddrinfo(res0);
			res0 = NULL;
		}
		return -1;
	}


	nsock = 0;
	for (res = res0; res != NULL && nsock < sockcount;
			res = res->ai_next) {

		/* Get a socket */
		socks[nsock] = socket(res->ai_family, res->ai_socktype,
				res->ai_protocol);

		sock = socks[nsock]; /* For clarity */

		if (sock < 0) {
			err = errno;
			continue;
		}

		/* Various useful socket options */
		val = 1;
		/* set to reuse, quick timeout */
		setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (void*) &val, sizeof(val));
		linger.l_onoff = 1;
		linger.l_linger = 5;
		setsockopt(sock, SOL_SOCKET, SO_LINGER, (void*)&linger, sizeof(linger));

#if defined(IPPROTO_IPV6) && defined(IPV6_V6ONLY)
		if (res->ai_family == AF_INET6) {
			int on = 1;
			if (setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY,
						&on, sizeof(on)) == -1) {
				dropbear_log("Couldn't set IPV6_V6ONLY");
			}
		}
#endif

		set_sock_priority(sock);

		if (bind(sock, res->ai_addr, res->ai_addrlen) < 0) {
			err = errno;
			close(sock);
			continue;
		}

		if (listen(sock, 20) < 0) {
			err = errno;
			close(sock);
			continue;
		}

		*maxfd = MAX(*maxfd, sock);

		nsock++;
	}

	if (res0) {
		freeaddrinfo(res0);
		res0 = NULL;
	}

	if (nsock == 0) {
		if (errstring != NULL && *errstring == NULL) {
			int len;
			len = 20 + strlen(strerror(err));
			*errstring = (char*)m_malloc(len);
			snprintf(*errstring, len, "Error listening: %s", strerror(err));
		}
		return -1;
	}
	return nsock;
}

/* Connect to a given unix socket. The socket is blocking */
#ifdef ENABLE_CONNECT_UNIX
static int connect_unix(const char* path) {
	struct sockaddr_un addr;
	int fd = -1;

	memset((void*)&addr, 0x0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, path, sizeof(addr.sun_path)-1);
	addr.sun_path[sizeof(addr.sun_path)-1]=0;
	fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (fd < 0)
		return -1;
	if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		m_close(fd);
		return -1;
	}
	return fd;
}
#endif

/* Connect via TCP to a host. Connection will try ipv4 or ipv6, will
 * return immediately if nonblocking is set. On failure, if errstring
 * wasn't null, it will be a newly malloced error message */

/* TODO: maxfd */
static int connect_remote(const char* remotehost, const char* remoteport,
		int nonblocking, char ** errstring) {

	struct addrinfo *res0 = NULL, *res = NULL, hints;
	int sock;
	int err;

	if (errstring != NULL)
		*errstring = NULL;

	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_family = PF_UNSPEC;

	err = getaddrinfo(remotehost, remoteport, &hints, &res0);
	if (err) {
		if (errstring != NULL && *errstring == NULL) {
			int len;
			len = 100 + strlen(gai_strerror(err));
			*errstring = (char*)m_malloc(len);
			snprintf(*errstring, len, "Error resolving '%s' port '%s'. %s",
					remotehost, remoteport, gai_strerror(err));
		}
		return -1;
	}

	sock = -1;
	err = EADDRNOTAVAIL;
	for (res = res0; res; res = res->ai_next) {

		sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (sock < 0) {
			err = errno;
			continue;
		}

		if (nonblocking) {
			setnonblocking(sock);
		}

		if (connect(sock, res->ai_addr, res->ai_addrlen) < 0) {
			if (errno == EINPROGRESS && nonblocking) {
				break;
			} else {
				err = errno;
				close(sock);
				sock = -1;
				continue;
			}
		}

		break; /* Success */
	}

	if (sock < 0 && !(errno == EINPROGRESS && nonblocking)) {
		/* Failed */
		if (errstring != NULL && *errstring == NULL) {
			int len;
			len = 20 + strlen(strerror(err));
			*errstring = (char*)m_malloc(len);
			snprintf(*errstring, len, "Error connecting: %s", strerror(err));
		}
	} else {
		/* Success */
		set_sock_priority(sock);
	}

	freeaddrinfo(res0);
	if (sock > 0 && errstring != NULL && *errstring != NULL) {
		m_free(*errstring);
	}

	return sock;
}

/* reads the contents of filename into the buffer buf, from the current
 * position, either to the end of the file, or the buffer being full.
 * Returns DROPBEAR_SUCCESS or DROPBEAR_FAILURE */
static int buf_readfile(buffer* buf, const char* filename) {

	int fd = -1;
	int len;
	int maxlen;
	int ret = DROPBEAR_FAILURE;

	fd = open(filename, O_RDONLY);

	if (fd < 0) {
		goto out;
	}

	do {
		maxlen = buf->size - buf->pos;
		len = read(fd, buf_getwriteptr(buf, maxlen), maxlen);
		if (len < 0) {
			if (errno == EINTR || errno == EAGAIN) {
				continue;
			}
			goto out;
		}
		buf_incrwritepos(buf, len);
	} while (len < maxlen && len > 0);

	ret = DROPBEAR_SUCCESS;

out:
	if (fd >= 0) {
		m_close(fd);
	}
	return ret;
}

/* get a line from the file into buffer in the style expected for an
 * authkeys file.
 * Will return DROPBEAR_SUCCESS if data is read, or DROPBEAR_FAILURE on EOF.*/
/* Only used for ~/.ssh/known_hosts and ~/.ssh/authorized_keys */
static int buf_getline(buffer * line, FILE * authfile) {

	int c = EOF;

	buf_setpos(line, 0);
	buf_setlen(line, 0);

	while (line->pos < line->size) {

		c = fgetc(authfile); /*getc() is weird with some uClibc systems*/
		if (c == EOF || c == '\n' || c == '\r') {
			goto out;
		}

		buf_putbyte(line, (unsigned char)c);
	}

	/* We return success, but the line length will be zeroed - ie we just
	 * ignore that line */
	buf_setlen(line, 0);

out:


	/* if we didn't read anything before EOF or error, exit */
	if (c == EOF && line->pos == 0) {
		return DROPBEAR_FAILURE;
	} else {
		buf_setpos(line, 0);
		return DROPBEAR_SUCCESS;
	}

}

/* make sure that the socket closes */
static void m_close(int fd) {

	int val;
	do {
		val = close(fd);
	} while (val < 0 && errno == EINTR);

	if (val < 0 && errno != EBADF) {
		/* Linux says EIO can happen */
		dropbear_exit("Error closing fd %d, %s", fd, strerror(errno));
	}
}

static void * m_strdup(const char * str) {
	char* ret;

	ret = strdup(str);
	if (ret == NULL)
		dropbear_exit("m_strdup failed");
	return ret;
}


static void setnonblocking(int fd) {

	if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0) {
		if (errno == ENODEV) {
			/* Some devices (like /dev/null redirected in)
			 * can't be set to non-blocking */
		} else {
			dropbear_exit("Couldn't set nonblocking");
		}
	}
}

static void disallow_core() {
	struct rlimit lim;
	lim.rlim_cur = lim.rlim_max = 0;
	setrlimit(RLIMIT_CORE, &lim);
}

/* Returns DROPBEAR_SUCCESS or DROPBEAR_FAILURE, with the result in *val */
static int m_str_to_uint(const char* str, unsigned int *val) {
	errno = 0;
	*val = strtoul(str, NULL, 10);
	/* The c99 spec doesn't actually seem to define EINVAL, but most platforms
	 * I've looked at mention it in their manpage */
	if ((*val == 0 && errno == EINVAL)
		|| (*val == ULONG_MAX && errno == ERANGE)) {
		return DROPBEAR_FAILURE;
	} else {
		return DROPBEAR_SUCCESS;
	}
}

/* Handle DSS (Digital Signature Standard), aka DSA (D.S. Algorithm),
 * operations, such as key reading, signing, verification. Key generation
 * is in gendss.c, since it isn't required in the server itself.
 *
 * See FIPS186 or the Handbook of Applied Cryptography for details of the
 * algorithm */

#ifdef DROPBEAR_DSS

/* Load a dss key from a buffer, initialising the values.
 * The key will have the same format as buf_put_dss_key.
 * These should be freed with dss_key_free.
 * Returns DROPBEAR_SUCCESS or DROPBEAR_FAILURE */
static int buf_get_dss_pub_key(buffer* buf, dropbear_dss_key *key) {

	dropbear_assert(key != NULL);
	key->p = m_malloc(sizeof(mp_int));
	key->q = m_malloc(sizeof(mp_int));
	key->g = m_malloc(sizeof(mp_int));
	key->y = m_malloc(sizeof(mp_int));
	m_mp_init_multi(key->p, key->q, key->g, key->y, NULL);
	key->x = NULL;

	buf_incrpos(buf, 4+SSH_SIGNKEY_DSS_LEN); /* int + "ssh-dss" */
	if (buf_getmpint(buf, key->p) == DROPBEAR_FAILURE
	 || buf_getmpint(buf, key->q) == DROPBEAR_FAILURE
	 || buf_getmpint(buf, key->g) == DROPBEAR_FAILURE
	 || buf_getmpint(buf, key->y) == DROPBEAR_FAILURE) {
		return DROPBEAR_FAILURE;
	}

	if (mp_count_bits(key->p) < MIN_DSS_KEYLEN) {
		dropbear_log("DSS key too short");
		return DROPBEAR_FAILURE;
	}

	return DROPBEAR_SUCCESS;
}

/* Same as buf_get_dss_pub_key, but reads a private "x" key at the end.
 * Loads a private dss key from a buffer
 * Returns DROPBEAR_SUCCESS or DROPBEAR_FAILURE */
static int buf_get_dss_priv_key(buffer* buf, dropbear_dss_key *key) {

	int ret = DROPBEAR_FAILURE;

	dropbear_assert(key != NULL);

	ret = buf_get_dss_pub_key(buf, key);
	if (ret == DROPBEAR_FAILURE) {
		return DROPBEAR_FAILURE;
	}

	key->x = m_malloc(sizeof(mp_int));
	m_mp_init(key->x);
	ret = buf_getmpint(buf, key->x);
	if (ret == DROPBEAR_FAILURE) {
		m_free(key->x);
	}

	return ret;
}


/* Clear and free the memory used by a public or private key */
static void dss_key_free(dropbear_dss_key *key) {

	if (key == NULL)
		return;
	if (key->p) {
		mp_clear(key->p);
		m_free(key->p);
	}
	if (key->q) {
		mp_clear(key->q);
		m_free(key->q);
	}
	if (key->g) {
		mp_clear(key->g);
		m_free(key->g);
	}
	if (key->y) {
		mp_clear(key->y);
		m_free(key->y);
	}
	if (key->x) {
		mp_clear(key->x);
		m_free(key->x);
	}
	m_free(key);
}

/* put the dss public key into the buffer in the required format:
 *
 * string       "ssh-dss"
 * mpint        p
 * mpint        q
 * mpint        g
 * mpint        y
 */
static void buf_put_dss_pub_key(buffer* buf, dropbear_dss_key *key) {

	dropbear_assert(key != NULL);
	buf_putstring(buf, SSH_SIGNKEY_DSS, SSH_SIGNKEY_DSS_LEN);
	buf_putmpint(buf, key->p);
	buf_putmpint(buf, key->q);
	buf_putmpint(buf, key->g);
	buf_putmpint(buf, key->y);

}

/* Verify a DSS signature (in buf) made on data by the key given.
 * returns DROPBEAR_SUCCESS or DROPBEAR_FAILURE */
static int buf_dss_verify(buffer* buf, dropbear_dss_key *key, const unsigned char* data,
		unsigned int len) {

	unsigned char msghash[SHA1_HASH_SIZE];
	hash_state hs;
	int ret = DROPBEAR_FAILURE;
	DEF_MP_INT(val1);
	DEF_MP_INT(val2);
	DEF_MP_INT(val3);
	DEF_MP_INT(val4);
	char * string = NULL;
	unsigned int stringlen;

	dropbear_assert(key != NULL);

	m_mp_init_multi(&val1, &val2, &val3, &val4, NULL);

	/* get blob, check length */
	string = buf_getstring(buf, &stringlen);
	if (stringlen != 2*SHA1_HASH_SIZE)
		goto out;

	/* hash the data */
	sha1_init(&hs);
	sha1_process(&hs, data, len);
	sha1_done(&hs, msghash);

	/* create the signature - s' and r' are the received signatures in buf */
	/* w = (s')-1 mod q */
	/* let val1 = s' */
	bytes_to_mp(&val1, (unsigned char *)&string[SHA1_HASH_SIZE], SHA1_HASH_SIZE);

	if (mp_cmp(&val1, key->q) != MP_LT)
		goto out;
	/* let val2 = w = (s')^-1 mod q*/
	if (mp_invmod(&val1, key->q, &val2) != MP_OKAY) {
		goto out;
	}

	/* u1 = ((SHA(M')w) mod q */
	/* let val1 = SHA(M') = msghash */
	bytes_to_mp(&val1, msghash, SHA1_HASH_SIZE);

	/* let val3 = u1 = ((SHA(M')w) mod q */
	if (mp_mulmod(&val1, &val2, key->q, &val3) != MP_OKAY) {
		goto out;
	}

	/* u2 = ((r')w) mod q */
	/* let val1 = r' */
	bytes_to_mp(&val1, (unsigned char *)&string[0], SHA1_HASH_SIZE);
	if (mp_cmp(&val1, key->q) != MP_LT)
		goto out;
	/* let val4 = u2 = ((r')w) mod q */
	if (mp_mulmod(&val1, &val2, key->q, &val4) != MP_OKAY) {
		goto out;
	}

	/* v = (((g)^u1 (y)^u2) mod p) mod q */
	/* val2 = g^u1 mod p */
	if (mp_exptmod(key->g, &val3, key->p, &val2) != MP_OKAY) {
		goto out;
	}
	/* val3 = y^u2 mod p */
	if (mp_exptmod(key->y, &val4, key->p, &val3) != MP_OKAY) {
		goto out;
	}
	/* val4 = ((g)^u1 (y)^u2) mod p */
	if (mp_mulmod(&val2, &val3, key->p, &val4) != MP_OKAY) {
		goto out;
	}
	/* val2 = v = (((g)^u1 (y)^u2) mod p) mod q */
	if (mp_mod(&val4, key->q, &val2) != MP_OKAY) {
		goto out;
	}

	/* check whether signatures verify */
	if (mp_cmp(&val2, &val1) == MP_EQ) {
		/* good sig */
		ret = DROPBEAR_SUCCESS;
	}

out:
	mp_clear_multi(&val1, &val2, &val3, &val4, NULL);
	m_free(string);

	return ret;

}

#ifdef DSS_PROTOK
/* convert an unsigned mp into an array of bytes, malloced.
 * This array must be freed after use, len contains the length of the array,
 * if len != NULL */
static unsigned char* mptobytes(mp_int *mp, int *len) {

	unsigned char* ret;
	int size;

	size = mp_unsigned_bin_size(mp);
	ret = m_malloc(size);
	if (mp_to_unsigned_bin(mp, ret) != MP_OKAY)
		dropbear_exit("Mem alloc error");
	if (len != NULL)
		*len = size;
	return ret;
}
#endif

/* Sign the data presented with key, writing the signature contents
 * to the buffer
 *
 * When DSS_PROTOK is #defined:
 * The alternate k generation method is based on the method used in PuTTY.
 * In particular to avoid being vulnerable to attacks using flaws in random
 * generation of k, we use the following:
 *
 * proto_k = SHA512 ( SHA512(x) || SHA160(message) )
 * k = proto_k mod q
 *
 * Now we aren't relying on the random number generation to protect the private
 * key x, which is a long term secret */
static void buf_put_dss_sign(buffer* buf, dropbear_dss_key *key,
				const unsigned char* data,
				unsigned int len) {

	unsigned char msghash[SHA1_HASH_SIZE];
	unsigned int writelen;
	unsigned int i;
#ifdef DSS_PROTOK
	unsigned char privkeyhash[SHA512_HASH_SIZE];
	unsigned char *privkeytmp;
	unsigned char proto_k[SHA512_HASH_SIZE];
	DEF_MP_INT(dss_protok);
#endif
	DEF_MP_INT(dss_k);
	DEF_MP_INT(dss_m);
	DEF_MP_INT(dss_temp1);
	DEF_MP_INT(dss_temp2);
	DEF_MP_INT(dss_r);
	DEF_MP_INT(dss_s);
	hash_state hs;

	dropbear_assert(key != NULL);

	/* hash the data */
	sha1_init(&hs);
	sha1_process(&hs, data, len);
	sha1_done(&hs, msghash);

	m_mp_init_multi(&dss_k, &dss_temp1, &dss_temp2, &dss_r, &dss_s,
			&dss_m, NULL);
#ifdef DSS_PROTOK
	/* hash the privkey */
	privkeytmp = mptobytes(key->x, &i);
	sha512_init(&hs);
	sha512_process(&hs, "the quick brown fox jumped over the lazy dog", 44);
	sha512_process(&hs, privkeytmp, i);
	sha512_done(&hs, privkeyhash);
	m_burn(privkeytmp, i);
	m_free(privkeytmp);

	/* calculate proto_k */
	sha512_init(&hs);
	sha512_process(&hs, privkeyhash, SHA512_HASH_SIZE);
	sha512_process(&hs, msghash, SHA1_HASH_SIZE);
	sha512_done(&hs, proto_k);

	/* generate k */
	m_mp_init(&dss_protok);
	bytes_to_mp(&dss_protok, proto_k, SHA512_HASH_SIZE);
	if (mp_mod(&dss_protok, key->q, &dss_k) != MP_OKAY)
		dropbear_exit("DSS error");
	mp_clear(&dss_protok);
	m_burn(proto_k, SHA512_HASH_SIZE);
#else /* DSS_PROTOK not defined*/
	gen_random_mpint(key->q, &dss_k);
#endif

	/* now generate the actual signature */
	bytes_to_mp(&dss_m, msghash, SHA1_HASH_SIZE);

	/* g^k mod p */
	if (mp_exptmod(key->g, &dss_k, key->p, &dss_temp1) !=  MP_OKAY)
		dropbear_exit("DSS error");
	/* r = (g^k mod p) mod q */
	if (mp_mod(&dss_temp1, key->q, &dss_r) != MP_OKAY)
		dropbear_exit("DSS error");

	/* x*r mod q */
	if (mp_mulmod(&dss_r, key->x, key->q, &dss_temp1) != MP_OKAY)
		dropbear_exit("DSS error");
	/* (SHA1(M) + xr) mod q) */
	if (mp_addmod(&dss_m, &dss_temp1, key->q, &dss_temp2) != MP_OKAY)
		dropbear_exit("DSS error");

	/* (k^-1) mod q */
	if (mp_invmod(&dss_k, key->q, &dss_temp1) != MP_OKAY)
		dropbear_exit("DSS error");

	/* s = (k^-1(SHA1(M) + xr)) mod q */
	if (mp_mulmod(&dss_temp1, &dss_temp2, key->q, &dss_s) != MP_OKAY)
		dropbear_exit("DSS error");

	buf_putstring(buf, SSH_SIGNKEY_DSS, SSH_SIGNKEY_DSS_LEN);
	buf_putint(buf, 2*SHA1_HASH_SIZE);

	writelen = mp_unsigned_bin_size(&dss_r);
	dropbear_assert(writelen <= SHA1_HASH_SIZE);
	/* need to pad to 160 bits with leading zeros */
	for (i = 0; i < SHA1_HASH_SIZE - writelen; i++) {
		buf_putbyte(buf, 0);
	}
	if (mp_to_unsigned_bin(&dss_r, buf_getwriteptr(buf, writelen)) != MP_OKAY)
		dropbear_exit("DSS error");
	mp_clear(&dss_r);
	buf_incrwritepos(buf, writelen);

	writelen = mp_unsigned_bin_size(&dss_s);
	dropbear_assert(writelen <= SHA1_HASH_SIZE);
	/* need to pad to 160 bits with leading zeros */
	for (i = 0; i < SHA1_HASH_SIZE - writelen; i++) {
		buf_putbyte(buf, 0);
	}
	if (mp_to_unsigned_bin(&dss_s, buf_getwriteptr(buf, writelen)) != MP_OKAY)
		dropbear_exit("DSS error");
	mp_clear(&dss_s);
	buf_incrwritepos(buf, writelen);

	mp_clear_multi(&dss_k, &dss_temp1, &dss_temp2, &dss_r, &dss_s,
			&dss_m, NULL);
}

#endif /* DROPBEAR_DSS */
/* Taken for Dropbear from OpenSSH 5.5p1 */

static void list_append(m_list *list, void *item) {
	m_list_elem *elem;

	elem = m_malloc(sizeof(*elem));
	elem->item = item;
	elem->list = list;
	elem->next = NULL;
	if (!list->first) {
		list->first = elem;
		elem->prev = NULL;
	} else {
		elem->prev = list->last;
		list->last->next = elem;
	}
	list->last = elem;
}

static m_list * list_new() {
	m_list *ret = m_malloc(sizeof(m_list));
	ret->first = ret->last = NULL;
	return ret;
}

static void * list_remove(m_list_elem *elem) {
	void *item = elem->item;
	m_list *list = elem->list;
	if (list->first == elem)
	{
		list->first = elem->next;
	}
	if (list->last == elem)
	{
		list->last = elem->prev;
	}
	if (elem->prev)
	{
		elem->prev->next = elem->next;
	}
	if (elem->next)
	{
		elem->next->prev = elem->prev;
	}
	m_free(elem);
	return item;
}


/* acceptor(int fd, void* typedata) is a function to accept connections,
 * cleanup(void* typedata) happens when cleaning up */
static struct Listener* new_listener(int socks[], unsigned int nsocks,
		int type, void* typedata,
		void (*acceptor)(struct Listener* listener, int sock),
		void (*cleanup)(struct Listener*)) {

	unsigned int i, j;
	struct Listener *newlisten = NULL;
	/* try get a new structure to hold it */
	for (i = 0; i < ses.listensize; i++) {
		if (ses.listeners[i] == NULL) {
			break;
		}
	}

	/* or create a new one */
	if (i == ses.listensize) {
		if (ses.listensize > MAX_LISTENERS) {
			for (j = 0; j < nsocks; j++)
				close(socks[i]);
			return NULL;
		}

		ses.listeners = (struct Listener**)m_realloc(ses.listeners,
				(ses.listensize+LISTENER_EXTEND_SIZE)
				*sizeof(struct Listener*));

		ses.listensize += LISTENER_EXTEND_SIZE;

		for (j = i; j < ses.listensize; j++) {
			ses.listeners[j] = NULL;
		}
	}

	for (j = 0; j < nsocks; j++) {
		ses.maxfd = MAX(ses.maxfd, socks[j]);
	}

	newlisten = (struct Listener*)m_malloc(sizeof(struct Listener));
	newlisten->index = i;
	newlisten->type = type;
	newlisten->typedata = typedata;
	newlisten->nsocks = nsocks;
	memcpy(newlisten->socks, socks, nsocks * sizeof(int));
	newlisten->acceptor = acceptor;
	newlisten->cleanup = cleanup;

	ses.listeners[i] = newlisten;
	return newlisten;
}


static int read_packet_init();
static void make_mac(unsigned int seqno, const struct key_context_directional * key_state,
		buffer * clear_buf, unsigned int clear_len,
		unsigned char *output_mac);
static int checkmac();

#ifndef DISABLE_ZLIB
#define ZLIB_COMPRESS_INCR 100
#define ZLIB_DECOMPRESS_INCR 100
static buffer* buf_decompress(buffer* buf, unsigned int len);
static void buf_compress(buffer * dest, buffer * src, unsigned int len);
#endif

/* non-blocking function writing out a current encrypted packet */
static void write_packet(void) {

	int len, written;
	buffer * writebuf = NULL;
	time_t now;
	unsigned packet_type;

	dropbear_assert(!isempty(&ses.writequeue));

	/* Get the next buffer in the queue of encrypted packets to write*/
	writebuf = (buffer*)examine(&ses.writequeue);

	/* The last byte of the buffer is not to be transmitted, but is
	 * a cleartext packet_type indicator */
	packet_type = writebuf->data[writebuf->len-1];
	len = writebuf->len - 1 - writebuf->pos;
	dropbear_assert(len > 0);
	/* Try to write as much as possible */
	written = write(ses.sock_out, buf_getptr(writebuf, len), len);

	if (written < 0) {
		if (errno == EINTR)
			return;
		 else
			dropbear_exit("Error writing");
	}

	now = time(NULL);
	ses.last_trx_packet_time = now;

	if (packet_type != SSH_MSG_IGNORE) {
		ses.last_packet_time = now;
	}

	if (written == 0) {
		ses.remoteclosed();
	}

	if (written == len) {
		/* We've finished with the packet, free it */
		dequeue(&ses.writequeue);
		buf_free(writebuf);
		writebuf = NULL;
	} else {
		/* More packet left to write, leave it in the queue for later */
		buf_incrpos(writebuf, written);
	}
}

/* Non-blocking function reading available portion of a packet into the
 * ses's buffer, decrypting the length if encrypted, decrypting the
 * full portion if possible */
static void read_packet(void) {

	int len;
	unsigned int maxlen;
	unsigned char blocksize;

	blocksize = ses.keys->recv.algo_crypt->blocksize;

	if (ses.readbuf == NULL || ses.readbuf->len < blocksize) {
		int ret;
		/* In the first blocksize of a packet */

		/* Read the first blocksize of the packet, so we can decrypt it and
		 * find the length of the whole packet */
		ret = read_packet_init();

		if (ret == DROPBEAR_FAILURE) {
			/* didn't read enough to determine the length */
			return;
		}
	}

	/* Attempt to read the remainder of the packet, note that there
	 * mightn't be any available (EAGAIN) */
	maxlen = ses.readbuf->len - ses.readbuf->pos;
	len = read(ses.sock_in, buf_getptr(ses.readbuf, maxlen), maxlen);

	if (len == 0) {
		ses.remoteclosed();
	}

	if (len < 0) {
		if (errno == EINTR || errno == EAGAIN)
			return;
		 else
			dropbear_exit("Error reading: %s", strerror(errno));
	}

	buf_incrpos(ses.readbuf, len);

	if ((unsigned int)len == maxlen) {
		/* The whole packet has been read */
		decrypt_packet();
		/* The main select() loop process_packet() to
		 * handle the packet contents... */
	}
}

/* Function used to read the initial portion of a packet, and determine the
 * length. Only called during the first BLOCKSIZE of a packet. */
/* Returns DROPBEAR_SUCCESS if the length is determined,
 * DROPBEAR_FAILURE otherwise */
static int read_packet_init() {

	unsigned int maxlen;
	int slen;
	unsigned int len;
	unsigned int blocksize;
	unsigned int macsize;


	blocksize = ses.keys->recv.algo_crypt->blocksize;
	macsize = ses.keys->recv.algo_mac->hashsize;

	if (ses.readbuf == NULL) {
		/* start of a new packet */
		ses.readbuf = buf_new(INIT_READBUF);
	}

	maxlen = blocksize - ses.readbuf->pos;

	/* read the rest of the packet if possible */
	slen = read(ses.sock_in, buf_getwriteptr(ses.readbuf, maxlen),
			maxlen);
	if (slen == 0) {
		ses.remoteclosed();
	}
	if (slen < 0) {
		if (errno == EINTR)
			return DROPBEAR_FAILURE;
		dropbear_exit("Error reading: %s", strerror(errno));
	}

	buf_incrwritepos(ses.readbuf, slen);

	if ((unsigned int)slen != maxlen) {
		/* don't have enough bytes to determine length, get next time */
		return DROPBEAR_FAILURE;
	}

	/* now we have the first block, need to get packet length, so we decrypt
	 * the first block (only need first 4 bytes) */
	buf_setpos(ses.readbuf, 0);
	if (ses.keys->recv.crypt_mode->decrypt(buf_getptr(ses.readbuf, blocksize),
				buf_getwriteptr(ses.readbuf, blocksize),
				blocksize,
				&ses.keys->recv.cipher_state) != CRYPT_OK) {
		dropbear_exit("Error decrypting");
	}
	len = buf_getint(ses.readbuf) + 4 + macsize;

	/* check packet length */
	if ((len > RECV_MAX_PACKET_LEN) ||
		(len < MIN_PACKET_LEN + macsize) ||
		((len - macsize) % blocksize != 0)) {
		dropbear_exit("Integrity error (bad packet size %d)", len);
	}

	if (len > ses.readbuf->size) {
		buf_resize(ses.readbuf, len);
	}
	buf_setlen(ses.readbuf, len);
	buf_setpos(ses.readbuf, blocksize);
	return DROPBEAR_SUCCESS;
}

/* handle the received packet */
static void decrypt_packet(void) {

	unsigned char blocksize;
	unsigned char macsize;
	unsigned int padlen;
	unsigned int len;

	blocksize = ses.keys->recv.algo_crypt->blocksize;
	macsize = ses.keys->recv.algo_mac->hashsize;

	ses.kexstate.datarecv += ses.readbuf->len;

	/* we've already decrypted the first blocksize in read_packet_init */
	buf_setpos(ses.readbuf, blocksize);

	/* decrypt it in-place */
	len = ses.readbuf->len - macsize - ses.readbuf->pos;
	if (ses.keys->recv.crypt_mode->decrypt(
				buf_getptr(ses.readbuf, len),
				buf_getwriteptr(ses.readbuf, len),
				len,
				&ses.keys->recv.cipher_state) != CRYPT_OK) {
		dropbear_exit("Error decrypting");
	}
	buf_incrpos(ses.readbuf, len);

	/* check the hmac */
	if (checkmac() != DROPBEAR_SUCCESS)
		dropbear_exit("Integrity error");

	/* get padding length */
	buf_setpos(ses.readbuf, PACKET_PADDING_OFF);
	padlen = buf_getbyte(ses.readbuf);

	/* payload length */
	/* - 4 - 1 is for LEN and PADLEN values */
	len = ses.readbuf->len - padlen - 4 - 1 - macsize;
	if ((len > RECV_MAX_PAYLOAD_LEN) || (len < 1))
		dropbear_exit("Bad packet size %d", len);

	buf_setpos(ses.readbuf, PACKET_PAYLOAD_OFF);

#ifndef DISABLE_ZLIB
	if (is_compress_recv()) {
		/* decompress */
		ses.payload = buf_decompress(ses.readbuf, len);
	} else
#endif
	{
		/* copy payload */
		ses.payload = buf_new(len);
		memcpy(ses.payload->data, buf_getptr(ses.readbuf, len), len);
		buf_incrlen(ses.payload, len);
	}

	buf_free(ses.readbuf);
	ses.readbuf = NULL;
	buf_setpos(ses.payload, 0);

	ses.recvseq++;
}

/* Checks the mac at the end of a decrypted readbuf.
 * Returns DROPBEAR_SUCCESS or DROPBEAR_FAILURE */
static int checkmac() {

	unsigned char mac_bytes[MAX_MAC_LEN];
	unsigned int mac_size, contents_len;

	mac_size = ses.keys->trans.algo_mac->hashsize;
	contents_len = ses.readbuf->len - mac_size;

	buf_setpos(ses.readbuf, 0);
	make_mac(ses.recvseq, &ses.keys->recv, ses.readbuf, contents_len, mac_bytes);

	/* compare the hash */
	buf_setpos(ses.readbuf, contents_len);
	if (memcmp(mac_bytes, buf_getptr(ses.readbuf, mac_size), mac_size) != 0) {
		return DROPBEAR_FAILURE;
	} else {
		return DROPBEAR_SUCCESS;
	}
}

#ifndef DISABLE_ZLIB
/* returns a pointer to a newly created buffer */
static buffer* buf_decompress(buffer* buf, unsigned int len) {

	int result;
	buffer * ret;
	z_streamp zstream;

	zstream = ses.keys->recv.zstream;
	ret = buf_new(len);

	zstream->avail_in = len;
	zstream->next_in = buf_getptr(buf, len);

	/* decompress the payload, incrementally resizing the output buffer */
	while (1) {

		zstream->avail_out = ret->size - ret->pos;
		zstream->next_out = buf_getwriteptr(ret, zstream->avail_out);

		result = inflate(zstream, Z_SYNC_FLUSH);

		buf_setlen(ret, ret->size - zstream->avail_out);
		buf_setpos(ret, ret->len);

		if (result != Z_BUF_ERROR && result != Z_OK)
			dropbear_exit("zlib error");

		if (zstream->avail_in == 0 &&
				(zstream->avail_out != 0 || result == Z_BUF_ERROR)) {
			/* we can only exit if avail_out hasn't all been used,
			 * and there's no remaining input */
			return ret;
		}

		if (zstream->avail_out == 0) {
			buf_resize(ret, ret->size + ZLIB_DECOMPRESS_INCR);
		}
	}
}
#endif


/* returns 1 if the packet is a valid type during kex (see 7.1 of rfc4253) */
static int packet_is_okay_kex(unsigned char type) {
	if (type >= SSH_MSG_USERAUTH_REQUEST) {
		return 0;
	}
	if (type == SSH_MSG_SERVICE_REQUEST || type == SSH_MSG_SERVICE_ACCEPT) {
		return 0;
	}
	if (type == SSH_MSG_KEXINIT) {
		/* XXX should this die horribly if !dataallowed ?? */
		return 0;
	}
	return 1;
}

static void enqueue_reply_packet() {
	struct packetlist * new_item = NULL;
	new_item = m_malloc(sizeof(struct packetlist));
	new_item->next = NULL;

	new_item->payload = buf_newcopy(ses.writepayload);
	buf_setpos(ses.writepayload, 0);
	buf_setlen(ses.writepayload, 0);

	if (ses.reply_queue_tail) {
		ses.reply_queue_tail->next = new_item;
	} else {
		ses.reply_queue_head = new_item;
	}
	ses.reply_queue_tail = new_item;
}

static void maybe_flush_reply_queue(void) {
	struct packetlist *tmp_item = NULL, *curr_item = NULL;
	if (!ses.dataallowed)
		return;

	for (curr_item = ses.reply_queue_head; curr_item; ) {
		buf_putbytes(ses.writepayload,
			curr_item->payload->data, curr_item->payload->len);

		buf_free(curr_item->payload);
		tmp_item = curr_item;
		curr_item = curr_item->next;
		m_free(tmp_item);
		encrypt_packet();
	}
	ses.reply_queue_head = ses.reply_queue_tail = NULL;
}

/* encrypt the writepayload, putting into writebuf, ready for write_packet()
 * to put on the wire */
static void encrypt_packet(void) {

	unsigned char padlen;
	unsigned char blocksize, mac_size;
	buffer * writebuf; /* the packet which will go on the wire. This is
			      encrypted in-place. */
	unsigned char packet_type;
	unsigned int len, encrypt_buf_size;
	unsigned char mac_bytes[MAX_MAC_LEN];

	buf_setpos(ses.writepayload, 0);
	packet_type = buf_getbyte(ses.writepayload);
	buf_setpos(ses.writepayload, 0);

	if ((!ses.dataallowed && !packet_is_okay_kex(packet_type))
			|| ses.kexstate.sentnewkeys) {
		/* During key exchange only particular packets are allowed.
			Since this packet_type isn't OK we just enqueue it to send
			after the KEX, see maybe_flush_reply_queue */

		/* We also enqueue packets here when we have sent a MSG_NEWKEYS
		 * packet but are yet to received one. For simplicity we just switch
		 * over all the keys at once. This is the 'ses.kexstate.sentnewkeys'
		 * case. */
		enqueue_reply_packet();
		return;
	}

	blocksize = ses.keys->trans.algo_crypt->blocksize;
	mac_size = ses.keys->trans.algo_mac->hashsize;

	/* Encrypted packet len is payload+5. We need to then make sure
	 * there is enough space for padding or MIN_PACKET_LEN.
	 * Add extra 3 since we need at least 4 bytes of padding */
	encrypt_buf_size = (ses.writepayload->len+4+1)
		+ MAX(MIN_PACKET_LEN, blocksize) + 3
	/* add space for the MAC at the end */
				+ mac_size
#ifndef DISABLE_ZLIB
	/* some extra in case 'compression' makes it larger */
				+ ZLIB_COMPRESS_INCR
#endif
	/* and an extra cleartext (stripped before transmission) byte for the
	 * packet type */
				+ 1;

	writebuf = buf_new(encrypt_buf_size);
	buf_setlen(writebuf, PACKET_PAYLOAD_OFF);
	buf_setpos(writebuf, PACKET_PAYLOAD_OFF);

#ifndef DISABLE_ZLIB
	/* compression */
	if (is_compress_trans()) {
		int compress_delta;
		buf_compress(writebuf, ses.writepayload, ses.writepayload->len);
		compress_delta = (writebuf->len - PACKET_PAYLOAD_OFF) - ses.writepayload->len;

		/* Handle the case where 'compress' increased the size. */
		if (compress_delta > ZLIB_COMPRESS_INCR) {
			buf_resize(writebuf, writebuf->size + compress_delta);
		}
	} else
#endif
	{
		memcpy(buf_getwriteptr(writebuf, ses.writepayload->len),
				buf_getptr(ses.writepayload, ses.writepayload->len),
				ses.writepayload->len);
		buf_incrwritepos(writebuf, ses.writepayload->len);
	}

	/* finished with payload */
	buf_setpos(ses.writepayload, 0);
	buf_setlen(ses.writepayload, 0);

	/* length of padding - packet length must be a multiple of blocksize,
	 * with a minimum of 4 bytes of padding */
	padlen = blocksize - (writebuf->len) % blocksize;
	if (padlen < 4) {
		padlen += blocksize;
	}
	/* check for min packet length */
	if (writebuf->len + padlen < MIN_PACKET_LEN) {
		padlen += blocksize;
	}

	buf_setpos(writebuf, 0);
	/* packet length excluding the packetlength uint32 */
	buf_putint(writebuf, writebuf->len + padlen - 4);

	/* padding len */
	buf_putbyte(writebuf, padlen);
	/* actual padding */
	buf_setpos(writebuf, writebuf->len);
	buf_incrlen(writebuf, padlen);
	genrandom(buf_getptr(writebuf, padlen), padlen);

	make_mac(ses.transseq, &ses.keys->trans, writebuf, writebuf->len, mac_bytes);

	/* do the actual encryption, in-place */
	buf_setpos(writebuf, 0);
	/* encrypt it in-place*/
	len = writebuf->len;
	if (ses.keys->trans.crypt_mode->encrypt(
				buf_getptr(writebuf, len),
				buf_getwriteptr(writebuf, len),
				len,
				&ses.keys->trans.cipher_state) != CRYPT_OK) {
		dropbear_exit("Error encrypting");
	}
	buf_incrpos(writebuf, len);

    /* stick the MAC on it */
    buf_putbytes(writebuf, mac_bytes, mac_size);

	/* The last byte of the buffer stores the cleartext packet_type. It is not
	 * transmitted but is used for transmit timeout purposes */
	buf_putbyte(writebuf, packet_type);
	/* enqueue the packet for sending. It will get freed after transmission. */
	buf_setpos(writebuf, 0);
	enqueue(&ses.writequeue, (void*)writebuf);

	/* Update counts */
	ses.kexstate.datatrans += writebuf->len;
	ses.transseq++;
}


/* Create the packet mac, and append H(seqno|clearbuf) to the output */
/* output_mac must have ses.keys->trans.algo_mac->hashsize bytes. */
static void make_mac(unsigned int seqno, const struct key_context_directional * key_state,
		buffer * clear_buf, unsigned int clear_len,
		unsigned char *output_mac) {
	unsigned char seqbuf[4];
	unsigned long bufsize;
	hmac_state hmac;

	if (key_state->algo_mac->hashsize > 0) {
		/* calculate the mac */
		if (hmac_init(&hmac, key_state->hash_index,
			       key_state->mackey,
			       key_state->algo_mac->keysize) != CRYPT_OK) {
			dropbear_exit("HMAC error");
		}

		/* sequence number */
		STORE32H(seqno, seqbuf);
		if (hmac_process(&hmac, seqbuf, 4) != CRYPT_OK)
			dropbear_exit("HMAC error");

		/* the actual contents */
		buf_setpos(clear_buf, 0);
		if (hmac_process(&hmac, buf_getptr(clear_buf, clear_len),
					clear_len) != CRYPT_OK) {
			dropbear_exit("HMAC error");
		}

		bufsize = MAX_MAC_LEN;
		if (hmac_done(&hmac, output_mac, &bufsize) != CRYPT_OK)
			dropbear_exit("HMAC error");
	}
}

#ifndef DISABLE_ZLIB
/* compresses len bytes from src, outputting to dest (starting from the
 * respective current positions. */
static void buf_compress(buffer * dest, buffer * src, unsigned int len) {

	unsigned int endpos = src->pos + len;
	int result;

	while (1) {

		ses.keys->trans.zstream->avail_in = endpos - src->pos;
		ses.keys->trans.zstream->next_in =
			buf_getptr(src, ses.keys->trans.zstream->avail_in);

		ses.keys->trans.zstream->avail_out = dest->size - dest->pos;
		ses.keys->trans.zstream->next_out =
			buf_getwriteptr(dest, ses.keys->trans.zstream->avail_out);

		result = deflate(ses.keys->trans.zstream, Z_SYNC_FLUSH);

		buf_setpos(src, endpos - ses.keys->trans.zstream->avail_in);
		buf_setlen(dest, dest->size - ses.keys->trans.zstream->avail_out);
		buf_setpos(dest, dest->len);

		if (result != Z_OK)
			dropbear_exit("zlib error");

		if (ses.keys->trans.zstream->avail_in == 0)
			break;

		dropbear_assert(ses.keys->trans.zstream->avail_out == 0);

		/* the buffer has been filled, we must extend. This only happens in
		 * unusual circumstances where the data grows in size after deflate(),
		 * but it is possible */
		buf_resize(dest, dest->size + ZLIB_COMPRESS_INCR);

	}
}
#endif

#define MAX_UNAUTH_PACKET_TYPE SSH_MSG_USERAUTH_PK_OK

/* This must be called directly after receiving the unimplemented packet.
 * Isn't the most clean implementation, it relies on packet processing
 * occurring directly after decryption (direct use of ses.recvseq).
 * This is reasonably valid, since there is only a single decryption buffer */
static void recv_unimplemented() {

	buf_putbyte(ses.writepayload, SSH_MSG_UNIMPLEMENTED);
	/* the decryption routine increments the sequence number, we must
	 * decrement */
	buf_putint(ses.writepayload, ses.recvseq - 1);

	encrypt_packet();
}

/* process a decrypted packet, call the appropriate handler */
static void process_packet(void) {

	unsigned char type;
	unsigned int i;

	type = buf_getbyte(ses.payload);

	ses.lastpacket = type;

	ses.last_packet_time = time(NULL);

	/* These packets we can receive at any time */
	switch(type) {

		case SSH_MSG_IGNORE:
			goto out;
		case SSH_MSG_DEBUG:
			goto out;

		case SSH_MSG_UNIMPLEMENTED:
			/* debugging XXX */
			dropbear_exit("Received SSH_MSG_UNIMPLEMENTED");

		case SSH_MSG_DISCONNECT:
			/* TODO cleanup? */
			dropbear_close("Disconnect received");
	}

	/* This applies for KEX, where the spec says the next packet MUST be
	 * NEWKEYS */
	if (ses.requirenext != 0) {
		if (ses.requirenext != type) {
			/* TODO send disconnect? */
			dropbear_exit("Unexpected packet type %d, expected %d", type,
					ses.requirenext);
		} else {
			/* Got what we expected */
			ses.requirenext = 0;
		}
	}

	/* Check if we should ignore this packet. Used currently only for
	 * KEX code, with first_kex_packet_follows */
	if (ses.ignorenext) {
		ses.ignorenext = 0;
		goto out;
	}


	/* Kindly the protocol authors gave all the preauth packets type values
	 * less-than-or-equal-to 60 ( == MAX_UNAUTH_PACKET_TYPE ).
	 * NOTE: if the protocol changes and new types are added, revisit this
	 * assumption */
	if ( !ses.authstate.authdone && type > MAX_UNAUTH_PACKET_TYPE )
		dropbear_exit("Received message %d before userauth", type);

	for (i = 0; ; i++) {
		if (ses.packettypes[i].type == 0) {
			/* end of list */
			break;
		}

		if (ses.packettypes[i].type == type) {
			ses.packettypes[i].handler();
			goto out;
		}
	}


	/* TODO do something more here? */
	recv_unimplemented();

out:
	buf_free(ses.payload);
	ses.payload = NULL;
}

static void initqueue(struct Queue* queue) {

	queue->head = NULL;
	queue->tail = NULL;
	queue->count = 0;
}

static void* dequeue(struct Queue* queue) {

	void* ret;
	struct Link* oldhead;
	dropbear_assert(!isempty(queue));

	ret = queue->head->item;
	oldhead = queue->head;

	if (oldhead->link != NULL) {
		queue->head = oldhead->link;
	} else {
		queue->head = NULL;
		queue->tail = NULL;
	}

	m_free(oldhead);
	queue->count--;
	return ret;
}

static void *examine(struct Queue* queue) {

	dropbear_assert(!isempty(queue));
	return queue->head->item;
}

static void enqueue(struct Queue* queue, void* item) {

	struct Link* newlink;

	newlink = (struct Link*)m_malloc(sizeof(struct Link));

	newlink->item = item;
	newlink->link = NULL;

	if (queue->tail != NULL) {
		queue->tail->link = newlink;
	}
	queue->tail = newlink;

	if (queue->head == NULL) {
		queue->head = newlink;
	}
	queue->count++;
}

/* Perform RSA operations on data, including reading keys, signing and
 * verification.
 *
 * The format is specified in rfc2437, Applied Cryptography or The Handbook of
 * Applied Cryptography detail the general algorithm. */

#ifdef DROPBEAR_RSA

static void rsa_pad_em(dropbear_rsa_key * key,
		const unsigned char * data, unsigned int len,
		mp_int * rsa_em);

/* Load a public rsa key from a buffer, initialising the values.
 * The key will have the same format as buf_put_rsa_key.
 * These should be freed with rsa_key_free.
 * Returns DROPBEAR_SUCCESS or DROPBEAR_FAILURE */
static int buf_get_rsa_pub_key(buffer* buf, dropbear_rsa_key *key) {

	int ret = DROPBEAR_FAILURE;

	dropbear_assert(key != NULL);
	key->e = m_malloc(sizeof(mp_int));
	key->n = m_malloc(sizeof(mp_int));
	m_mp_init_multi(key->e, key->n, NULL);
	key->d = NULL;
	key->p = NULL;
	key->q = NULL;

	buf_incrpos(buf, 4+SSH_SIGNKEY_RSA_LEN); /* int + "ssh-rsa" */

	if (buf_getmpint(buf, key->e) == DROPBEAR_FAILURE
	 || buf_getmpint(buf, key->n) == DROPBEAR_FAILURE) {
	    goto out;
	}

	if (mp_count_bits(key->n) < MIN_RSA_KEYLEN) {
	    dropbear_log("RSA key too short");
	    goto out;
	}

	ret = DROPBEAR_SUCCESS;
out:
	if (ret == DROPBEAR_FAILURE) {
		m_free(key->e);
		m_free(key->n);
	}
	return ret;
}

/* Same as buf_get_rsa_pub_key, but reads private bits at the end.
 * Loads a private rsa key from a buffer
 * Returns DROPBEAR_SUCCESS or DROPBEAR_FAILURE */
static int buf_get_rsa_priv_key(buffer* buf, dropbear_rsa_key *key) {
	int ret = DROPBEAR_FAILURE;

	dropbear_assert(key != NULL);

	if (buf_get_rsa_pub_key(buf, key) == DROPBEAR_FAILURE) {
		return DROPBEAR_FAILURE;
	}

	key->d = NULL;
	key->p = NULL;
	key->q = NULL;

	key->d = m_malloc(sizeof(mp_int));
	m_mp_init(key->d);
	if (buf_getmpint(buf, key->d) == DROPBEAR_FAILURE) {
	    goto out;
	}

	if (buf->pos == buf->len) {
	/* old Dropbear private keys didn't keep p and q, so we will ignore them*/
	} else {
		key->p = m_malloc(sizeof(mp_int));
		key->q = m_malloc(sizeof(mp_int));
		m_mp_init_multi(key->p, key->q, NULL);

		if (buf_getmpint(buf, key->p) == DROPBEAR_FAILURE)
			goto out;

		if (buf_getmpint(buf, key->q) == DROPBEAR_FAILURE)
			goto out;
	}

	ret = DROPBEAR_SUCCESS;
out:
	if (ret == DROPBEAR_FAILURE) {
		m_free(key->d);
		m_free(key->p);
		m_free(key->q);
	}
	return ret;
}


/* Clear and free the memory used by a public or private key */
static void rsa_key_free(dropbear_rsa_key *key) {

	if (key == NULL)
		return;
	if (key->d) {
		mp_clear(key->d);
		m_free(key->d);
	}
	if (key->e) {
		mp_clear(key->e);
		m_free(key->e);
	}
	if (key->n) {
		 mp_clear(key->n);
		 m_free(key->n);
	}
	if (key->p) {
		mp_clear(key->p);
		m_free(key->p);
	}
	if (key->q) {
		mp_clear(key->q);
		m_free(key->q);
	}
	m_free(key);
}

/* Put the public rsa key into the buffer in the required format:
 *
 * string       "ssh-rsa"
 * mp_int       e
 * mp_int       n
 */
static void buf_put_rsa_pub_key(buffer* buf, dropbear_rsa_key *key) {

	dropbear_assert(key != NULL);

	buf_putstring(buf, SSH_SIGNKEY_RSA, SSH_SIGNKEY_RSA_LEN);
	buf_putmpint(buf, key->e);
	buf_putmpint(buf, key->n);
}

/* Verify a signature in buf, made on data by the key given.
 * Returns DROPBEAR_SUCCESS or DROPBEAR_FAILURE */
static int buf_rsa_verify(buffer * buf, dropbear_rsa_key *key, const unsigned char* data,
		unsigned int len) {

	unsigned int slen;
	DEF_MP_INT(rsa_s);
	DEF_MP_INT(rsa_mdash);
	DEF_MP_INT(rsa_em);
	int ret = DROPBEAR_FAILURE;

	dropbear_assert(key != NULL);

	m_mp_init_multi(&rsa_mdash, &rsa_s, &rsa_em, NULL);

	slen = buf_getint(buf);
	if (slen != (unsigned int)mp_unsigned_bin_size(key->n))
		goto out;

	if (mp_read_unsigned_bin(&rsa_s, buf_getptr(buf, buf->len - buf->pos),
				buf->len - buf->pos) != MP_OKAY)
		goto out;

	/* check that s <= n-1 */
	if (mp_cmp(&rsa_s, key->n) != MP_LT)
		goto out;

	/* create the magic PKCS padded value */
	rsa_pad_em(key, data, len, &rsa_em);

	if (mp_exptmod(&rsa_s, key->e, key->n, &rsa_mdash) != MP_OKAY)
		goto out;

	if (mp_cmp(&rsa_em, &rsa_mdash) == MP_EQ) {
		/* signature is valid */
		ret = DROPBEAR_SUCCESS;
	}

out:
	mp_clear_multi(&rsa_mdash, &rsa_s, &rsa_em, NULL);
	return ret;
}

/* Sign the data presented with key, writing the signature contents
 * to the buffer */
static void buf_put_rsa_sign(buffer* buf, dropbear_rsa_key *key, const unsigned char* data,
		unsigned int len) {

	unsigned int nsize, ssize;
	unsigned int i;
	DEF_MP_INT(rsa_s);
	DEF_MP_INT(rsa_tmp1);
	DEF_MP_INT(rsa_tmp2);
	DEF_MP_INT(rsa_tmp3);

	dropbear_assert(key != NULL);

	m_mp_init_multi(&rsa_s, &rsa_tmp1, &rsa_tmp2, &rsa_tmp3, NULL);

	rsa_pad_em(key, data, len, &rsa_tmp1);

	/* the actual signing of the padded data */

#ifdef RSA_BLINDING

	/* With blinding, s = (r^(-1))((em)*r^e)^d mod n */

	/* generate the r blinding value */
	/* rsa_tmp2 is r */
	gen_random_mpint(key->n, &rsa_tmp2);

	/* rsa_tmp1 is em */
	/* em' = em * r^e mod n */

	/* rsa_s used as a temp var*/
	if (mp_exptmod(&rsa_tmp2, key->e, key->n, &rsa_s) != MP_OKAY)
		dropbear_exit("RSA error");
	if (mp_invmod(&rsa_tmp2, key->n, &rsa_tmp3) != MP_OKAY)
		dropbear_exit("RSA error");
	if (mp_mulmod(&rsa_tmp1, &rsa_s, key->n, &rsa_tmp2) != MP_OKAY)
		dropbear_exit("RSA error");

	/* rsa_tmp2 is em' */
	/* s' = (em')^d mod n */
	if (mp_exptmod(&rsa_tmp2, key->d, key->n, &rsa_tmp1) != MP_OKAY)
		dropbear_exit("RSA error");

	/* rsa_tmp1 is s' */
	/* rsa_tmp3 is r^(-1) mod n */
	/* s = (s')r^(-1) mod n */
	if (mp_mulmod(&rsa_tmp1, &rsa_tmp3, key->n, &rsa_s) != MP_OKAY)
		dropbear_exit("RSA error");

#else

	/* s = em^d mod n */
	/* rsa_tmp1 is em */
	if (mp_exptmod(&rsa_tmp1, key->d, key->n, &rsa_s) != MP_OKAY)
		dropbear_exit("RSA error");

#endif /* RSA_BLINDING */

	mp_clear_multi(&rsa_tmp1, &rsa_tmp2, &rsa_tmp3, NULL);

	/* create the signature to return */
	buf_putstring(buf, SSH_SIGNKEY_RSA, SSH_SIGNKEY_RSA_LEN);

	nsize = mp_unsigned_bin_size(key->n);

	/* string rsa_signature_blob length */
	buf_putint(buf, nsize);
	/* pad out s to same length as n */
	ssize = mp_unsigned_bin_size(&rsa_s);
	dropbear_assert(ssize <= nsize);
	for (i = 0; i < nsize-ssize; i++) {
		buf_putbyte(buf, 0x00);
	}

	if (mp_to_unsigned_bin(&rsa_s, buf_getwriteptr(buf, ssize)) != MP_OKAY)
		dropbear_exit("RSA error");
	buf_incrwritepos(buf, ssize);
	mp_clear(&rsa_s);
}

/* Creates the message value as expected by PKCS, see rfc2437 etc */
/* format to be padded to is:
 * EM = 01 | FF* | 00 | prefix | hash
 *
 * where FF is repeated enough times to make EM one byte
 * shorter than the size of key->n
 *
 * prefix is the ASN1 designator prefix,
 * hex 30 21 30 09 06 05 2B 0E 03 02 1A 05 00 04 14
 *
 * rsa_em must be a pointer to an initialised mp_int.
 */
static void rsa_pad_em(dropbear_rsa_key * key,
		const unsigned char * data, unsigned int len,
		mp_int * rsa_em) {

	/* ASN1 designator (including the 0x00 preceding) */
	const unsigned char rsa_asn1_magic[] =
		{0x00, 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b,
		 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14};
	const unsigned int RSA_ASN1_MAGIC_LEN = 16;

	buffer * rsa_EM = NULL;
	hash_state hs;
	unsigned int nsize;

	dropbear_assert(key != NULL);
	dropbear_assert(data != NULL);
	nsize = mp_unsigned_bin_size(key->n);

	rsa_EM = buf_new(nsize-1);
	/* type byte */
	buf_putbyte(rsa_EM, 0x01);
	/* Padding with 0xFF bytes */
	while(rsa_EM->pos != rsa_EM->size - RSA_ASN1_MAGIC_LEN - SHA1_HASH_SIZE) {
		buf_putbyte(rsa_EM, 0xff);
	}
	/* Magic ASN1 stuff */
	memcpy(buf_getwriteptr(rsa_EM, RSA_ASN1_MAGIC_LEN),
			rsa_asn1_magic, RSA_ASN1_MAGIC_LEN);
	buf_incrwritepos(rsa_EM, RSA_ASN1_MAGIC_LEN);

	/* The hash of the data */
	sha1_init(&hs);
	sha1_process(&hs, data, len);
	sha1_done(&hs, buf_getwriteptr(rsa_EM, SHA1_HASH_SIZE));
	buf_incrwritepos(rsa_EM, SHA1_HASH_SIZE);

	dropbear_assert(rsa_EM->pos == rsa_EM->size);

	/* Create the mp_int from the encoded bytes */
	buf_setpos(rsa_EM, 0);
	bytes_to_mp(rsa_em, buf_getptr(rsa_EM, rsa_EM->size),
			rsa_EM->size);
	buf_free(rsa_EM);
}

#endif /* DROPBEAR_RSA */

/* malloc a new sign_key and set the dss and rsa keys to NULL */
static sign_key * new_sign_key() {

	sign_key * ret;

	ret = (sign_key*)m_malloc(sizeof(sign_key));
#ifdef DROPBEAR_DSS
	ret->dsskey = NULL;
#endif
#ifdef DROPBEAR_RSA
	ret->rsakey = NULL;
#endif
	ret->filename = NULL;
	ret->type = DROPBEAR_SIGNKEY_NONE;
	ret->source = SIGNKEY_SOURCE_INVALID;
	return ret;
}

/* Returns "ssh-dss" or "ssh-rsa" corresponding to the type. Exits fatally
 * if the type is invalid */
static const char* signkey_name_from_type(int type, int *namelen) {

#ifdef DROPBEAR_RSA
	if (type == DROPBEAR_SIGNKEY_RSA) {
		*namelen = SSH_SIGNKEY_RSA_LEN;
		return SSH_SIGNKEY_RSA;
	}
#endif
#ifdef DROPBEAR_DSS
	if (type == DROPBEAR_SIGNKEY_DSS) {
		*namelen = SSH_SIGNKEY_DSS_LEN;
		return SSH_SIGNKEY_DSS;
	}
#endif
	dropbear_exit("Bad key type %d", type);
	return NULL; /* notreached */
}

/* Returns DROPBEAR_SIGNKEY_RSA, DROPBEAR_SIGNKEY_DSS,
 * or DROPBEAR_SIGNKEY_NONE */
static int signkey_type_from_name(const char* name, int namelen) {

#ifdef DROPBEAR_RSA
	if (namelen == SSH_SIGNKEY_RSA_LEN
			&& memcmp(name, SSH_SIGNKEY_RSA, SSH_SIGNKEY_RSA_LEN) == 0) {
		return DROPBEAR_SIGNKEY_RSA;
	}
#endif
#ifdef DROPBEAR_DSS
	if (namelen == SSH_SIGNKEY_DSS_LEN
			&& memcmp(name, SSH_SIGNKEY_DSS, SSH_SIGNKEY_DSS_LEN) == 0) {
		return DROPBEAR_SIGNKEY_DSS;
	}
#endif

	return DROPBEAR_SIGNKEY_NONE;
}

/* returns DROPBEAR_SUCCESS on success, DROPBEAR_FAILURE on fail.
 * type should be set by the caller to specify the type to read, and
 * on return is set to the type read (useful when type = _ANY) */
static int buf_get_pub_key(buffer *buf, sign_key *key, int *type) {

	char* ident;
	unsigned int len;
	int keytype;
	int ret = DROPBEAR_FAILURE;

	ident = buf_getstring(buf, &len);
	keytype = signkey_type_from_name(ident, len);
	m_free(ident);

	if (*type != DROPBEAR_SIGNKEY_ANY && *type != keytype)
		return DROPBEAR_FAILURE;

	*type = keytype;

	/* Rewind the buffer back before "ssh-rsa" etc */
	buf_incrpos(buf, -len - 4);

#ifdef DROPBEAR_DSS
	if (keytype == DROPBEAR_SIGNKEY_DSS) {
		dss_key_free(key->dsskey);
		key->dsskey = m_malloc(sizeof(*key->dsskey));
		ret = buf_get_dss_pub_key(buf, key->dsskey);
		if (ret == DROPBEAR_FAILURE) {
			m_free(key->dsskey);
		}
	}
#endif
#ifdef DROPBEAR_RSA
	if (keytype == DROPBEAR_SIGNKEY_RSA) {
		rsa_key_free(key->rsakey);
		key->rsakey = m_malloc(sizeof(*key->rsakey));
		ret = buf_get_rsa_pub_key(buf, key->rsakey);
		if (ret == DROPBEAR_FAILURE) {
			m_free(key->rsakey);
		}
	}
#endif

	return ret;
}

/* returns DROPBEAR_SUCCESS on success, DROPBEAR_FAILURE on fail.
 * type should be set by the caller to specify the type to read, and
 * on return is set to the type read (useful when type = _ANY) */
static int buf_get_priv_key(buffer *buf, sign_key *key, int *type) {

	char* ident;
	unsigned int len;
	int keytype;
	int ret = DROPBEAR_FAILURE;

	ident = buf_getstring(buf, &len);
	keytype = signkey_type_from_name(ident, len);
	m_free(ident);

	if (*type != DROPBEAR_SIGNKEY_ANY && *type != keytype)
		return DROPBEAR_FAILURE;

	*type = keytype;

	/* Rewind the buffer back before "ssh-rsa" etc */
	buf_incrpos(buf, -len - 4);

#ifdef DROPBEAR_DSS
	if (keytype == DROPBEAR_SIGNKEY_DSS) {
		dss_key_free(key->dsskey);
		key->dsskey = m_malloc(sizeof(*key->dsskey));
		ret = buf_get_dss_priv_key(buf, key->dsskey);
		if (ret == DROPBEAR_FAILURE) {
			m_free(key->dsskey);
		}
	}
#endif
#ifdef DROPBEAR_RSA
	if (keytype == DROPBEAR_SIGNKEY_RSA) {
		rsa_key_free(key->rsakey);
		key->rsakey = m_malloc(sizeof(*key->rsakey));
		ret = buf_get_rsa_priv_key(buf, key->rsakey);
		if (ret == DROPBEAR_FAILURE) {
			m_free(key->rsakey);
		}
	}
#endif

	return ret;
}

/* type is either DROPBEAR_SIGNKEY_DSS or DROPBEAR_SIGNKEY_RSA */
static void buf_put_pub_key(buffer* buf, sign_key *key, int type) {

	buffer *pubkeys;

	pubkeys = buf_new(MAX_PUBKEY_SIZE);

#ifdef DROPBEAR_DSS
	if (type == DROPBEAR_SIGNKEY_DSS) {
		buf_put_dss_pub_key(pubkeys, key->dsskey);
	}
#endif
#ifdef DROPBEAR_RSA
	if (type == DROPBEAR_SIGNKEY_RSA) {
		buf_put_rsa_pub_key(pubkeys, key->rsakey);
	}
#endif
	if (pubkeys->len == 0)
		dropbear_exit("Bad key types in buf_put_pub_key");

	buf_setpos(pubkeys, 0);
	buf_putstring(buf, (char *)buf_getptr(pubkeys, pubkeys->len), pubkeys->len);

	buf_free(pubkeys);
}

static void sign_key_free(sign_key *key) {

#ifdef DROPBEAR_DSS
	dss_key_free(key->dsskey);
	key->dsskey = NULL;
#endif
#ifdef DROPBEAR_RSA
	rsa_key_free(key->rsakey);
	key->rsakey = NULL;
#endif

	m_free(key->filename);

	m_free(key);
}

static char hexdig(unsigned char x) {

	if (x > 0xf)
		return 'X';

	if (x < 10)
		return '0' + x;
	else
		return 'a' + x - 10;
}

/* Since we're not sure if we'll have md5 or sha1, we present both.
 * MD5 is used in preference, but sha1 could still be useful */
#ifdef DROPBEAR_MD5_HMAC
static char * sign_key_md5_fingerprint(unsigned char* keyblob,
		unsigned int keybloblen) {

	char * ret;
	hash_state hs;
	unsigned char hash[MD5_HASH_SIZE];
	unsigned int i;
	unsigned int buflen;

	md5_init(&hs);

	/* skip the size int of the string - this is a bit messy */
	md5_process(&hs, keyblob, keybloblen);

	md5_done(&hs, hash);

	/* "md5 hexfingerprinthere\0", each hex digit is "AB:" etc */
	buflen = 4 + 3*MD5_HASH_SIZE;
	ret = (char*)m_malloc(buflen);

	memset(ret, 'Z', buflen);
	strcpy(ret, "md5 ");

	for (i = 0; i < MD5_HASH_SIZE; i++) {
		unsigned int pos = 4 + i*3;
		ret[pos] = hexdig(hash[i] >> 4);
		ret[pos+1] = hexdig(hash[i] & 0x0f);
		ret[pos+2] = ':';
	}
	ret[buflen-1] = 0x0;

	return ret;
}

#else /* use SHA1 rather than MD5 for fingerprint */
static char * sign_key_sha1_fingerprint(unsigned char* keyblob,
		unsigned int keybloblen) {

	char * ret;
	hash_state hs;
	unsigned char hash[SHA1_HASH_SIZE];
	unsigned int i;
	unsigned int buflen;

	sha1_init(&hs);

	/* skip the size int of the string - this is a bit messy */
	sha1_process(&hs, keyblob, keybloblen);

	sha1_done(&hs, hash);

	/* "sha1 hexfingerprinthere\0", each hex digit is "AB:" etc */
	buflen = 5 + 3*SHA1_HASH_SIZE;
	ret = (char*)m_malloc(buflen);

	strcpy(ret, "sha1 ");

	for (i = 0; i < SHA1_HASH_SIZE; i++) {
		unsigned int pos = 5 + 3*i;
		ret[pos] = hexdig(hash[i] >> 4);
		ret[pos+1] = hexdig(hash[i] & 0x0f);
		ret[pos+2] = ':';
	}
	ret[buflen-1] = 0x0;

	return ret;
}

#endif /* MD5/SHA1 switch */

/* This will return a freshly malloced string, containing a fingerprint
 * in either sha1 or md5 */
static char * sign_key_fingerprint(unsigned char* keyblob, unsigned int keybloblen) {

#ifdef DROPBEAR_MD5_HMAC
	return sign_key_md5_fingerprint(keyblob, keybloblen);
#else
	return sign_key_sha1_fingerprint(keyblob, keybloblen);
#endif
}

static void buf_put_sign(buffer* buf, sign_key *key, int type,
		const unsigned char *data, unsigned int len) {

	buffer *sigblob;
	sigblob = buf_new(MAX_PUBKEY_SIZE);

#ifdef DROPBEAR_DSS
	if (type == DROPBEAR_SIGNKEY_DSS) {
		buf_put_dss_sign(sigblob, key->dsskey, data, len);
	}
#endif
#ifdef DROPBEAR_RSA
	if (type == DROPBEAR_SIGNKEY_RSA) {
		buf_put_rsa_sign(sigblob, key->rsakey, data, len);
	}
#endif
	if (sigblob->len == 0)
		dropbear_exit("Non-matching signing type");
	buf_setpos(sigblob, 0);
	buf_putstring(buf, (char *)buf_getptr(sigblob, sigblob->len), sigblob->len);

	buf_free(sigblob);

}

/* Return DROPBEAR_SUCCESS or DROPBEAR_FAILURE.
 * If FAILURE is returned, the position of
 * buf is undefined. If SUCCESS is returned, buf will be positioned after the
 * signature blob */
static int buf_verify(buffer * buf, sign_key *key, const unsigned char *data,
		unsigned int len) {

	unsigned int bloblen;
	char * ident = NULL;
	unsigned int identlen = 0;

	bloblen = buf_getint(buf);
	ident = buf_getstring(buf, &identlen);

#ifdef DROPBEAR_DSS
	if (bloblen == DSS_SIGNATURE_SIZE &&
			memcmp(ident, SSH_SIGNKEY_DSS, identlen) == 0) {
		m_free(ident);
		if (key->dsskey == NULL)
			dropbear_exit("No DSS key to verify signature");
		return buf_dss_verify(buf, key->dsskey, data, len);
	}
#endif

#ifdef DROPBEAR_RSA
	if (memcmp(ident, SSH_SIGNKEY_RSA, identlen) == 0) {
		m_free(ident);
		if (key->rsakey == NULL)
			dropbear_exit("No RSA key to verify signature");
		return buf_rsa_verify(buf, key->rsakey, data, len);
	}
#endif

	m_free(ident);
	dropbear_exit("Non-matching signing type");
	return DROPBEAR_FAILURE;
}

/* Returns DROPBEAR_SUCCESS or DROPBEAR_FAILURE when given a buffer containing
 * a key, a key, and a type. The buffer is positioned at the start of the
 * base64 data, and contains no trailing data */
/* If fingerprint is non-NULL, it will be set to a malloc()ed fingerprint
   of the key if it is successfully decoded */
static int cmp_base64_key(const unsigned char* keyblob, unsigned int keybloblen,
					const char* algoname, unsigned int algolen,
					buffer * line, char ** fingerprint) {

	buffer * decodekey = NULL;
	int ret = DROPBEAR_FAILURE;
	unsigned int len, filealgolen;
	unsigned long decodekeylen;
	unsigned char* filealgo = NULL;

	/* now we have the actual data */
	len = line->len - line->pos;
	decodekeylen = len * 2; /* big to be safe */
	decodekey = buf_new(decodekeylen);

	if (base64_decode(buf_getptr(line, len), len,
				buf_getwriteptr(decodekey, decodekey->size),
				&decodekeylen) != CRYPT_OK) {
		goto out;
	}
	buf_incrlen(decodekey, decodekeylen);

	if (fingerprint) {
		*fingerprint = sign_key_fingerprint(buf_getptr(decodekey, decodekeylen),
											decodekeylen);
	}

	/* compare the keys */
	if ( ( decodekeylen != keybloblen )
			|| memcmp( buf_getptr(decodekey, decodekey->len),
						keyblob, decodekey->len) != 0) {
		goto out;
	}

	/* ... and also check that the algo specified and the algo in the key
	 * itself match */
	filealgolen = buf_getint(decodekey);
	filealgo = buf_getptr(decodekey, filealgolen);
	if (filealgolen != algolen || memcmp(filealgo, algoname, algolen) != 0) {
		goto out;
	}

	/* All checks passed */
	ret = DROPBEAR_SUCCESS;

out:
	buf_free(decodekey);
	decodekey = NULL;
	return ret;
}

#ifdef DROPBEAR_TCP_ACCEPT
static void cleanup_tcp(struct Listener *listener) {

	struct TCPListener *tcpinfo = (struct TCPListener*)(listener->typedata);

	m_free(tcpinfo->sendaddr);
	m_free(tcpinfo->listenaddr);
	m_free(tcpinfo);
}

static void tcp_acceptor(struct Listener *listener, int sock) {

	int fd;
	struct sockaddr_storage addr;
	socklen_t len;
	char ipstring[NI_MAXHOST], portstring[NI_MAXSERV];
	struct TCPListener *tcpinfo = (struct TCPListener*)(listener->typedata);

	len = sizeof(addr);

	fd = accept(sock, (struct sockaddr*)&addr, &len);
	if (fd < 0) {
		return;
	}

	if (getnameinfo((struct sockaddr*)&addr, len, ipstring, sizeof(ipstring),
				portstring, sizeof(portstring),
				NI_NUMERICHOST | NI_NUMERICSERV) != 0) {
		m_close(fd);
		return;
	}

	if (send_msg_channel_open_init(fd, tcpinfo->chantype) == DROPBEAR_SUCCESS) {
		char* addr = NULL;
		unsigned int port = 0;

		if (tcpinfo->tcp_type == direct) {
			/* "direct-tcpip" */
			/* host to connect, port to connect */
			addr = tcpinfo->sendaddr;
			port = tcpinfo->sendport;
		} else {
			dropbear_assert(tcpinfo->tcp_type == forwarded);
			/* "forwarded-tcpip" */
			/* address that was connected, port that was connected */
			addr = tcpinfo->listenaddr;
			port = tcpinfo->listenport;
		}

		if (addr == NULL)
			addr = "localhost";
		buf_putstring(ses.writepayload, addr, strlen(addr));
		buf_putint(ses.writepayload, port);

		/* originator ip */
		buf_putstring(ses.writepayload, ipstring, strlen(ipstring));
		/* originator port */
		buf_putint(ses.writepayload, atol(portstring));

		encrypt_packet();

	} else {
		/* XXX debug? */
		close(fd);
	}
}

static int listen_tcpfwd(struct TCPListener* tcpinfo) {

	char portstring[NI_MAXSERV];
	int socks[DROPBEAR_MAX_SOCKS];
	struct Listener *listener = NULL;
	int nsocks;
	char* errstring = NULL;

	/* first we try to bind, so don't need to do so much cleanup on failure */
	snprintf(portstring, sizeof(portstring), "%d", tcpinfo->listenport);

	nsocks = dropbear_listen(tcpinfo->listenaddr, portstring, socks,
			DROPBEAR_MAX_SOCKS, &errstring, &ses.maxfd);
	if (nsocks < 0) {
		dropbear_log("TCP forward failed: %s", errstring);
		m_free(errstring);
		return DROPBEAR_FAILURE;
	}
	m_free(errstring);

	/* new_listener will close the socks if it fails */
	listener = new_listener(socks, nsocks, CHANNEL_ID_TCPFORWARDED, tcpinfo,
			tcp_acceptor, cleanup_tcp);

	if (listener == NULL)
		return DROPBEAR_FAILURE;

	return DROPBEAR_SUCCESS;
}
#endif /* DROPBEAR_TCP_ACCEPT */


static void cli_dropbear_exit(int exitcode, const char* format, va_list param) {

	char fmtbuf[300];

	if (!sessinitdone) {
		snprintf(fmtbuf, sizeof(fmtbuf), "Exited: %s",
				format);
	} else {
		snprintf(fmtbuf, sizeof(fmtbuf),
				"Connection to %s@%s:%s exited: %s",
				cli_opts.username, cli_opts.remotehost,
				cli_opts.remoteport, format);
	}

	/* Do the cleanup first, since then the terminal will be reset */
	cli_session_cleanup();
	common_session_cleanup();

	cli_dropbear_log(fmtbuf, param);

	exit(exitcode);
}

int main(int argc, char ** argv) {
	int sock_in, sock_out;
	char* error = NULL;

	disallow_core();

	cli_getopts(argc, argv);

	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
		dropbear_exit("signal() error");
	sock_in = connect_remote(cli_opts.remotehost, cli_opts.remoteport,
				0, &error);
	if (sock_in < 0)
		dropbear_exit("%s", error);
	sock_out = sock_in;

	cli_session(sock_in, sock_out);

	/* not reached */
	return -1;
}
