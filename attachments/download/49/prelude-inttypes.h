/*****
*
* Copyright (C) 2004, 2005 PreludeIDS Technologies. All Rights Reserved.
* Author: Yoann Vandoorselaere <yoann.v@prelude-ids.com>
*
* This file is part of the Prelude library.
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 2, or (at your option)
* any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; see the file COPYING.  If not, write to
* the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
*
*****/

#ifndef _LIBPRELUDE_INTTYPES_H
#define _LIBPRELUDE_INTTYPES_H

#ifdef __cplusplus
 extern "C" {
#endif

/*
 * Defined by ax_create_prelude_inttypes_h.m4
 */
#define __PRELUDE_HAVE_STDINT_H
#define __PRELUDE_HAVE_INTTYPES_H
/* #define __PRELUDE_HAVE_64BIT_LONG */
#define __PRELUDE_STDINT_HAVE_UINT8
#define __PRELUDE_STDINT_HAVE_UINT16
#define __PRELUDE_STDINT_HAVE_UINT32
#define __PRELUDE_STDINT_HAVE_UINT64


#ifdef __PRELUDE_HAVE_64BIT_LONG
 #define __PRELUDE_INT64_SUFFIX(x) x ## L
 #define __PRELUDE_UINT64_SUFFIX(x) x ## UL
#else
 #define __PRELUDE_INT64_SUFFIX(x) x ## LL
 #define __PRELUDE_UINT64_SUFFIX(x) x ##ULL
#endif

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef __PRELUDE_HAVE_STDINT_H
# include <stdint.h>
#endif

#ifdef __PRELUDE_HAVE_INTTYPES_H
# include <inttypes.h>
#endif


#ifndef TRUE
# define TRUE 1
#endif

#ifndef FALSE
# define FALSE 0
#endif



/*
 * Minimum of signed integral types.
 */
#define PRELUDE_INT8_MIN               (-128)
#define PRELUDE_INT16_MIN              (-32767 - 1)
#define PRELUDE_INT32_MIN              (-2147483647 - 1)
#define PRELUDE_INT64_MIN              (-__PRELUDE_INT64_SUFFIX(9223372036854775807) - 1)



/*
 * Maximum of signed integral types.
 */
#define PRELUDE_INT8_MAX               (127)
#define PRELUDE_INT16_MAX              (32767)
#define PRELUDE_INT32_MAX              (2147483647)
#define PRELUDE_INT64_MAX              (__PRELUDE_INT64_SUFFIX(9223372036854775807))


/*
 * Maximum of unsigned integral types.
 */
#define PRELUDE_UINT8_MAX              (255)
#define PRELUDE_UINT16_MAX             (65535)
#define PRELUDE_UINT32_MAX             (4294967295U)
#define PRELUDE_UINT64_MAX             (__PRELUDE_UINT64_SUFFIX(18446744073709551615))


/*
 * Other
 */
#define PRELUDE_INTMAX_MIN             INT64_MIN
#define PRELUDE_INTMAX_MAX             INT64_MAX
#define PRELUDE_UINTMAX_MAX            UINT64_MAX


/* 
 * Tandem NonStop R series and compatible platforms released before
 * July 2005 support %Ld but not %lld.  
 */
# if defined _TNS_R_TARGET
#  define _LONG_LONG_FORMAT_PREFIX "L"
# else
#  define _LONG_LONG_FORMAT_PREFIX "ll"
# endif

#if PRELUDE_INT64_MAX == LONG_MAX
# define __PRELUDE_64BIT_FORMAT_PREFIX "l"
#elif defined _MSC_VER || defined __MINGW32__
# define __PRELUDE_64BIT_FORMAT_PREFIX "I64"
#elif 1 && LONG_MAX >> 30 == 1
# define __PRELUDE_64BIT_FORMAT_PREFIX _LONG_LONG_FORMAT_PREFIX
#endif



/*
 * format specifier
 */
#define PRELUDE_PRId64      __PRELUDE_64BIT_FORMAT_PREFIX "d"
#define PRELUDE_PRIi64      __PRELUDE_64BIT_FORMAT_PREFIX "i"
#define PRELUDE_PRIo64      __PRELUDE_64BIT_FORMAT_PREFIX "o"
#define PRELUDE_PRIx64      __PRELUDE_64BIT_FORMAT_PREFIX "x"
#define PRELUDE_PRIX64      __PRELUDE_64BIT_FORMAT_PREFIX "X"
#define PRELUDE_PRIu64      __PRELUDE_64BIT_FORMAT_PREFIX "u"

#define PRELUDE_PRId32      "d"
#define PRELUDE_PRIi32      "i"
#define PRELUDE_PRIo32      "o"
#define PRELUDE_PRIx32      "x"
#define PRELUDE_PRIX32      "X"
#define PRELUDE_PRIu32      "u"

#define PRELUDE_PRId16      "d"
#define PRELUDE_PRIi16      "i"
#define PRELUDE_PRIo16      "o"
#define PRELUDE_PRIx16      "x"
#define PRELUDE_PRIX16      "X"
#define PRELUDE_PRIu16      "u"

#define PRELUDE_PRId8       "d"
#define PRELUDE_PRIi8       "i"
#define PRELUDE_PRIo8       "o"
#define PRELUDE_PRIx8       "x"
#define PRELUDE_PRIX8       "X"
#define PRELUDE_PRIu8       "u"

#define PRELUDE_SCNd64      __PRELUDE_64BIT_FORMAT_PREFIX "d"
#define PRELUDE_SCNi64      __PRELUDE_64BIT_FORMAT_PREFIX "i"
#define PRELUDE_SCNo64      __PRELUDE_64BIT_FORMAT_PREFIX "o"
#define PRELUDE_SCNx64      __PRELUDE_64BIT_FORMAT_PREFIX "x"
#define PRELUDE_SCNu64      __PRELUDE_64BIT_FORMAT_PREFIX "u"




/*
 * Type definition
 */
typedef enum { 
	PRELUDE_BOOL_TRUE = TRUE, 
	PRELUDE_BOOL_FALSE = FALSE 
} prelude_bool_t;


#ifndef __PRELUDE_STDINT_HAVE_UINT8
 typedef signed char int8_t;
 typedef unsigned char uint8_t;
#endif


#ifndef __PRELUDE_STDINT_HAVE_UINT16
 typedef short int16_t;
 typedef unsigned short uint16_t;
#endif

#ifndef __PRELUDE_STDINT_HAVE_UINT32
 typedef int int32_t;
 typedef unsigned int uint32_t;
#endif

#ifndef __PRELUDE_STDINT_HAVE_UINT64
# ifdef __PRELUDE_HAVE_64BIT_LONG

  typedef long int64_t;
  typedef unsigned long uint64_t;

# else

  typedef long long int64_t;
  typedef unsigned long long uint64_t;

# endif
#endif

#ifdef __cplusplus
 }
#endif

#endif /* _LIBPRELUDE_INTTYPES_H */
