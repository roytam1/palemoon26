/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/* Various compiler checks. */

#ifndef mozilla_Compiler_h_
#define mozilla_Compiler_h_

#if !defined(__clang__) && defined(__GNUC__)

#define MOZ_IS_GCC 1
   /*
    * This macro should simplify gcc version checking. For example, to check
    * for gcc 4.6.0 or later, check `#ifdef MOZ_GCC_VERSION_AT_LEAST(4, 6, 0)`.
    */
#  define MOZ_GCC_VERSION_AT_LEAST(major, minor, patchlevel)          \
     ((__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__) \
      >= ((major) * 10000 + (minor) * 100 + (patchlevel)))
#if !MOZ_GCC_VERSION_AT_LEAST(4, 6, 0)
#  error "mfbt (and Goanna) require at least gcc 4.6 to build."
#endif

#else

#define MOZ_IS_GCC 0

#endif

#endif  /* mozilla_Compiler_h_ */
