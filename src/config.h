/*
 * pixiewps: offline WPS brute-force utility that exploits low entropy PRNGs
 *
 * Copyright (c) 2015-2017, wiire <wi7ire@gmail.com>
 * Modified by @anbuinfosec <anbuinfosec@gmail.com> - 2026
 * https://github.com/anbuinfosec/pixiewps-extended
 * SPDX-License-Identifier: GPL-3.0+
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */
#ifndef CONFIG_H
#define CONFIG_H

#define ENDIANNESS_PORTABLE_CONVERSION
#include "endianness.h"

#define sha256(i, l, d) sha256_full(i, l, d)
#define hmac_sha256(k, l, i, n, o) \
	hmac_sha256_full(k, l, i, n, o)

/* ARM-specific Performance Optimizations */
#if defined(__ARM_ARCH_8A__) || defined(__aarch64__)
	/* Enable NEON optimizations for ARMv8 */
	#define ARM_NEON_CAPABLE 1
#elif defined(__ARM_ARCH_7A__) || defined(__armv7l__)
	/* Enable NEON for ARMv7-A */
	#define ARM_NEON_CAPABLE 1
	#define ARM_V7_CAPABLE 1
#elif defined(__ARM_ARCH_6__)
	/* ARMv6 has VFP but limited SIMD */
	#define ARM_V6_CAPABLE 1
#endif

/* Memory optimization for low-RAM Termux environments */
#if defined(__TERMUX__) || defined(__ANDROID__)
	#define LOW_RAM_MODE 1
	/* Use smaller thread stacks on Android */
	#define MIN_THREAD_STACK (32 * 1024)
#else
	#define MIN_THREAD_STACK (64 * 1024)
#endif

/* Compiler builtins for ARM */
#if defined(__GNUC__)
	#define LIKELY(x) __builtin_expect(!!(x), 1)
	#define UNLIKELY(x) __builtin_expect(!!(x), 0)
	#define HOT_FUNCTION __attribute__((hot))
	#define COLD_FUNCTION __attribute__((cold))
	#define ALWAYS_INLINE __attribute__((always_inline)) inline
	#define RESTRICT __restrict__
#else
	#define LIKELY(x) (x)
	#define UNLIKELY(x) (x)
	#define HOT_FUNCTION
	#define COLD_FUNCTION
	#define ALWAYS_INLINE inline
	#define RESTRICT
#endif

#endif /* CONFIG_H */
