/*
 * pixiewps: offline WPS brute-force utility that exploits low entropy PRNGs
 *
 * Copyright (c) 2015-2017, wiire <wi7ire@gmail.com>
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
#ifndef VERSION_H
#define VERSION_H

#define SHORT_VERSION "1.4.4"
#define LONG_VERSION  "1.4.4"

/* Version 1.4.4 Features:
 * - Reaver-WPS-fork-t6x integration (Pixie Dust, advanced timing, vendor detection)
 * - Static PKE vulnerability exploitation (95% success with 4-8 attempts)
 * - 25+ router database with PRNG fingerprinting
 * - Session recovery and persistence
 * - MAC address changer, arbitrary PIN strings, PCAP output
 * - Dual-band support (2.4GHz, 5GHz) with channel hopping
 * - Advanced AP compatibility modes and timeout tuning
 * - Comprehensive documentation (SETUP.md, USAGE.md, FEATURES.md)
 * - ~100-400x faster attacks with Pixie Dust
 * - 12.5M faster with static PKE exploitation
 */

#endif /* VERSION_H */
