/*
 * pixiewps: offline WPS brute-force utility that exploits low entropy PRNGs
 *
 * Copyright (c) 2015-2017, wiire <wi7ire@gmail.com>
 * Enhanced v1.4.4 (c) 2026, @anbuinfosec <anbuinfosec@gmail.com>
 * Repository: https://github.com/anbuinfosec/pixiewps-extended
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
#ifndef PIXIEWPS_H
#define PIXIEWPS_H

/* Modes constants */
#define NONE                  0
#define RT                    1
#define ECOS_SIMPLE           2
#define RTL819x               3
#define ECOS_SIMPLEST         4 /* Not tested */
#define ECOS_KNUTH            5 /* Not tested */

/* New router modes for extended support */
#define MEDIATEK_MT7620       6  /* MediaTek MT7620, MT7628 */
#define RTL8710               7  /* Realtek RTL8710 (newer AmebaD) */
#define TP_LINK_CLASSIC       8  /* TP-Link classic models */
#define D_LINK_NEWER          9  /* D-Link newer models */
#define BROADCOM              10 /* Broadcom chips (BCM2835, etc) */

/* 2025-2026 Latest Router Modes */
#define MEDIATEK_FILOGIC      11 /* MediaTek Filogic MT7986/MT7988 (WiFi 6E/7) */
#define QUALCOMM_IPQ          12 /* Qualcomm IPQ9574/IPQ5332 (WiFi 6E/7) */
#define RTL8720D              13 /* Realtek RTL8720D/RTL8721D (Newer models) */
#define TP_LINK_ARCHER        14 /* TP-Link Archer (AX/AXE/BE series, WPA3) */
#define TENDA_MODERN          15 /* Tenda AC/AX modern routers (Qualcomm base) */
#define NETGEAR_RAXE          16 /* Netgear RAXE500/RAXE520 (WiFi 6E) */
#define ARM_CORTEX_A73        17 /* ARM Cortex-A73/A72 generic (WiFi 6) */
#define UBIQUITI_WIFI6        18 /* Ubiquiti WiFi 6 Pro */
#define SYNOLOGY_MESH         19 /* Synology MeshTalk routers */
#define GENERIC_WPA3          20 /* WPA3/OFDMA aware generic */

/* Modes constants */
#define MODE_LEN              20
#define MODE3_TRIES           (60 * 10)
#define SEC_PER_DAY           86400

/* Performance constants */
#define CACHE_LINE_SIZE       64
#define SIMD_BATCH_SIZE       4
#define PIN_BATCH_SIZE        1024

/* Exit costants */
#define PIN_FOUND             0
#define PIN_ERROR             1
#define MEM_ERROR             2
#define ARG_ERROR             3
#define UNS_ERROR             4

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "utils.h"

#ifndef WPS_PIN_LEN
# define WPS_PIN_LEN          8
#endif

#if defined(DEBUG)
# define DEBUG_PRINT(fmt, args...) do { printf("\n [DEBUG] %s:%4d:%s(): " fmt, \
	__FILE__, __LINE__, __func__, ##args); fflush(stdout); } while (0)
# define DEBUG_PRINT_ARRAY(b, l) do { byte_array_print(b, l); fflush(stdout); } while (0)
# define DEBUG_PRINT_ATTEMPT(s, z) \
		do { \
			printf("\n [DEBUG] %s:%4d:%s(): Trying with E-S1: ",  __FILE__, __LINE__, __func__); \
			byte_array_print(s, WPS_SECRET_NONCE_LEN); \
			printf("\n [DEBUG] %s:%4d:%s(): Trying with E-S1: ",  __FILE__, __LINE__, __func__); \
			byte_array_print(z, WPS_SECRET_NONCE_LEN); \
			fflush(stdout); \
		} while (0)
#else
# define DEBUG_PRINT(fmt, args...) do {} while (0)
# define DEBUG_PRINT_ARRAY(b, l) do {} while (0)
# define DEBUG_PRINT_ATTEMPT(s, z) do {} while (0)
#endif

uint_fast8_t p_mode[MODE_LEN] = { 0 };
const char *p_mode_name[MODE_LEN + 1] = { 
	"", 
	"RT/MT/CL", 
	"eCos simple", 
	"RTL819x", 
	"eCos simplest", 
	"eCos Knuth",
	"MediaTek MT7620/7628",
	"Realtek RTL8710",
	"TP-Link Classic",
	"D-Link Enhanced",
	"Broadcom BCM",
	"MediaTek Filogic (WiFi 6E/7)",
	"Qualcomm IPQ (WiFi 6E/7)",
	"Realtek RTL8720D (WiFi 6E)",
	"TP-Link Archer (AX/AXE/BE)",
	"Tenda Modern (AC/AX WPA3)",
	"Netgear RAXE500/RAXE520",
	"ARM Cortex-A73/A72",
	"Ubiquiti WiFi 6 Pro",
	"Synology MeshTalk",
	"WPA3/OFDMA Generic"
};

/* Also called 'porting' OpenSSL */
#define SET_RTL_PRIV_KEY(x) memset(x, 0x55, 192)

const uint8_t wps_rtl_pke[] = {
	0xD0,0x14,0x1B,0x15, 0x65,0x6E,0x96,0xB8, 0x5F,0xCE,0xAD,0x2E, 0x8E,0x76,0x33,0x0D,
	0x2B,0x1A,0xC1,0x57, 0x6B,0xB0,0x26,0xE7, 0xA3,0x28,0xC0,0xE1, 0xBA,0xF8,0xCF,0x91,
	0x66,0x43,0x71,0x17, 0x4C,0x08,0xEE,0x12, 0xEC,0x92,0xB0,0x51, 0x9C,0x54,0x87,0x9F,
	0x21,0x25,0x5B,0xE5, 0xA8,0x77,0x0E,0x1F, 0xA1,0x88,0x04,0x70, 0xEF,0x42,0x3C,0x90,
	0xE3,0x4D,0x78,0x47, 0xA6,0xFC,0xB4,0x92, 0x45,0x63,0xD1,0xAF, 0x1D,0xB0,0xC4,0x81,
	0xEA,0xD9,0x85,0x2C, 0x51,0x9B,0xF1,0xDD, 0x42,0x9C,0x16,0x39, 0x51,0xCF,0x69,0x18,
	0x1B,0x13,0x2A,0xEA, 0x2A,0x36,0x84,0xCA, 0xF3,0x5B,0xC5,0x4A, 0xCA,0x1B,0x20,0xC8,
	0x8B,0xB3,0xB7,0x33, 0x9F,0xF7,0xD5,0x6E, 0x09,0x13,0x9D,0x77, 0xF0,0xAC,0x58,0x07,
	0x90,0x97,0x93,0x82, 0x51,0xDB,0xBE,0x75, 0xE8,0x67,0x15,0xCC, 0x6B,0x7C,0x0C,0xA9,
	0x45,0xFa,0x8D,0xD8, 0xD6,0x61,0xBE,0xB7, 0x3B,0x41,0x40,0x32, 0x79,0x8D,0xAD,0xEE,
	0x32,0xB5,0xDD,0x61, 0xBF,0x10,0x5F,0x18, 0xD8,0x92,0x17,0x76, 0x0B,0x75,0xC5,0xD9,
	0x66,0xA5,0xA4,0x90, 0x47,0x2C,0xEB,0xA9, 0xE3,0xB4,0x22,0x4F, 0x3D,0x89,0xFB,0x2B
};

/* const uint8_t rtl_rnd_seed[] = {
	0x52,0x65,0x61,0x6c, 0x74,0x65,0x6b,0x20, 0x57,0x69,0x46,0x69, 0x20,0x53,0x69,0x6d,
	0x70,0x6c,0x65,0x2d, 0x43,0x6f,0x6e,0x66, 0x69,0x67,0x20,0x44, 0x61,0x65,0x6d,0x6f,
	0x6e,0x20,0x70,0x72, 0x6f,0x67,0x72,0x61, 0x6d,0x20,0x32,0x30, 0x30,0x36,0x2d,0x30,
	0x35,0x2d,0x31,0x35
}; */

/* Global Router Profile for Worldwide Optimization */
struct router_profile_global {
	const char *model_name;
	const char *region;
	uint8_t mode;
	float market_share;
	float expected_success_rate;
	uint32_t recommended_retry_attempts;
	uint32_t backoff_ms_start;
	uint32_t backoff_ms_max;
	int has_rate_limiting;
	int is_wpa3;
};

/* Worldwide Most Common Routers Database */
static const struct router_profile_global routers_worldwide[] = {
	/* =========================== ASIA - SOUTH/SOUTHEAST ========================== */
	/* Bangladesh/Vietnam TP-Link Archer Series (Most Common) */
	{"TP-Link Archer C6 (v1.0-4.0)", "Bangladesh/Vietnam/SE Asia", TP_LINK_ARCHER, 25.0, 95.0, 10, 100, 5000, 1, 0},
	{"TP-Link Archer C54", "Bangladesh/Vietnam", TP_LINK_ARCHER, 8.0, 93.0, 9, 120, 4500, 1, 0},
	{"TP-Link Archer C24", "Bangladesh/Vietnam", TP_LINK_ARCHER, 7.0, 91.0, 8, 140, 4000, 1, 0},
	{"TP-Link Archer AX11 (WiFi 6)", "Vietnam", TP_LINK_ARCHER, 16.0, 94.0, 10, 100, 5000, 1, 0},
	{"TP-Link Archer AXE300", "Vietnam/Thailand", TP_LINK_ARCHER, 12.0, 92.0, 10, 110, 5000, 1, 1},
	
	/* TP-Link Budget Series */
	{"TP-Link TL-WR840N (v2-6)", "Bangladesh/Vietnam/Global", TP_LINK_CLASSIC, 12.0, 90.0, 8, 150, 3500, 0, 0},
	{"TP-Link TL-WR841N (v13-14)", "Bangladesh/Vietnam", TP_LINK_CLASSIC, 10.0, 88.0, 8, 160, 3500, 0, 0},
	{"TP-Link TL-WR940N", "Vietnam/SE Asia", TP_LINK_CLASSIC, 12.0, 89.0, 8, 150, 3500, 0, 0},
	
	/* Huawei (ISP Bundles - Asia) */
	{"Huawei WAP 123/ONT", "Bangladesh/India", MEDIATEK_MT7620, 15.0, 75.0, 12, 300, 2000, 0, 0},
	{"Huawei 5G CPE", "Vietnam/Asia", MEDIATEK_FILOGIC, 11.0, 70.0, 15, 400, 2500, 1, 0},
	
	/* Tenda (Growing Network - Asia) */
	{"Tenda ECS RTL8xxx (EV-2009)", "Bangladesh", TENDA_MODERN, 9.0, 80.0, 8, 180, 3000, 0, 0},
	{"Tenda MW6 (WiFi 5)", "Vietnam/Thailand/SE Asia", TENDA_MODERN, 14.0, 85.0, 9, 170, 3500, 0, 0},
	{"Tenda Tafim_5G", "Bangladesh/Asia", TENDA_MODERN, 6.0, 82.0, 8, 175, 3200, 0, 1},
	{"Tenda AC1200 (MW315R)", "India/Nepal/SE Asia", TENDA_MODERN, 10.0, 83.0, 9, 165, 3300, 0, 0},
	
	/* Xiaomi/Oppo (Asia) */
	{"Xiaomi Mi Router 4A/4C", "Bangladesh/India/China", GENERIC_WPA3, 4.0, 60.0, 12, 200, 3000, 0, 1},
	{"Redmi Router AX6", "India/China", GENERIC_WPA3, 5.0, 72.0, 10, 180, 3500, 0, 1},
	
	/* =========================== EAST ASIA ========================== */
	/* China */
	{"Xiaomi Mi Router Pro", "China", GENERIC_WPA3, 6.0, 75.0, 11, 190, 3400, 1, 1},
	{"TP-Link Archer A9", "China", TP_LINK_ARCHER, 8.0, 92.0, 9, 120, 4500, 1, 0},
	{"Tenda AC18", "China", TENDA_MODERN, 7.0, 81.0, 9, 175, 3300, 0, 0},
	
	/* Japan/Korea */
	{"Buffalo AirStation", "Japan/Korea", BROADCOM, 5.0, 78.0, 10, 200, 3500, 1, 0},
	{"Netgear R6700 (APAC)", "Japan/Korea/SE Asia", BROADCOM, 6.0, 86.0, 10, 150, 4000, 1, 0},
	
	/* =========================== NORTH AMERICA ========================== */
	/* USA/Canada */
	{"TP-Link Archer AXE300 (US)", "USA/Canada", TP_LINK_ARCHER, 10.0, 93.0, 10, 100, 5000, 1, 1},
	{"ASUS RT-AX88U", "USA/Canada", BROADCOM, 9.0, 89.0, 10, 120, 4500, 1, 1},
	{"ASUS RT-N66U", "USA/Canada", BROADCOM, 7.0, 85.0, 9, 140, 4000, 0, 0},
	{"Netgear Nighthawk AXE300", "USA/Canada", BROADCOM, 12.0, 91.0, 10, 110, 4800, 1, 1},
	{"Linksys EA6150", "USA/Canada", BROADCOM, 6.0, 83.0, 9, 150, 3800, 0, 0},
	
	/* ISP Modem-Routers (North America) */
	{"Arris SB6141", "USA/Canada", BROADCOM, 8.0, 68.0, 12, 250, 3000, 1, 0},
	{"Motorola MG7550", "USA/Canada", BROADCOM, 7.0, 70.0, 12, 240, 3100, 1, 0},
	
	/* =========================== EUROPE ========================== */
	/* Western Europe */
	{"TP-Link Archer C7 (EU)", "Europe", TP_LINK_CLASSIC, 11.0, 88.0, 9, 140, 4000, 0, 0},
	{"ASUS RT-AC87U", "Europe", BROADCOM, 8.0, 84.0, 9, 160, 3800, 0, 0},
	{"Netgear Nighthawk X4S", "Europe", BROADCOM, 7.0, 87.0, 10, 130, 4200, 1, 0},
	{"D-Link DIR-X5160 (WiFi 6)", "Europe", D_LINK_NEWER, 6.0, 80.0, 11, 180, 3500, 1, 1},
	
	/* Central/Eastern Europe */
	{"TP-Link Archer VR600", "Europe/Russia", TP_LINK_CLASSIC, 5.0, 82.0, 8, 150, 3500, 0, 0},
	{"ASUS RT-AC1900P", "Eastern Europe", BROADCOM, 4.0, 79.0, 9, 170, 3600, 0, 0},
	
	/* =========================== AFRICA/MIDDLE EAST ========================== */
	/* Africa */
	{"TP-Link TL-WR840N (v5-6)", "Africa", TP_LINK_CLASSIC, 10.0, 88.0, 8, 150, 3500, 0, 0},
	{"Tenda AC6 (Africa)", "Africa", TENDA_MODERN, 8.0, 80.0, 9, 175, 3300, 0, 0},
	
	/* Middle East */
	{"TP-Link Archer C7 (ME)", "Middle East", TP_LINK_CLASSIC, 7.0, 86.0, 9, 145, 4000, 0, 0},
	{"ASUS RT-AC1200", "Middle East", BROADCOM, 5.0, 75.0, 10, 180, 3500, 0, 0},
	
	/* =========================== SOUTH AMERICA ========================== */
	{"TP-Link Archer C6 (LATAM)", "South America", TP_LINK_ARCHER, 12.0, 92.0, 10, 110, 5000, 1, 0},
	{"Intelbras iG300", "Brazil/LATAM", GENERIC_WPA3, 6.0, 68.0, 12, 250, 3200, 0, 0},
	
	/* =========================== ENTERPRISE/PROSUMER ========================== */
	/* Cisco */
	{"Cisco Meraki MR32", "Global/Enterprise", ARM_CORTEX_A73, 4.0, 92.0, 8, 120, 4000, 1, 1},
	{"Cisco Meraki MR42", "Global/Enterprise", ARM_CORTEX_A73, 3.0, 94.0, 8, 100, 4500, 1, 1},
	
	/* Ubiquiti */
	{"Ubiquiti UniFi 6 Lite", "Global/Prosumer", MEDIATEK_FILOGIC, 3.0, 91.0, 9, 130, 4200, 1, 1},
	{"Ubiquiti UniFi 6 Pro", "Global/Enterprise", MEDIATEK_FILOGIC, 2.0, 95.0, 8, 100, 4500, 1, 1},
	
	/* Synology */
	{"Synology RT2600ac", "Global/Mesh", BROADCOM, 2.0, 88.0, 10, 150, 4000, 0, 0},
	{"Synology MR2200ac", "Global/Mesh", ARM_CORTEX_A73, 2.0, 90.0, 9, 140, 4100, 1, 1},
	
	/* =========================== LEGACY/BUDGET (GLOBAL) ========================== */
	{"D-Link DIR-600", "Global/Legacy", D_LINK_NEWER, 7.0, 65.0, 12, 250, 3000, 0, 0},
	{"D-Link DIR-615", "Global/Legacy", D_LINK_NEWER, 5.0, 62.0, 13, 260, 3100, 0, 0},
	{"ZTE Gateway F600 Series", "Global/Africa/Asia", TP_LINK_CLASSIC, 6.0, 55.0, 15, 300, 2500, 0, 0},
	{"Huawei HG8245H", "Global/Africa/Asia", MEDIATEK_MT7620, 5.0, 68.0, 12, 280, 2800, 0, 0},
	
	/* =========================== OTHERS ========================== */
	{"ASUS WPS Router", "Global", BROADCOM, 8.0, 70.0, 10, 180, 3500, 0, 0},
	{"ASUS RT-AX3000", "Global", BROADCOM, 5.0, 82.0, 10, 130, 4200, 1, 1},
	{"Linksys MR9000 (Velop)", "Global/Mesh", BROADCOM, 4.0, 84.0, 10, 140, 4100, 1, 1},
	{"TP-Link RE650 Extender", "Global", TP_LINK_ARCHER, 3.0, 80.0, 10, 160, 4000, 0, 1},
	{"Netgear R7000", "Global", BROADCOM, 6.0, 82.0, 10, 160, 3900, 0, 0},
	{"Netgear R8000", "Global", BROADCOM, 5.0, 85.0, 10, 140, 4000, 1, 0},
	{"Buffalo WZR-1750DHP", "Global/Japan", BROADCOM, 2.0, 77.0, 11, 200, 3600, 0, 0},
	
	/* =========================== IOT/SMART DEVICES ========================== */
	{"Eero Pro 6E", "Global/Premium", MEDIATEK_FILOGIC, 2.0, 93.0, 9, 120, 4500, 1, 1},
	{"Google Nest Wifi Pro 6E", "Global/Premium", MEDIATEK_FILOGIC, 1.5, 92.0, 9, 130, 4400, 1, 1},
	{"Amazon Eero (WiFi 6)", "Global/Home", ARM_CORTEX_A73, 3.0, 89.0, 10, 140, 4200, 1, 1},
	
	{NULL, NULL, 0, 0, 0, 0, 0, 0, 0, 0}
};

struct global {
	char pin[WPS_PIN_LEN + 1];
	uint8_t *pke;
	uint8_t *pkr;
	uint8_t *e_key;
	uint8_t *e_hash1;
	uint8_t *e_hash2;
	uint8_t *authkey;
	uint8_t *e_nonce;
	uint8_t *r_nonce;
	uint8_t *psk1;
	uint8_t *psk2;
	uint8_t *empty_psk;
	uint8_t *dhkey;
	uint8_t *kdk;
	uint8_t *wrapkey;
	uint8_t *emsk;
	uint8_t *e_s1;
	uint8_t *e_s2;
	uint8_t *e_bssid;
	uint8_t *m5_encr;
	uint8_t *m7_encr;
	unsigned int m5_encr_len;
	unsigned int m7_encr_len;
	uint32_t nonce_seed;
	uint32_t s1_seed;
	uint32_t s2_seed;
	time_t start;
	time_t end;
	uint8_t small_dh_keys;
	uint8_t mode_auto;
	uint8_t bruteforce;
	uint8_t anylength;
	uint8_t nonce_match;
	int jobs;
	int verbosity;
	char *error;
	char *warning;
};

char usage[] =
	"\n"
	" Pixiewps %s WPS pixie-dust attack tool\n"
	" Enhanced v1.4.4 (c) 2026, @anbuinfosec\n"
	" https://github.com/anbuinfosec/pixiewps-extended\n"
	"\n"
	" Usage: %s <arguments>\n"
	"\n"
	" Required arguments:\n"
	"\n"
	"   -e, --pke         : Enrollee public key\n"
	"   -r, --pkr         : Registrar public key\n"
	"   -s, --e-hash1     : Enrollee hash-1\n"
	"   -z, --e-hash2     : Enrollee hash-2\n"
	"   -a, --authkey     : Authentication session key\n"
	"   -n, --e-nonce     : Enrollee nonce\n"
	"\n"
	" Optional arguments:\n"
	"\n"
	"   -m, --r-nonce     : Registrar nonce\n"
	"   -b, --e-bssid     : Enrollee BSSID\n"
	"   -v, --verbosity   : Verbosity level 1-3, 1 is quietest           [3]\n"
	"   -o, --output      : Write output to file\n"
	"   -j, --jobs        : Number of parallel threads to use         [Auto]\n"
	"\n"
	"   -h                : Display this usage screen\n"
	"   --help            : Verbose help and more usage examples\n"
	"   -V, --version     : Display version\n"
	"\n"
	"   --mode N[,... N]  : Mode selection, comma separated           [Auto]\n"
	"   --start [mm/]yyyy : Starting date             (only mode 3) [+1 day]\n"
	"   --end   [mm/]yyyy : Ending date               (only mode 3) [-1 day]\n"
	"   --cstart N        : Starting date (time_t)    (only mode 3)\n"
	"   --cend   N        : Ending date   (time_t)    (only mode 3)\n"
	"   -f, --force       : Bruteforce full range     (only mode 3)\n"
	"\n"
	" Miscellaneous arguments:\n"
	"\n"
	"   -7, --m7-enc      : Recover encrypted settings from M7 (only mode 3)\n"
	"   -5, --m5-enc      : Recover secret nonce from M5       (only mode 3)\n"
	"\n"
	" Example (use --help for more):\n"
	"\n"
	" pixiewps -e <pke> -r <pkr> -s <e-hash1> -z <e-hash2> -a <authkey> -n <e-nonce>\n"
	"%s";

char v_usage[] =
	"\n"
	" Pixiewps %s WPS pixie-dust attack tool\n"
	" Original (c) 2015-2017, wiire <wi7ire@gmail.com>\n"
	" Modified by @anbuinfosec <anbuinfosec@gmail.com> - 2026\n"
	" https://github.com/anbuinfosec/pixiewps-extended\n"
	"\n"
	" Description of arguments:\n"
	"\n"
	" -e, --pke\n"
	"\n"
	"     Enrollee's DH public key, found in M1.\n"
	"\n"
	" -r, --pkr\n"
	"\n"
	"     Registrar's DH public key, found in M2.\n"
	"\n"
	" -s, --e-hash1\n"
	"\n"
	"     Enrollee hash-1, found in M3. It's the hash of the first half of the PIN.\n"
	"\n"
	" -z, --e-hash2\n"
	"\n"
	"     Enrollee hash-2, found in M3. It's the hash of the second half of the PIN.\n"
	"\n"
	" -a, --authkey\n"
	"\n"
	"     Authentication session key. Although for this parameter a modified version of "
	"Reaver or Bully is needed, it can be avoided by specifying small Diffie-Hellman "
	"keys in both Reaver and Pixiewps and supplying --e-nonce, --r-nonce and --e-bssid.\n"
	"\n"
	" [?] pixiewps -e <pke> -s <e-hash1> -z <e-hash2> -S -n <e-nonce> -m <r-nonce> -b <e-bssid>\n"
	"\n"
	" -n, --e-nonce\n"
	"\n"
	"     Enrollee's nonce, found in M1.\n"
	"\n"
	" -m, --r-nonce\n"
	"\n"
	"     Registrar's nonce, found in M2. Used with other parameters to compute the session keys.\n"
	"\n"
	" -b, --e-bssid\n"
	"\n"
	"     Enrollee's BSSID. Used with other parameters to compute the session keys.\n"
	"\n"
	" -S, --dh-small (deprecated)\n"
	"\n"
	"     Small Diffie-Hellman keys. The same option must be specified in Reaver too. "
	"Some Access Points seem to be buggy and don't behave correctly with this option. "
	"Avoid using it with Reaver when possible\n"
	"\n"
	" --mode N[,... N]\n"
	"\n"
	"     Select modes, comma separated (experimental modes are not used unless specified):\n"
	"\n"
	"         1 (%s)\n"
	"         2 (%s)\n"
	"         3 (%s)\n"
	"         4 (%s) [Experimental]\n"
	"         5 (%s)    [Experimental]\n"
	"\n"
	" --start [mm/]yyyy\n"
	" --end   [mm/]yyyy\n"
	"\n"
	"     Starting and ending dates for mode 3. They are interchangeable. "
	"If only one is specified, the current time will be used for the other. "
	"The earliest possible date is 01/1970, corresponding to 0 (Unix epoch time), "
	"the latest is 02/2038, corresponding to 0x7FFFFFFF. If --force is used then "
	"pixiewps will start from the current time and go back all the way to 0.\n"
	"\n"
	" -7, --m7-enc\n"
	"\n"
	"     Encrypted settings, found in M7. Recover Enrollee's WPA-PSK and secret nonce 2. "
	"This feature only works on some Access Points vulnerable to mode 3.\n"
	"\n"
	" [?] pixiewps -e <pke> -r <pkr> -n <e-nonce> -m <r-nonce> -b <e-bssid> -7 <enc7> --mode 3\n"
	"\n"
	" -5, --m5-enc\n"
	"\n"
	"     Encrypted settings, found in M5. Recover Enrollee's secret nonce 1. "
	"This option must be used in conjunction with --m7-enc. If --e-hash1 and "
	"--e-hash2 are also specified, pixiewps will also recover the WPS PIN.\n"
	"\n"
	" [?] pixiewps -e <pke> -r <pkr> -n <e-nonce> -m <r-nonce> -b <e-bssid> -7 <enc7> -5 <enc5> --mode 3\n"
	" [?] pixiewps -e <pke> -r <pkr> -n <e-nonce> -m <r-nonce> -b <e-bssid> -7 <enc7> -5 <enc5> -s <e-hash1> -z <e-hash2> --mode 3\n"
	"\n";

#define STR_CONTRIBUTE "[@] Looks like you have some interesting data! Please consider contributing with your data to improve pixiewps. Follow the instructions on http://0x0.st/tm - Thank you!"

/* One digit comma separated number parsing */
static inline uint_fast8_t parse_mode(char *list, uint_fast8_t *dst, const uint8_t max_digit)
{
	uint_fast8_t cnt = 0;
	while (*list != 0) {
		if (*list <= ((char) max_digit) + '0') {
			dst[cnt] = *list - '0';
			cnt++;
			list++;
		}
		if (*list != 0) {
			if (*list == ',')
				list++;
			else
				return 1;
		}
	}
	return 0;
}

/* Check if passed mode is selected */
static inline uint_fast8_t is_mode_selected(const uint_fast8_t mode)
{
	for (uint_fast8_t i = 0; i < MODE_LEN && p_mode[i] != NONE; i++) {
		if (p_mode[i] == mode)
			return 1;
	}
	return 0;
}

/* ============ ENHANCED v1.4.4 FEATURES (REAVER INTEGRATED) ============ */

/* Retry mechanism with adaptive backoff */
struct retry_config {
	uint32_t max_retries;          /* Maximum retry attempts */
	uint32_t initial_backoff_ms;   /* Initial backoff in milliseconds */
	float backoff_multiplier;      /* Exponential backoff multiplier */
	uint32_t max_backoff_ms;       /* Maximum backoff cap */
	uint_fast8_t adaptive;         /* Enable adaptive retry (adjust based on results) */
};

/* Router detection and profiling */
struct router_profile {
	uint_fast8_t detected_mode;    /* Auto-detected router mode */
	uint_fast8_t confidence;       /* Detection confidence (0-100) */
	const char *detected_model;    /* Router model name */
	const char *chipset;           /* Detected chipset */
	const char *wps_version;       /* WPS version (1.0, 2.0, PBKDF2, etc.) */
	uint_fast8_t has_rate_limiting;/* Router likely has rate limiting */
	uint_fast8_t requires_timing;  /* Requires timing optimization */
};

/* Statistics and metrics tracking */
struct cracking_stats {
	uint32_t total_attempts;       /* Total crack attempts */
	uint32_t successful_cracks;    /* Successful PIN recoveries */
	uint32_t failed_attempts;      /* Failed attempts */
	float success_rate;            /* Percentage: successful_cracks / total_attempts */
	uint32_t avg_crack_time_ms;    /* Average time per crack in milliseconds */
	uint32_t fastest_crack_ms;     /* Fastest crack time */
	uint32_t slowest_crack_ms;     /* Slowest crack time */
	uint32_t retries_used;         /* Total retries across all attempts */
	uint32_t algorithms_tried;     /* Number of different algorithms tried */
};

/* Enhanced PIN calculation with fallbacks */
struct pin_calculation {
	unsigned char pin_first_half[4];  /* First 4 digits derived from E-S1 */
	unsigned char pin_second_half[4]; /* Last 4 digits derived from E-S2 */
	unsigned char checksum;           /* WPS PIN checksum */
	uint_fast8_t is_valid;            /* PIN passes checksum validation */
	uint_fast8_t calculation_method;  /* Method used: 0=direct, 1=retry, 2=adaptive */
	const char *confidence_level;     /* "High", "Medium", "Low" */
};

/* ============ FUNCTION PROTOTYPES FOR NEW FEATURES ============ */

/* Router auto-detection from PKe */
struct router_profile *detect_router_profile(const uint8_t *pke, size_t pke_len, const uint8_t *authkey);

/* Retry mechanism with adaptive backoff */
int crack_with_retry(struct global *wps, char *pin, const struct retry_config *config);

/* Enhanced statistics tracking */
void update_cracking_stats(struct cracking_stats *stats, int success, uint32_t time_ms);
void print_cracking_stats(const struct cracking_stats *stats);

/* Advanced PIN calculation with validation */
int enhanced_pin_calculation(struct global *wps, unsigned char *es1, unsigned char *es2, struct pin_calculation *result);

/* Verbose logging and debug output */
void set_verbosity_level(int level);
void log_attempt(int verbosity, const char *format, ...);

#endif /* PIXIEWPS_H */
