/*
 * router_prng.h - Enhanced PRNG detection and support for modern routers
 * Supports: Acer, Tenda, TP-Link, Archer, Realtek variants, and more
 * Copyright (c) 2026, @anbuinfosec
 * SPDX-License-Identifier: GPL-3.0+
 */

#ifndef ROUTER_PRNG_H
#define ROUTER_PRNG_H

#include <stdint.h>
#include <time.h>

/* Modern Router PRNG Types */
#define PRNG_RTL819X          1   /* Realtek RTL8196C/RTL8197/RTL8198 */
#define PRNG_RTL819X_VARIANT  2   /* RTL8196E, RTL8199 variants */
#define PRNG_MEDIATEK_FILOGIC 3   /* MediaTek Filogic series */
#define PRNG_ACER_C60_C50     4   /* Acer C60/C50 (Qualcomm IPQ) */
#define PRNG_TENDA_NEW        5   /* Tenda latest generation */
#define PRNG_TP_LINK_MODERN   6   /* TP-Link Archer modern */
#define PRNG_QUALCOMM_IPQ     7   /* Qualcomm IPQ4018/IPQ4019/IPQ5018 */
#define PRNG_BROADCOM_BCM43   8   /* Broadcom BCM4318/BCM4330+ */
#define PRNG_RALINK_MT        9   /* Ralink/MediaTek MT variants */
#define PRNG_HISILICON_HI     10  /* HiSilicon Hi3881 (Huawei) */
#define PRNG_MARVELL_MV       11  /* Marvell Armada variants */
#define PRNG_ATHEROS_QCA      12  /* Atheros QCA9563/QCA8337 */
#define PRNG_AR9344_AR9331    13  /* TP-Link TL-WR841N v9+ */
#define PRNG_GENERIC          99  /* Fallback generic PRNG */

/* Vulnerability Levels */
#define VULN_CRITICAL         5   /* Pixie Dust highly likely */
#define VULN_HIGH             4   /* Pixie Dust possible */
#define VULN_MEDIUM           3   /* Weak RNG */
#define VULN_LOW              2   /* Strong RNG with minor issue */
#define VULN_NONE             1   /* No known vulnerability */

/* Router Model Database Entry */
struct router_model {
	const char *oui;              /* MAC OUI (e.g., "98:03:8E") */
	const char *model_name;       /* Acer C60, Tenda AC1200, etc */
	const char *vendor;           /* Acer, Tenda, TP-Link, etc */
	uint8_t prng_type;            /* PRNG algorithm ID */
	uint8_t vulnerability_level;
	const char *known_issues;     /* E.g., "weak_seed", "time_based" */
	uint8_t supports_pixiedust;
	uint8_t supports_eapol_start; /* Can send multiple EAPOL Start */
	uint8_t eapol_start_count;    /* How many to send (1-3) */
	uint8_t has_m1_cache;         /* Caches M1 with same seed */
	uint8_t retry_delay_ms;       /* Delay between retries */
	const char *special_handling; /* "skip_m2_validation", etc */
};

/* PRNG Context for Seed Generation */
struct prng_context {
	uint32_t seed;
	uint64_t timestamp;
	uint8_t mac[6];
	uint8_t nonce[16];
	uint8_t state[256];           /* For more complex PRNGs */
	uint32_t counter;
	uint8_t prng_type;
	uint8_t router_prng_type;
};

/* Enhanced PIN Calculation */
struct pin_calc_context {
	uint8_t prng_type;
	uint8_t router_prng_type;
	uint32_t current_pin;
	uint32_t pin_list[100];       /* Array of candidate PINs */
	uint32_t pin_count;
	uint32_t pin_position;
	
	/* Entropy sources */
	uint8_t e_nonce[16];
	uint8_t pke[192];
	uint8_t pkr[192];
	uint8_t authkey[32];
	
	/* Timing information */
	time_t m1_time;
	time_t m3_time;
	uint32_t time_delta_ms;
	
	/* Seed recovery */
	uint32_t recovered_seed;
	uint8_t seed_recovery_confidence;
};

/* Router Detection Result */
struct router_detection {
	uint8_t bssid[6];
	char ssid[33];
	uint8_t channel;
	char oui[9];                  /* OUI string: "XX:XX:XX" */
	uint8_t detected_prng_type;
	uint8_t vulnerability_level;
	struct router_model *matched_model;
	uint8_t confidence;           /* 0-100% */
	const char *detected_issues;
	uint8_t attack_recommendations;
};

/* Function prototypes */

/* Router Detection */
int router_detect_from_bssid(const uint8_t *bssid, struct router_detection *result);
int router_lookup_model(const char *oui, struct router_model **model);
int router_detect_prng_type(const uint8_t *pke, const uint8_t *pkr, 
                           const uint8_t *authkey);
const char *router_get_oui_string(const uint8_t *mac);

/* PRNG Generation */
uint32_t prng_generate_seed_rtl819x(uint8_t prng_type, const uint8_t *mac,
                                   time_t timestamp);
uint32_t prng_generate_seed_mediatek(uint8_t prng_type, const uint8_t *mac,
                                    time_t timestamp);
uint32_t prng_generate_seed_acer_c60(const uint8_t *mac, const uint8_t *nonce);
uint32_t prng_generate_seed_tenda_new(const uint8_t *mac, time_t timestamp);
uint32_t prng_generate_seed_qualcomm(const uint8_t *mac, const uint8_t *authkey);
uint32_t prng_generate_seed_broadcom(const uint8_t *mac, uint32_t timestamp_seed);

/* PIN Calculation - Model Specific */
int pin_calc_init(struct pin_calc_context *ctx, uint8_t router_prng_type);
int pin_calc_from_seed(struct pin_calc_context *ctx, uint32_t seed, 
                      uint32_t *pin);
int pin_calc_rtl819x_variant(const uint8_t *e_nonce, const uint8_t *pke,
                            uint32_t *pin_list, uint32_t *pin_count);
int pin_calc_acer_c60(const uint8_t *e_nonce, const uint8_t *authkey,
                     const uint8_t *mac, uint32_t *pin_list, 
                     uint32_t *pin_count);
int pin_calc_tenda_modern(const uint8_t *e_nonce, const uint8_t *e_hash1,
                         const uint8_t *e_hash2, uint32_t *pin_list,
                         uint32_t *pin_count);
int pin_calc_time_based(time_t m1_time, time_t m3_time, uint32_t *pin_list,
                       uint32_t *pin_count);

/* Seed Recovery */
uint32_t seed_recover_from_m1_m3_timing(const struct pin_calc_context *ctx);
uint32_t seed_recover_from_authkey_entropy(const uint8_t *authkey, 
                                          const uint8_t *pke);
int seed_brute_force_with_constraints(uint32_t known_bits, uint32_t bit_mask,
                                     uint32_t *seed_list, uint32_t *count);

/* Fuzzy Matching */
int router_fuzzy_match_model(const char *ssid, const uint8_t *bssid,
                            struct router_model **best_match);

/* Statistics and Heuristics */
int router_analyze_entropy(const uint8_t *pke, const uint8_t *pkr,
                          const uint8_t *authkey, uint8_t *entropy_estimate);
int router_detect_weak_rng_patterns(const uint8_t *nonce_list, uint32_t count);

/* Export/Logging */
void router_print_detection(struct router_detection *result);
void router_print_model_info(struct router_model *model);
void router_log_pin_candidates(uint32_t *pins, uint32_t count);

/* Database Management */
struct router_model *router_get_database(uint32_t *count);
int router_add_custom_model(struct router_model *model);

/* ===== STATIC KEY EXPLOITATION ===== */

/**
 * Detect if router uses static/cached ephemeral keys
 * This is a critical vulnerability found in some Broadcom/Realtek routers
 * Returns confidence level (0-100)
 */
uint8_t router_detect_static_key_vulnerability(const uint8_t *pke1, 
                                               const uint8_t *pke2,
                                               const uint8_t *pke3);

/**
 * Calculate PIN directly from static PKE without needing M3
 * Only possible when PKE is static (ephemeral key not changing)
 */
int router_calculate_pin_from_static_key(const uint8_t *pke, const uint8_t *bssid,
                                        uint32_t *pin_candidates, uint32_t *count);

/**
 * Add detected static key vulnerability to router model database
 */
int router_add_static_key_model(const char *oui, const char *model_name,
                               uint8_t vulnerability_level);

#endif /* ROUTER_PRNG_H */
