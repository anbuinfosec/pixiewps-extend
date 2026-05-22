/*
 * target_priority.h - Smart target prioritization engine
 * Copyright (c) 2026, @anbuinfosec
 * SPDX-License-Identifier: GPL-3.0+
 */

#ifndef TARGET_PRIORITY_H
#define TARGET_PRIORITY_H

#include <stdint.h>

/* Priority Scoring Factors */
#define SCORE_WPS_ENABLED           25
#define SCORE_PMF_DISABLED          15
#define SCORE_WEAK_ENCRYPTION       30
#define SCORE_HIGH_SIGNAL           20
#define SCORE_VULNERABLE_VENDOR     20
#define SCORE_PMKID_AVAILABLE       40
#define SCORE_HANDSHAKE_AVAILABLE   35
#define SCORE_MULTIPLE_CLIENTS      10
#define SCORE_ACTIVE_CLIENTS        15
#define SCORE_WPA3_AVAILABLE        50
#define SCORE_TRANSITION_MODE       45

/* Vulnerability Levels */
#define VULN_NONE                   0
#define VULN_LOW                    1
#define VULN_MEDIUM                 2
#define VULN_HIGH                   3
#define VULN_CRITICAL               4

/* Vendor Profiles with Known Vulnerabilities */
struct vendor_profile {
	const char *vendor_name;
	const char *model_patterns;  /* Comma-separated glob patterns */
	uint8_t vuln_level;
	const char *known_issues;
	uint8_t wps_common;          /* WPS commonly enabled */
	uint8_t weak_rng;            /* Known weak RNG */
	uint8_t default_creds;       /* Uses default credentials */
};

/* Target Priority Record */
struct target_priority {
	uint8_t bssid[6];
	char ssid[33];
	uint32_t priority_score;
	uint8_t vulnerability_level;
	
	/* Scoring components */
	uint16_t score_wps;
	uint16_t score_pmf;
	uint16_t score_encryption;
	uint16_t score_signal;
	uint16_t score_vendor;
	uint16_t score_pmkid;
	uint16_t score_handshake;
	uint16_t score_clients;
	uint16_t score_wpa3;
	
	/* Metadata */
	uint8_t attack_type;         /* WPS, Handshake, PMKID, etc */
	uint8_t estimated_time_sec;
	uint8_t success_probability;
	uint8_t est_handshake_captures;
	uint8_t is_transition_mode;
};

/* Priority Engine */
struct priority_engine {
	struct target_priority *targets;
	uint32_t target_count;
	uint32_t max_targets;
	
	struct vendor_profile *profiles;
	uint32_t profile_count;
};

/* Function prototypes */

/* Engine management */
struct priority_engine *priority_engine_init(void);
void priority_engine_free(struct priority_engine *engine);

/* Target Evaluation */
int priority_evaluate_target(struct priority_engine *engine,
                            const uint8_t *bssid, const char *ssid,
                            uint8_t wps_enabled, uint8_t pmf_required,
                            uint8_t encryption_type, int8_t signal_dbm,
                            uint32_t client_count);

/* Scoring Functions */
uint32_t priority_score_wps(uint8_t wps_enabled);
uint32_t priority_score_pmf(uint8_t pmf_required);
uint32_t priority_score_encryption(uint8_t encryption_type);
uint32_t priority_score_signal(int8_t signal_dbm);
uint32_t priority_score_vendor(const char *vendor_name);
uint32_t priority_score_pmkid_available(uint8_t available);
uint32_t priority_score_handshake_available(uint8_t available);
uint32_t priority_score_clients(uint32_t client_count);
uint32_t priority_score_wpa3(uint8_t wpa3_enabled);
uint32_t priority_score_transition(uint8_t is_transition);

/* Vulnerability Assessment */
uint8_t priority_assess_vendor_vulnerability(const char *vendor_name,
                                            const char *model_name);
uint8_t priority_assess_encryption_weakness(uint8_t encryption_type);
uint8_t priority_assess_pmf_risk(uint8_t pmf_required);

/* Attack Type Selection */
uint8_t priority_select_attack_type(struct target_priority *target);
uint32_t priority_estimate_attack_time(struct target_priority *target);
uint8_t priority_estimate_success_rate(struct target_priority *target);

/* Sorting and Ranking */
struct target_priority *priority_get_best_target(struct priority_engine *engine);
struct target_priority *priority_get_targets_by_score(struct priority_engine *engine,
                                                     struct target_priority **out,
                                                     uint32_t *out_count);
void priority_sort_targets(struct target_priority *targets, uint32_t count);

/* Reporting */
void priority_print_target(struct target_priority *target);
void priority_print_all_targets(struct priority_engine *engine);
void priority_print_scoring_breakdown(struct target_priority *target);

/* Database and Profiles */
void priority_init_vendor_profiles(struct priority_engine *engine);
struct vendor_profile *priority_find_vendor_profile(struct priority_engine *engine,
                                                   const char *vendor_name);
int priority_add_vendor_profile(struct priority_engine *engine,
                               struct vendor_profile *profile);

#endif /* TARGET_PRIORITY_H */
