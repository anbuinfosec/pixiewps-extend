/*
 * pmkid_capture.h - PMKID collection and WPA3 transition analysis
 * Copyright (c) 2026, @anbuinfosec
 * SPDX-License-Identifier: GPL-3.0+
 */

#ifndef PMKID_CAPTURE_H
#define PMKID_CAPTURE_H

#include <stdint.h>
#include <time.h>

/* PMKID Constants */
#define PMKID_LEN                16
#define PMKID_MAX_RECORDS        512
#define PMKID_TIMEOUT_SEC        300

/* PMK Hash Modes */
#define PMK_MODE_PBKDF2          1  /* WPA2 */
#define PMK_MODE_SALTY           2  /* WPA3 transition */
#define PMK_MODE_SAE             3  /* WPA3 pure */
#define PMK_MODE_OWE             4  /* OWE */
#define PMK_MODE_DPP             5  /* DPP */

/* PMKID Record */
struct pmkid_record {
	uint8_t pmkid[PMKID_LEN];
	uint8_t bssid[6];
	uint8_t client_mac[6];
	uint8_t ssid[33];
	uint8_t ssid_len;
	uint8_t pmk_mode;            /* WPA2, WPA3, OWE, etc */
	uint8_t wpa_version;         /* 2 or 3 */
	uint32_t priority_score;
	time_t captured_at;
	uint8_t is_valid;
	uint8_t export_status;       /* 0=not exported, 1=hc22000, 2=pcapng */
};

/* WPA3 Transition Detection */
struct wpa3_transition_record {
	uint8_t bssid[6];
	uint8_t ssid[33];
	uint8_t ssid_len;
	uint8_t has_wpa2;
	uint8_t has_wpa3;
	uint8_t sae_groups;          /* Bitmask for SAE groups */
	uint8_t pmf_required;
	uint32_t transition_score;
	time_t discovered_at;
};

/* PMKID Cache Engine */
struct pmkid_engine {
	struct pmkid_record *records;
	uint32_t record_count;
	uint32_t max_records;
	
	struct wpa3_transition_record *transitions;
	uint32_t transition_count;
	uint32_t max_transitions;
	
	uint8_t auto_export;
	char export_path[256];
	uint8_t capturing;
	time_t last_cleanup;
};

/* Function prototypes */

/* Engine management */
struct pmkid_engine *pmkid_engine_init(void);
void pmkid_engine_free(struct pmkid_engine *engine);

/* PMKID Capture */
int pmkid_add_record(struct pmkid_engine *engine, const uint8_t *pmkid,
                    const uint8_t *bssid, const uint8_t *client_mac,
                    const uint8_t *ssid, uint8_t ssid_len);
int pmkid_start_capture(struct pmkid_engine *engine, const char *interface);
int pmkid_stop_capture(struct pmkid_engine *engine);
int pmkid_process_frame(struct pmkid_engine *engine, const uint8_t *frame,
                       uint16_t frame_len);

/* PMKID Search and Management */
struct pmkid_record *pmkid_find_by_bssid(struct pmkid_engine *engine,
                                        const uint8_t *bssid);
struct pmkid_record *pmkid_get_best_target(struct pmkid_engine *engine);
int pmkid_verify_record(struct pmkid_record *record);
void pmkid_update_priority(struct pmkid_record *record);

/* WPA3 Transition Detection */
int pmkid_detect_wpa3_transition(struct pmkid_engine *engine,
                                const uint8_t *bssid,
                                const uint8_t *ssid, uint8_t ssid_len,
                                uint8_t has_wpa2, uint8_t has_wpa3);
struct wpa3_transition_record *pmkid_find_transition(struct pmkid_engine *engine,
                                                    const uint8_t *bssid);
int pmkid_analyze_transitions(struct pmkid_engine *engine);

/* Export Functions */
int pmkid_export_hc22000(struct pmkid_engine *engine, const char *filename);
int pmkid_export_hashcat_format(struct pmkid_record *record, char *output_buf);
int pmkid_export_pcapng(struct pmkid_engine *engine, const char *filename);
int pmkid_export_json(struct pmkid_engine *engine, const char *filename);

/* Statistics and Reporting */
uint32_t pmkid_get_record_count(struct pmkid_engine *engine);
uint32_t pmkid_get_transition_count(struct pmkid_engine *engine);
uint32_t pmkid_get_exported_count(struct pmkid_engine *engine);
void pmkid_print_summary(struct pmkid_engine *engine);
void pmkid_print_transitions(struct pmkid_engine *engine);

/* Cleanup and Validation */
void pmkid_cleanup_expired(struct pmkid_engine *engine, uint32_t timeout_sec);
int pmkid_validate_all(struct pmkid_engine *engine);
void pmkid_mark_duplicates(struct pmkid_engine *engine);

/* Integration with other modules */
int pmkid_priority_from_ap_info(const uint8_t *bssid, uint8_t wps_enabled,
                               uint8_t pmf_required, int8_t signal_dbm);

#endif /* PMKID_CAPTURE_H */
