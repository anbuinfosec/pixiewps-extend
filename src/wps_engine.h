/*
 * wps_engine.h - Integrated WPS attack engine with Pixiewps, Reaver, Bully, OneShot
 * Copyright (c) 2026, @anbuinfosec
 * SPDX-License-Identifier: GPL-3.0+
 */

#ifndef WPS_ENGINE_H
#define WPS_ENGINE_H

#include <stdint.h>
#include <time.h>

/* WPS Attack Methods */
#define WPS_METHOD_PIXIEWPS       1  /* Pixie Dust attack */
#define WPS_METHOD_REAVER         2  /* Brute force PIN */
#define WPS_METHOD_BULLY          3  /* Pixie Dust variant */
#define WPS_METHOD_ONESHOT        4  /* Real-time Pixie Dust */
#define WPS_METHOD_HYBRID         5  /* Combined methods */

/* WPS Lock Detection */
#define WPS_LOCK_STATUS_UNKNOWN   0
#define WPS_LOCK_STATUS_UNLOCKED  1
#define WPS_LOCK_STATUS_LOCKED    2
#define WPS_LOCK_STATUS_TEMP_LOCK 3

/* WPS PRNG Types */
#define WPS_PRNG_RTL819X          1
#define WPS_PRNG_RALINK           2
#define WPS_PRNG_BROADCOM         3
#define WPS_PRNG_MEDIATEK         4
#define WPS_PRNG_QUALCOMM         5
#define WPS_PRNG_GENERIC          6

/* WPS Session State */
#define WPS_SESSION_IDLE          0
#define WPS_SESSION_PROBING       1
#define WPS_SESSION_RUNNING       2
#define WPS_SESSION_PAUSED        3
#define WPS_SESSION_SUCCESS       4
#define WPS_SESSION_FAILED        5
#define WPS_SESSION_LOCKED        6

/* WPS Vulnerability Scoring */
#define WPS_VULN_SCORE_CRITICAL   90  /* Very likely to succeed */
#define WPS_VULN_SCORE_HIGH       70  /* Likely to succeed */
#define WPS_VULN_SCORE_MEDIUM     50  /* May succeed */
#define WPS_VULN_SCORE_LOW        30  /* Unlikely */
#define WPS_VULN_SCORE_NONE       0   /* Not vulnerable */

/* WPS Attack Result */
struct wps_attack_result {
	uint8_t method_used;
	uint8_t success;
	char recovered_pin[9];
	char recovered_psk[65];
	char recovered_ssid[33];
	uint32_t attempts;
	uint32_t timeout_sec;
	time_t started_at;
	time_t completed_at;
	uint8_t lock_detected;
	uint8_t retry_available;
};

/* WPS Session */
struct wps_session {
	uint8_t bssid[6];
	char ssid[33];
	uint8_t ssid_len;
	uint8_t channel;
	uint8_t wps_version;         /* 1.0, 2.0 */
	uint8_t lock_status;
	uint8_t prng_type;
	
	uint8_t attack_method;
	uint8_t session_state;
	uint32_t vulnerability_score;
	
	/* Pixiewps specific data */
	uint8_t pke[192];            /* Public key */
	uint8_t pkr[192];
	uint8_t authkey[32];
	uint8_t e_hash1[32];
	uint8_t e_hash2[32];
	uint8_t e_nonce[16];
	uint8_t r_nonce[16];
	uint8_t e_bssid[6];
	
	struct wps_attack_result result;
	
	/* Retry logic */
	uint32_t retry_count;
	uint32_t max_retries;
	uint32_t retry_delay_sec;
	time_t last_attempt;
	time_t lock_until;  /* Timestamp when lock expires */
	
	/* Session resume */
	uint8_t resumable;
	char resume_token[256];
	time_t created_at;
};

/* WPS Engine */
struct wps_engine {
	struct wps_session *sessions;
	uint32_t session_count;
	uint32_t max_sessions;
	
	uint8_t auto_retry;
	uint8_t auto_method_select;
	uint8_t smart_delays;
	uint8_t lock_avoidance;
	
	time_t last_update;
};

/* Function prototypes */

/* Engine management */
struct wps_engine *wps_engine_init(void);
void wps_engine_free(struct wps_engine *engine);

/* Session management */
struct wps_session *wps_session_create(struct wps_engine *engine,
                                      const uint8_t *bssid,
                                      const char *ssid);
int wps_session_resume(struct wps_engine *engine, const char *resume_token,
                      struct wps_session **session);
void wps_session_free(struct wps_session *session);

/* Attack method selection */
uint8_t wps_select_best_method(struct wps_session *session);
uint8_t wps_detect_prng_type(struct wps_session *session);
int wps_check_vulnerability(struct wps_session *session);

/* Attack execution */
int wps_attack_pixiedust(struct wps_session *session);
int wps_attack_reaver(struct wps_session *session, const char *interface);
int wps_attack_bully(struct wps_session *session, const char *interface);
int wps_attack_oneshot(struct wps_session *session, const char *interface);
int wps_attack_hybrid(struct wps_session *session, const char *interface);

/* Lock detection and handling */
int wps_detect_lock(struct wps_session *session, const char *interface);
int wps_check_lock_status(struct wps_session *session);
uint32_t wps_get_lock_timeout(struct wps_session *session);
int wps_wait_for_lock_release(struct wps_session *session);
int wps_trigger_lock_recovery(struct wps_session *session);

/* Retry logic */
int wps_should_retry(struct wps_session *session);
int wps_execute_retry(struct wps_engine *engine, struct wps_session *session);
void wps_set_smart_delay(struct wps_session *session);
void wps_set_adaptive_timeout(struct wps_session *session);

/* Session resuming */
void wps_save_session(struct wps_session *session, const char *filename);
int wps_load_session(const char *filename, struct wps_session **session);
void wps_create_resume_token(struct wps_session *session);

/* Result handling */
int wps_process_result(struct wps_session *session,
                      struct wps_attack_result *result);
int wps_verify_credentials(const char *pin, const char *psk, const char *ssid);
void wps_save_result(struct wps_session *session, const char *filename);

/* Vulnerability assessment */
uint32_t wps_calculate_vulnerability_score(struct wps_session *session);
uint8_t wps_is_critical_vulnerability(struct wps_session *session);
const char *wps_get_vulnerability_reason(struct wps_session *session);

/* Integration with other tools */
int wps_call_external_pixiewps(struct wps_session *session);
int wps_call_external_reaver(struct wps_session *session, const char *interface);
int wps_call_external_bully(struct wps_session *session, const char *interface);
int wps_call_external_oneshot(struct wps_session *session, const char *interface);

/* Statistics and reporting */
void wps_print_session_info(struct wps_session *session);
void wps_print_attack_result(struct wps_attack_result *result);
uint32_t wps_get_total_attempts(struct wps_engine *engine);
uint32_t wps_get_successful_attacks(struct wps_engine *engine);

/* Cleanup */
void wps_cleanup_expired_sessions(struct wps_engine *engine, uint32_t timeout_sec);
void wps_cleanup_locked_sessions(struct wps_engine *engine);

#endif /* WPS_ENGINE_H */
