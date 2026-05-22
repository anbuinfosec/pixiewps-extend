/*
 * wps_protocol.h - Enhanced WPS protocol handling with modern router support
 * Fixes: wpa_supplicant failures, insufficient data issues, multi-protocol negotiation
 * Copyright (c) 2026, @anbuinfosec
 * SPDX-License-Identifier: GPL-3.0+
 */

#ifndef WPS_PROTOCOL_H
#define WPS_PROTOCOL_H

#include <stdint.h>

/* WPS State Machine States */
#define WPS_STATE_INIT             0
#define WPS_STATE_EAPOL_START      1
#define WPS_STATE_IDENTITY_REQ     2
#define WPS_STATE_M1_RECEIVED      3
#define WPS_STATE_M2_SENT          4
#define WPS_STATE_M3_RECEIVED      5
#define WPS_STATE_M4_SENT          6
#define WPS_STATE_WSC_NACK         7
#define WPS_STATE_COMPLETE         8
#define WPS_STATE_FAILED           9

/* WPS Message Types */
#define WPS_MSG_M1                 0x04
#define WPS_MSG_M2                 0x05
#define WPS_MSG_M3                 0x07
#define WPS_MSG_M4                 0x08
#define WPS_MSG_M5                 0x09
#define WPS_MSG_M6                 0x0A
#define WPS_MSG_M7                 0x0B
#define WPS_MSG_M8                 0x0C
#define WPS_MSG_ACK                0x0D
#define WPS_MSG_NACK               0x0E
#define WPS_MSG_DONE               0x0F

/* WPS Attributes */
#define WPS_ATTR_AUTHENTICATOR     0x1005
#define WPS_ATTR_E_HASH1           0x1014
#define WPS_ATTR_E_HASH2           0x1015
#define WPS_ATTR_E_NONCE           0x1018
#define WPS_ATTR_ENCR_SETTINGS     0x1018
#define WPS_ATTR_AUTH_TYPE         0x1003
#define WPS_ATTR_ENCR_TYPE         0x100F
#define WPS_ATTR_MESSAGE_TYPE      0x104A
#define WPS_ATTR_NETWORK_KEY       0x1027
#define WPS_ATTR_NETWORK_KEY_INDEX 0x1028
#define WPS_ATTR_OS_VERSION        0x102D
#define WPS_ATTR_POWER_LEVEL       0x102C
#define WPS_ATTR_PUBLIC_KEY        0x1023
#define WPS_ATTR_REGISTRAR_NONCE   0x1039
#define WPS_ATTR_VERSION           0x104A

/* WPS Protocol Issues */
#define WPS_ISSUE_WEAK_SEED        (1 << 0)   /* Weak random seed */
#define WPS_ISSUE_PREDICTABLE_PIN  (1 << 1)   /* Predictable PIN derivation */
#define WPS_ISSUE_TIMING_LEAK      (1 << 2)   /* Timing-based seed leak */
#define WPS_ISSUE_E_NONCE_REUSE    (1 << 3)   /* E-Nonce reused */
#define WPS_ISSUE_R_NONCE_REUSE    (1 << 4)   /* R-Nonce reused */
#define WPS_ISSUE_AUTHKEY_ENTROPY   (1 << 5)   /* AuthKey low entropy */
#define WPS_ISSUE_NO_PIXIEDUST      (1 << 6)   /* Missing Pixie Dust markers */
#define WPS_ISSUE_INCOMPLETE_M1    (1 << 7)   /* Incomplete M1 message */

/* Enhanced WPS Session */
struct wps_session_enhanced {
	uint8_t state;                /* Current state machine state */
	
	/* Connection info */
	uint8_t bssid[6];
	uint8_t client_mac[6];
	char ssid[33];
	uint8_t channel;
	
	/* EAPOL/WPS negotiation */
	uint8_t eapol_start_count;    /* How many EAPOL Start sent */
	uint8_t max_eapol_start;      /* Router's max expected (1-3) */
	uint32_t eapol_failures;      /* EAPOL failure count */
	
	/* WPS Messages */
	uint8_t m1_buffer[512];
	uint16_t m1_len;
	uint8_t m1_complete;          /* Has all required attributes */
	
	uint8_t m3_buffer[512];
	uint16_t m3_len;
	uint8_t m3_complete;
	
	/* Critical data */
	uint8_t e_nonce[16];
	uint8_t r_nonce[16];
	uint8_t pke[192];
	uint8_t pkr[192];
	uint8_t authkey[32];
	uint8_t e_hash1[32];
	uint8_t e_hash2[32];
	
	/* Pixel Dust indicators */
	uint32_t pixiedust_score;     /* 0-100 confidence */
	uint32_t detected_issues;     /* Bitmask of issues */
	
	/* Retry logic */
	uint8_t m1_retry_count;
	uint8_t m3_retry_count;
	uint32_t last_error_code;
	
	/* Timing info */
	uint64_t m1_timestamp_ms;
	uint64_t m3_timestamp_ms;
	uint32_t time_delta_ms;
	
	/* PIN recovery candidates */
	uint32_t pin_candidates[50];
	uint32_t pin_count;
	uint32_t pin_attempts;
};

/* wpa_supplicant Interaction */
struct wpas_state {
	char state_file[256];         /* State file path */
	char ctrl_interface[256];     /* Control interface path */
	uint8_t wpas_running;
	uint8_t wpas_version_major;
	uint8_t wpas_version_minor;
	uint8_t supports_wps_pbc;
	uint8_t supports_wps_pin;
	uint8_t last_wpas_error;
	char last_error_msg[128];
};

/* Function prototypes */

/* Session Management */
struct wps_session_enhanced *wps_session_enhanced_init(const uint8_t *bssid,
                                                       const char *ssid);
void wps_session_enhanced_free(struct wps_session_enhanced *sess);
int wps_session_reset(struct wps_session_enhanced *sess);

/* EAPOL Start Handling */
int wps_send_eapol_start(struct wps_session_enhanced *sess, 
                        const char *interface);
int wps_handle_eapol_start_failure(struct wps_session_enhanced *sess);
int wps_get_router_eapol_requirement(const uint8_t *bssid);

/* Message Parsing */
int wps_parse_m1_enhanced(struct wps_session_enhanced *sess, 
                         const uint8_t *frame, uint16_t frame_len);
int wps_parse_m3_enhanced(struct wps_session_enhanced *sess,
                         const uint8_t *frame, uint16_t frame_len);
int wps_validate_message_completeness(struct wps_session_enhanced *sess,
                                     uint8_t msg_type);

/* Pixie Dust Analysis */
int wps_analyze_pixiedust_indicators(struct wps_session_enhanced *sess);
uint32_t wps_calculate_pixiedust_score(struct wps_session_enhanced *sess);
int wps_has_sufficient_data(struct wps_session_enhanced *sess);
uint32_t wps_get_required_attributes(uint8_t msg_type);
int wps_check_attribute_completeness(const uint8_t *msg, uint16_t msg_len,
                                    uint32_t required_mask);

/* Issue Detection */
uint32_t wps_detect_protocol_issues(struct wps_session_enhanced *sess);
int wps_check_nonce_reuse(struct wps_session_enhanced *sess);
int wps_check_authkey_entropy(struct wps_session_enhanced *sess);
int wps_detect_weak_seed_indicators(struct wps_session_enhanced *sess);

/* wpa_supplicant Integration */
struct wpas_state *wpas_init(void);
void wpas_free(struct wpas_state *state);
int wpas_start(struct wpas_state *state, const char *interface);
int wpas_stop(struct wpas_state *state);
int wpas_try_wps_pin(struct wpas_state *state, const uint8_t *bssid,
                    uint32_t pin);
int wpas_try_wps_pbc(struct wpas_state *state, const uint8_t *bssid);
int wpas_get_state(struct wpas_state *state, char *state_buf, size_t len);
int wpas_check_wps_fail(struct wpas_state *state);
int wpas_recover_from_failure(struct wpas_state *state);
int wpas_get_version(struct wpas_state *state, uint8_t *major, uint8_t *minor);

/* Error Recovery */
int wps_recover_insufficient_data(struct wps_session_enhanced *sess,
                                  const char *interface);
int wps_fallback_to_alternative_method(struct wps_session_enhanced *sess);
int wps_retry_with_different_timing(struct wps_session_enhanced *sess);
int wps_attempt_m1_recovery(struct wps_session_enhanced *sess,
                           const char *interface);

/* PIN Extraction with Fallback */
int wps_extract_pin_with_fuzzy_matching(struct wps_session_enhanced *sess,
                                       uint32_t *pin);
int wps_extract_pin_from_timing(struct wps_session_enhanced *sess,
                               uint32_t *pin);
int wps_extract_pin_from_entropy_pool(struct wps_session_enhanced *sess,
                                     uint32_t *pin_candidates,
                                     uint32_t *count);

/* Message Construction */
int wps_construct_m2(struct wps_session_enhanced *sess,
                    uint8_t *m2_buffer, uint16_t *m2_len);
int wps_construct_m4(struct wps_session_enhanced *sess,
                    uint8_t *m4_buffer, uint16_t *m4_len);
int wps_construct_eapol_start_enhanced(struct wps_session_enhanced *sess,
                                       uint8_t *eapol_buf, uint16_t *buf_len);

/* Attribute Parsing */
int wps_get_attribute(const uint8_t *msg, uint16_t msg_len,
                     uint16_t attr_type, uint8_t *attr_data,
                     uint16_t *attr_len);
int wps_set_attribute(uint8_t *msg, uint16_t *msg_len,
                     uint16_t attr_type, const uint8_t *attr_data,
                     uint16_t attr_len);

/* Debugging/Logging */
void wps_print_session_state(struct wps_session_enhanced *sess);
void wps_print_detected_issues(uint32_t issues_mask);
void wps_print_pixiedust_indicators(struct wps_session_enhanced *sess);
void wps_dump_m1_attributes(struct wps_session_enhanced *sess);
void wps_dump_m3_attributes(struct wps_session_enhanced *sess);

/* ===== STATIC PKE VULNERABILITY (Real-World) ===== */

/**
 * Detect if ephemeral key (PKE) is static (cached across sessions)
 * Static PKE = CRITICAL vulnerability, PIN derivable from key alone
 */
int wps_detect_static_ephemeral_key(const uint8_t *pke1, const uint8_t *pke2,
                                   uint16_t pke_len);

/**
 * Extract PIN candidates from static/weak PKE
 * Returns number of PIN candidates generated
 */
uint32_t wps_extract_pins_from_static_pke(const uint8_t *pke, const uint8_t *pkr,
                                          uint32_t *pin_candidates, uint32_t max_count);

/**
 * Analyze PKE entropy for weak PRNG indicators
 * Returns entropy score (0-255)
 */
uint8_t wps_analyze_pke_entropy(const uint8_t *pke);

/**
 * Check for PKE reuse patterns indicating weak RNG
 */
int wps_detect_pke_weak_patterns(const uint8_t *pke);

#endif /* WPS_PROTOCOL_H */
