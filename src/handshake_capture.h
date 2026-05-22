/*
 * handshake_capture.h - WPA2/WPA3 EAPOL handshake capture for pixiewps-extend
 * Copyright (c) 2026, @anbuinfosec
 * SPDX-License-Identifier: GPL-3.0+
 */

#ifndef HANDSHAKE_CAPTURE_H
#define HANDSHAKE_CAPTURE_H

#include <stdint.h>
#include <time.h>

/* EAPOL Constants */
#define EAPOL_VERSION           1
#define EAPOL_TYPE_EAP          0
#define EAPOL_TYPE_START        1
#define EAPOL_TYPE_LOGOFF       2
#define EAPOL_TYPE_KEY          3
#define EAPOL_TYPE_ENCASF       4

#define WPA_KEY_DESC_VERSION_HMAC_MD5_ARC4    1
#define WPA_KEY_DESC_VERSION_HMAC_SHA1_AES    2
#define WPA_KEY_DESC_VERSION_AES_128_CMAC_AES_128 3

/* Key Info Flags */
#define WPA_KEY_INFO_KEY_TYPE       (1 << 0)
#define WPA_KEY_INFO_KEY_INDEX_MASK (3 << 1)
#define WPA_KEY_INFO_INSTALL        (1 << 6)
#define WPA_KEY_INFO_ACK            (1 << 7)
#define WPA_KEY_INFO_MIC            (1 << 8)
#define WPA_KEY_INFO_SECURE         (1 << 9)
#define WPA_KEY_INFO_ERROR          (1 << 10)
#define WPA_KEY_INFO_REQUEST        (1 << 11)
#define WPA_KEY_INFO_ENCRYPTED      (1 << 12)
#define WPA_KEY_INFO_SMK_MESSAGE    (1 << 13)

#define HANDSHAKE_MAX_RECORDS       1024
#define EAPOL_MAX_FRAME_LEN         512

/* EAPOL Header Structure */
struct eapol_header {
	uint8_t version;
	uint8_t type;
	uint16_t length;
} __attribute__((packed));

/* WPA Key Frame Structure */
struct wpa_key_frame {
	uint8_t type;
	uint16_t key_info;
	uint16_t key_len;
	uint8_t replay_counter[8];
	uint8_t key_nonce[32];
	uint8_t key_iv[16];
	uint8_t key_rsc[8];
	uint8_t reserved[8];
	uint8_t key_mic[16];
	uint16_t key_data_len;
	/* Key data follows */
} __attribute__((packed));

/* Handshake Record */
struct handshake_message {
	uint8_t message_number;  /* 1-4 */
	uint8_t frame_type;      /* EAPOL_TYPE_KEY */
	uint8_t key_desc_version;
	uint16_t key_info;
	uint16_t key_len;
	uint8_t replay_counter[8];
	uint8_t key_nonce[32];
	uint8_t key_iv[16];
	uint8_t key_rsc[8];
	uint8_t key_mic[16];
	uint16_t key_data_len;
	uint8_t key_data[256];
	time_t captured_at;
};

/* Complete Handshake Record */
struct handshake_record {
	uint8_t bssid[6];
	uint8_t client_mac[6];
	uint8_t ssid[33];
	uint8_t ssid_len;
	uint8_t wpa_version;     /* 1 for WPA, 2 for WPA2, 3 for WPA3 */
	uint8_t pairwise_cipher;
	uint8_t group_cipher;
	uint8_t akm_suite;       /* AKM: PSK, FT-PSK, SAE, OWE, etc */
	uint8_t pmf_capability;  /* 0=None, 1=Capable, 2=Required */
	
	struct handshake_message msg1;
	struct handshake_message msg2;
	struct handshake_message msg3;
	struct handshake_message msg4;
	
	uint8_t msg_mask;        /* Bitmask: bits 0-3 for messages 1-4 */
	uint8_t is_complete;     /* All 4 messages captured */
	uint8_t has_ftie;        /* Fast Roaming enabled */
	uint8_t has_mdie;        /* 802.11r */
	uint8_t has_otiie;       /* OWE Transition Info */
	
	time_t started_at;
	time_t completed_at;
	uint32_t timeout_seconds;
	uint32_t priority_score;  /* Higher = prioritize for cracking */
};

/* Handshake Capture Engine */
struct handshake_engine {
	struct handshake_record *records;
	uint32_t record_count;
	uint32_t max_records;
	uint8_t auto_deauth_enabled;
	uint16_t deauth_count;
	time_t last_deauth;
};

/* Function prototypes */

/* Engine management */
struct handshake_engine *handshake_engine_init(uint32_t max_records);
void handshake_engine_free(struct handshake_engine *engine);

/* Frame parsing */
int handshake_parse_eapol(const uint8_t *frame, uint16_t frame_len,
                          struct handshake_message *msg);
int handshake_parse_wpa_key(const uint8_t *key_data, uint16_t data_len,
                            struct wpa_key_frame *key_frame);

/* Handshake detection and recording */
int handshake_detect_message_number(const struct wpa_key_frame *key1,
                                    const struct wpa_key_frame *key2);
int handshake_add_message(struct handshake_engine *engine, const uint8_t *bssid,
                          const uint8_t *client_mac, const uint8_t *frame,
                          uint16_t frame_len);

/* Record management */
struct handshake_record *handshake_find_record(struct handshake_engine *engine,
                                              const uint8_t *bssid,
                                              const uint8_t *client_mac);
struct handshake_record *handshake_get_best_target(struct handshake_engine *engine);
void handshake_update_priority(struct handshake_record *record);
int handshake_is_complete(struct handshake_record *record);
int handshake_is_valid(struct handshake_record *record);

/* Export and verification */
int handshake_verify_mic(struct handshake_record *record, const uint8_t *pmk,
                        const uint8_t *ptk);
int handshake_export_pcap(struct handshake_engine *engine, const char *filename);
int handshake_export_hc22000(struct handshake_record *record, const char *filename);

/* Deauth assistance */
int handshake_send_deauth_burst(const uint8_t *interface, const uint8_t *bssid,
                               const uint8_t *client_mac, uint8_t count);
int handshake_monitor_for_reassoc(struct handshake_engine *engine,
                                 const uint8_t *bssid);

/* Timeout and cleanup */
void handshake_cleanup_expired(struct handshake_engine *engine, uint32_t timeout_sec);
void handshake_reset_record(struct handshake_record *record);

/* Statistics */
uint32_t handshake_get_complete_count(struct handshake_engine *engine);
uint32_t handshake_get_partial_count(struct handshake_engine *engine);
void handshake_print_stats(struct handshake_engine *engine);

#endif /* HANDSHAKE_CAPTURE_H */
