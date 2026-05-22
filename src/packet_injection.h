/*
 * packet_injection.h - WiFi packet injection for pixiewps-extend
 * Copyright (c) 2026, @anbuinfosec
 * SPDX-License-Identifier: GPL-3.0+
 */

#ifndef PACKET_INJECTION_H
#define PACKET_INJECTION_H

#include <stdint.h>
#include <time.h>

/* 802.11 Frame Types */
#define FC_TYPE_MGMT        0x00
#define FC_SUBTYPE_DEAUTH   0xC0
#define FC_SUBTYPE_DISASSOC 0xA0
#define FC_SUBTYPE_AUTH     0x00
#define FC_SUBTYPE_BEACON   0x80
#define FC_SUBTYPE_PROBE_REQ 0x40
#define FC_SUBTYPE_PROBE_RSP 0x50
#define FC_SUBTYPE_ASSOC_REQ 0x00
#define FC_SUBTYPE_ASSOC_RSP 0x10
#define FC_SUBTYPE_REASSOC_REQ 0x20
#define FC_SUBTYPE_REASSOC_RSP 0x30

/* Frame Control Flags */
#define FC_TO_DS            (1 << 8)
#define FC_FROM_DS          (1 << 9)
#define FC_MORE_FRAG        (1 << 10)
#define FC_RETRY            (1 << 11)
#define FC_PWR_MGT           (1 << 12)
#define FC_MORE_DATA        (1 << 13)
#define FC_PROTECTED        (1 << 14)
#define FC_ORDER            (1 << 15)

/* Reason Codes */
#define REASON_UNSPECIFIED           1
#define REASON_PREV_AUTH_NOT_VALID   2
#define REASON_DEAUTH_LEAVING        3
#define REASON_DISASSOC_DUE_INACTIVITY 4
#define REASON_DISASSOC_AP_UNABLE   5
#define REASON_CLASS2_FRAME_FROM_NONAUTHC 6
#define REASON_CLASS3_FRAME_FROM_NONASSOC 7
#define REASON_DISASSOC_STA_LEFT     8
#define REASON_STA_REQ_ASSOC_WITHOUT_AUTH 9

/* Status Codes for Auth/Assoc */
#define STATUS_SUCCESS                  0
#define STATUS_UNSPECIFIED_FAILURE     1
#define STATUS_TDLS_WAKEUP_ALT_REASON  2
#define STATUS_SECURITY_DISABLED       5
#define STATUS_UNKNOWN_AUTH_ALG       13
#define STATUS_UNKNOWN_AUTH_TRANS_SEQ_NUM 14
#define STATUS_CHALLENGE_FAILURE      15
#define STATUS_AUTH_TIMEOUT           16
#define STATUS_AP_UNABLE_TO_HANDLE_NEW_STA 17
#define STATUS_ASSOC_DENIED_RATES     18

/* Radiotap Header */
struct radiotap_header {
	uint8_t version;
	uint8_t pad;
	uint16_t length;
	uint32_t present;
} __attribute__((packed));

/* 802.11 MAC Header */
struct mac_header {
	uint16_t frame_control;
	uint16_t duration;
	uint8_t addr1[6];
	uint8_t addr2[6];
	uint8_t addr3[6];
	uint16_t seq_ctrl;
	/* addr4 and QoS for extended frames */
} __attribute__((packed));

/* Management Frame Body */
struct mgmt_body {
	/* Auth/Beacon specific fields */
	uint16_t auth_alg;
	uint16_t auth_seq;
	uint16_t status_code;
	/* Timestamp, Beacon Interval, Capability Info for Beacon */
	uint8_t timestamp[8];
	uint16_t beacon_interval;
	uint16_t capability_info;
} __attribute__((packed));

/* Deauth Frame */
struct deauth_frame {
	struct mac_header hdr;
	uint16_t reason_code;
} __attribute__((packed));

/* Auth Frame */
struct auth_frame {
	struct mac_header hdr;
	uint16_t auth_alg;
	uint16_t auth_seq;
	uint16_t status_code;
	/* Optional: Challenge text */
	uint8_t challenge_data[256];
	uint16_t challenge_len;
} __attribute__((packed));

/* Injection Test Types */
typedef enum {
	TEST_DEAUTH = 1,
	TEST_DISASSOC = 2,
	TEST_FAKE_AUTH = 3,
	TEST_REPLAY = 4,
	TEST_BEACON_SPAM = 5,
	TEST_PROBE_REQUEST = 6,
	TEST_ASSOC_SPAM = 7
} injection_test_type_t;

/* Injection Context */
struct injection_context {
	const char *interface;
	uint8_t source_mac[6];
	uint8_t channel;
	int tx_power_dbm;
	uint32_t test_enabled;  /* Bitmask for enabled tests */
	uint8_t verbose;
	time_t last_injection;
};

/* Injection Result */
struct injection_result {
	injection_test_type_t test_type;
	uint8_t target_bssid[6];
	uint8_t target_client[6];
	uint8_t success;
	uint32_t frames_sent;
	uint32_t frames_acked;
	float tx_rate_mbps;
	int signal_dbm;
	uint8_t channel_hopping;
	time_t started_at;
	time_t completed_at;
};

/* Function prototypes */

/* Context management */
struct injection_context *injection_context_create(const char *interface);
void injection_context_free(struct injection_context *ctx);

/* Frame construction */
struct deauth_frame *deauth_frame_create(const uint8_t *bssid,
                                        const uint8_t *client_mac,
                                        const uint8_t *source_mac,
                                        uint16_t reason_code);
struct auth_frame *auth_frame_create(const uint8_t *bssid,
                                    const uint8_t *client_mac,
                                    const uint8_t *source_mac,
                                    uint16_t auth_alg,
                                    uint16_t auth_seq,
                                    uint16_t status_code);

/* Injection operations */
int injection_send_deauth(struct injection_context *ctx, const uint8_t *bssid,
                         const uint8_t *client_mac, uint8_t count, uint16_t delay_ms);
int injection_send_disassoc(struct injection_context *ctx, const uint8_t *bssid,
                           const uint8_t *client_mac, uint16_t reason_code);
int injection_send_fake_auth(struct injection_context *ctx, const uint8_t *bssid,
                            const uint8_t *client_mac, uint16_t auth_seq);
int injection_send_beacon_spam(struct injection_context *ctx, const uint8_t *bssid,
                              const char *ssid, uint8_t count);
int injection_send_probe_request(struct injection_context *ctx, const char *ssid,
                                const uint8_t *broadcast_mac);

/* Test execution */
int injection_test_deauth_stability(struct injection_context *ctx,
                                   const uint8_t *target_bssid,
                                   const uint8_t *target_client);
int injection_test_channel_lock(struct injection_context *ctx,
                               const uint8_t *target_bssid);
int injection_test_rate_limiting(struct injection_context *ctx,
                                const uint8_t *target_bssid);
int injection_test_tx_power(struct injection_context *ctx,
                           const uint8_t *target_bssid);

/* Monitoring and feedback */
int injection_monitor_ack(struct injection_context *ctx, uint32_t timeout_ms);
uint32_t injection_get_frame_rate(struct injection_context *ctx);
int injection_get_signal_strength(struct injection_context *ctx,
                                 const uint8_t *bssid);

/* Utilities */
void injection_set_source_mac(struct injection_context *ctx, const uint8_t *mac);
void injection_set_channel(struct injection_context *ctx, uint8_t channel);
void injection_set_power(struct injection_context *ctx, int dbm);
int injection_check_monitor_mode(const char *interface);
int injection_verify_injection_support(const char *interface);

/* Frame utilities */
uint16_t mac_frame_control(uint8_t type, uint8_t subtype, uint16_t flags);
void mac_set_sequence_number(struct mac_header *hdr, uint16_t seq_num);
void mac_set_retry_bit(struct mac_header *hdr, uint8_t retry);

#endif /* PACKET_INJECTION_H */
