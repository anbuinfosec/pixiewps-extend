/*
 * wpa3_handler.h - WPA3 PMKID and SAE support for pixiewps-extend
 * Copyright (c) 2026, @anbuinfosec
 * SPDX-License-Identifier: GPL-3.0+
 */

#ifndef WPA3_HANDLER_H
#define WPA3_HANDLER_H

#include <stdint.h>
#include <stddef.h>
#include <time.h>

/* WPA3 Constants */
#define WPA3_PMKID_LEN           16
#define WPA3_KDE_LEN             256
#define WPA3_SAE_MAX_GROUPS      4
#define WPA3_OWE_DHE_LEN         256
#define WPA3_PMF_TIMEOUT         60  /* PMF BIP check timeout in seconds */

/* WPA3 Frame Types */
typedef enum {
	WPA3_TYPE_NONE = 0,
	WPA3_TYPE_SAE_COMMIT = 1,
	WPA3_TYPE_SAE_CONFIRM = 2,
	WPA3_TYPE_OWE_TRANSITION = 3,
	WPA3_TYPE_PMKID_CANDIDATE = 4,
	WPA3_TYPE_TRANSITION_MODE = 5,
	WPA3_TYPE_192BIT_KEY = 6
} wpa3_frame_type_t;

/* PMKID Candidate entry */
struct pmkid_candidate {
	uint8_t bssid[6];
	uint32_t preauth_capable : 1;
	uint32_t pmkid_candidate : 1;
	uint32_t rsvd : 14;
	uint32_t pmkid_count : 16;
	uint8_t pmkids[WPA3_PMKID_LEN];
	time_t timestamp;
};

/* WPA3 Transition Mode Detector */
struct wpa3_transition {
	uint8_t bssid[6];
	uint8_t ssid[33];
	uint8_t ssid_len;
	uint8_t has_wpa3 : 1;
	uint8_t has_wpa2 : 1;
	uint8_t has_open : 1;
	uint8_t pmf_required : 1;
	uint8_t sae_groups;  /* Bitmask: bit 0=19, 1=20, 2=21, 3=25 */
	uint8_t owe_enabled : 1;
	uint8_t pwe_method;  /* Password Element method: 0=hunting, 1=hash */
	time_t discovered_at;
};

/* WPA3 SAE State Machine */
struct sae_context {
	uint8_t mac[6];
	uint8_t bssid[6];
	uint8_t password[256];
	uint16_t password_len;
	uint16_t group;
	uint8_t counter;
	uint8_t sae_commit[512];
	uint8_t sae_commit_len;
	uint8_t sae_confirm[512];
	uint8_t sae_confirm_len;
	uint8_t pmk[32];
	time_t initiated_at;
};

/* PMKID Cache */
struct pmkid_cache {
	uint8_t pmkid[WPA3_PMKID_LEN];
	uint8_t bssid[6];
	uint8_t ssid[33];
	uint8_t ssid_len;
	uint32_t priority;
	time_t found_at;
};

/* WPA3 Handler Structure */
struct wpa3_handler {
	struct pmkid_candidate *pmkid_candidates;
	uint32_t pmkid_count;
	struct wpa3_transition *transition_networks;
	uint32_t transition_count;
	struct pmkid_cache *pmkid_cache;
	uint32_t cache_size;
	struct sae_context *sae_ctx;
	uint32_t sae_count;
	time_t last_update;
};

/* Function prototypes */
struct wpa3_handler *wpa3_handler_init(void);
void wpa3_handler_free(struct wpa3_handler *handler);

/* PMKID detection and extraction */
int wpa3_extract_pmkid(const uint8_t *ie_buf, uint16_t ie_len, uint8_t *pmkid);
int wpa3_is_pmkid_candidate(const uint8_t *ie_buf, uint16_t ie_len);
int wpa3_add_pmkid_candidate(struct wpa3_handler *handler, const uint8_t *bssid, 
                            const uint8_t *pmkid);

/* Transition Mode Detection */
int wpa3_detect_transition_mode(struct wpa3_handler *handler, const uint8_t *bssid,
                                const uint8_t *ssid, uint8_t ssid_len,
                                uint8_t has_wpa3, uint8_t has_wpa2);
struct wpa3_transition *wpa3_find_transition(struct wpa3_handler *handler, 
                                            const uint8_t *bssid);

/* SAE (Simultaneous Authentication of Equals) Support */
int wpa3_sae_init_context(struct wpa3_handler *handler, const uint8_t *mac,
                          const uint8_t *bssid, const uint8_t *password, 
                          uint16_t password_len);
int wpa3_sae_parse_commit(struct sae_context *ctx, const uint8_t *frame, 
                          uint16_t frame_len);
int wpa3_sae_derive_pmk(struct sae_context *ctx);

/* PMF (Protected Management Frames) */
int wpa3_parse_pmf_capability(const uint8_t *ie_buf, uint16_t ie_len);
int wpa3_validate_bip_mic(const uint8_t *frame, uint16_t frame_len, 
                          const uint8_t *key, uint8_t key_len);

/* OWE (Opportunistic Wireless Encryption) */
int wpa3_parse_owe_transition(const uint8_t *ie_buf, uint16_t ie_len,
                              uint8_t *ssid, uint8_t *ssid_len);
int wpa3_owe_derive_psk(const uint8_t *dh_shared_secret, uint16_t secret_len,
                        const uint8_t *bssid, const uint8_t *client_mac,
                        uint8_t *psk);

/* PMKID Caching and Priority */
void wpa3_add_to_pmkid_cache(struct wpa3_handler *handler, const uint8_t *pmkid,
                             const uint8_t *bssid, const uint8_t *ssid, 
                             uint8_t ssid_len, uint32_t priority);
struct pmkid_cache *wpa3_get_pmkid_by_priority(struct wpa3_handler *handler);

#endif /* WPA3_HANDLER_H */
