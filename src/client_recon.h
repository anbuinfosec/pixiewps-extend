/*
 * client_recon.h - Client reconnaissance and tracking module
 * Copyright (c) 2026, @anbuinfosec
 * SPDX-License-Identifier: GPL-3.0+
 */

#ifndef CLIENT_RECON_H
#define CLIENT_RECON_H

#include <stdint.h>
#include <time.h>

/* MAC Randomization Indicators */
#define MAC_RANDOM_INDICATOR_OUI     (1 << 0)  /* Locally administered bit set */
#define MAC_RANDOM_INDICATOR_PATTERN (1 << 1)  /* Non-standard pattern */
#define MAC_RANDOM_INDICATOR_STATIC  (1 << 2)  /* Stays same across SSIDs */
#define MAC_RANDOM_INDICATOR_DYNAMIC (1 << 3)  /* Changes frequently */

/* Activity Types */
#define ACTIVITY_BEACON             1
#define ACTIVITY_PROBE_REQUEST      2
#define ACTIVITY_PROBE_RESPONSE     3
#define ACTIVITY_ASSOCIATION        4
#define ACTIVITY_REASSOCIATION      5
#define ACTIVITY_DATA_FRAME         6
#define ACTIVITY_DEAUTHENTICATION   7
#define ACTIVITY_DISASSOCIATION     8

/* Client State */
#define CLIENT_STATE_PROBING         1
#define CLIENT_STATE_ASSOCIATING     2
#define CLIENT_STATE_ASSOCIATED      3
#define CLIENT_STATE_AUTHENTICATED   4
#define CLIENT_STATE_ROAMING         5
#define CLIENT_STATE_DISCONNECTED    6

/* Roaming Event */
struct roaming_event {
	uint8_t client_mac[6];
	uint8_t from_bssid[6];
	uint8_t to_bssid[6];
	int8_t from_signal;
	int8_t to_signal;
	time_t roam_time;
	uint8_t reason;
};

/* Client Device Information */
struct client_device {
	uint8_t mac[6];
	uint8_t random_mac;          /* MAC randomization detected */
	uint8_t random_indicators;   /* Bitmask of randomization signs */
	char manufacturer[64];
	char model[64];
	char os_name[32];
	uint8_t os_type;             /* 1=Android, 2=iOS, 3=Windows, 4=Linux, 5=macOS */
	uint8_t device_type;         /* 1=Phone, 2=Tablet, 3=Laptop, 4=Desktop, 5=IoT */
};

/* Client Activity Log */
struct activity_log {
	uint8_t activity_type;
	char ssid[33];
	uint8_t channel;
	int8_t signal_dbm;
	time_t timestamp;
};

/* Complete Client Record */
struct client_record {
	uint8_t mac[6];
	uint8_t state;               /* Connected, probing, etc */
	struct client_device device;
	
	uint32_t probe_count;
	uint32_t probe_ack_count;
	
	uint32_t association_count;
	uint32_t reassociation_count;
	
	uint8_t **ssid_list;         /* List of SSIDs client probed for */
	uint32_t ssid_count;
	
	struct roaming_event *roam_history;
	uint32_t roam_count;
	uint32_t max_roams;
	
	struct activity_log *activity;
	uint32_t activity_count;
	uint32_t max_activities;
	
	time_t first_seen;
	time_t last_seen;
	time_t last_activity;
	
	int8_t avg_signal_dbm;
	uint32_t priority_score;
};

/* Recon Engine */
struct client_recon_engine {
	struct client_record *clients;
	uint32_t client_count;
	uint32_t max_clients;
	
	struct roaming_event *roam_events;
	uint32_t roam_event_count;
	
	uint8_t tracking_enabled;
	time_t last_update;
};

/* Function prototypes */

/* Engine management */
struct client_recon_engine *client_recon_init(void);
void client_recon_free(struct client_recon_engine *engine);

/* Client tracking */
int client_recon_add_client(struct client_recon_engine *engine, const uint8_t *mac);
struct client_record *client_recon_find_client(struct client_recon_engine *engine,
                                              const uint8_t *mac);
struct client_record *client_recon_get_best_target(struct client_recon_engine *engine);

/* MAC Randomization Detection */
int client_detect_mac_randomization(const uint8_t *mac);
void client_analyze_mac_patterns(struct client_recon_engine *engine);
struct client_record *client_find_by_randomized_mac(struct client_recon_engine *engine,
                                                    const uint8_t *random_mac);

/* Probe Request Tracking */
int client_add_probe_request(struct client_recon_engine *engine, const uint8_t *mac,
                            const char *ssid);
int client_get_probed_ssids(struct client_recon_engine *engine, const uint8_t *mac,
                           char **ssid_list, uint32_t *count);

/* Device Fingerprinting */
int client_fingerprint_device(struct client_record *client, const uint8_t *frame,
                             uint16_t frame_len);
const char *client_identify_os(const uint8_t *mac);
const char *client_identify_manufacturer(const uint8_t *mac);

/* Roaming Detection and Tracking */
int client_detect_roaming(struct client_recon_engine *engine, const uint8_t *mac,
                         const uint8_t *from_bssid, const uint8_t *to_bssid);
struct roaming_event *client_get_roaming_history(struct client_recon_engine *engine,
                                                const uint8_t *mac,
                                                uint32_t *count);

/* Activity Monitoring */
int client_log_activity(struct client_record *client, uint8_t activity_type,
                       const char *ssid, uint8_t channel, int8_t signal_dbm);
int client_is_active(struct client_record *client, uint32_t idle_threshold_sec);

/* Signal Strength Tracking */
void client_update_signal_strength(struct client_record *client, int8_t signal_dbm);
int8_t client_get_avg_signal(struct client_record *client);

/* Statistics and Reporting */
uint32_t client_get_count(struct client_recon_engine *engine);
uint32_t client_get_active_count(struct client_recon_engine *engine);
uint32_t client_get_roaming_count(struct client_recon_engine *engine);
void client_print_summary(struct client_recon_engine *engine);
void client_print_device_info(struct client_record *client);

#endif /* CLIENT_RECON_H */
