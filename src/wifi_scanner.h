/*
 * wifi_scanner.h - Advanced WiFi scanning module for pixiewps-extend
 * Copyright (c) 2026, @anbuinfosec
 * SPDX-License-Identifier: GPL-3.0+
 */

#ifndef WIFI_SCANNER_H
#define WIFI_SCANNER_H

#include <stdint.h>
#include <time.h>

/* WiFi Standards */
#define WIFI_STANDARD_802_11B    (1 << 0)
#define WIFI_STANDARD_802_11G    (1 << 1)
#define WIFI_STANDARD_802_11N    (1 << 2)
#define WIFI_STANDARD_802_11AC   (1 << 3)
#define WIFI_STANDARD_802_11AX   (1 << 4)  /* WiFi 6 */
#define WIFI_STANDARD_802_11BE   (1 << 5)  /* WiFi 7 */

/* Encryption Types */
#define ENC_OPEN                 0
#define ENC_WEP                  1
#define ENC_WPA                  2
#define ENC_WPA2                 3
#define ENC_WPA3                 4
#define ENC_WPA2_WPA3            5
#define ENC_OWE                  6

/* Maximum values */
#define MAX_SSID_LEN             32
#define MAX_NETWORKS             512
#define MAX_CLIENTS_PER_AP       64
#define CHANNEL_LIST_SIZE        165  /* 2.4GHz (14) + 5GHz (36-165) + 6GHz */

/* 2.4 GHz Channels */
#define CHAN_2400_START          1
#define CHAN_2400_END            14

/* 5 GHz Channels */
#define CHAN_5000_START          32
#define CHAN_5000_END            165

/* 6 GHz Channels (WiFi 6E) */
#define CHAN_6000_START          1
#define CHAN_6000_END            233

/* Access Point Information */
struct ap_info {
	uint8_t bssid[6];
	uint8_t ssid[MAX_SSID_LEN + 1];
	uint8_t ssid_len;
	uint8_t hidden_ssid;
	uint8_t channel;
	int8_t signal_dbm;
	uint32_t encryption;     /* Bitmask: WPA|WPA2|WPA3 */
	uint8_t wps_enabled;
	uint8_t pmf_capable;
	uint8_t pmf_required;
	uint16_t beacon_interval;
	uint8_t vendor_oui[3];
	char vendor_name[32];
	uint32_t capability_info;
	uint8_t supported_rates[16];
	uint8_t supported_rates_len;
	uint8_t standards;       /* Bitmask: 802.11b/g/n/ac/ax/be */
	uint32_t client_count;
	uint8_t has_ht;          /* 802.11n */
	uint8_t has_vht;         /* 802.11ac */
	uint8_t has_he;          /* 802.11ax (WiFi 6) */
	uint8_t has_eht;         /* 802.11be (WiFi 7) */
	time_t first_seen;
	time_t last_seen;
	uint32_t beacon_count;
};

/* Connected Client Information */
struct client_info {
	uint8_t mac[6];
	uint8_t bssid[6];
	int8_t signal_dbm;
	uint16_t power_save_mode;
	uint8_t random_mac;      /* OUI randomization detected */
	uint8_t probe_count;
	char last_ssid[MAX_SSID_LEN + 1];
	time_t first_seen;
	time_t last_seen;
	uint32_t tx_packets;
	uint32_t rx_packets;
	uint8_t tx_rate_mbps;
	uint8_t rx_rate_mbps;
};

/* Probe Request */
struct probe_request {
	uint8_t source_mac[6];
	char ssid[MAX_SSID_LEN + 1];
	uint8_t ssid_len;
	int8_t signal_dbm;
	uint8_t random_mac;
	time_t timestamp;
};

/* Scanner Configuration */
struct scan_config {
	uint8_t *channels;
	uint32_t channel_count;
	uint16_t dwell_time_ms;
	uint8_t passive_mode;
	uint8_t monitor_clients;
	uint8_t monitor_probes;
	uint8_t channel_hopping;
	uint32_t scan_timeout_sec;
};

/* Scanner Engine */
struct wifi_scanner {
	struct ap_info *networks;
	uint32_t network_count;
	uint32_t max_networks;
	
	struct client_info *clients;
	uint32_t client_count;
	uint32_t max_clients;
	
	struct probe_request *probes;
	uint32_t probe_count;
	uint32_t max_probes;
	
	struct scan_config config;
	uint8_t scanning;
	time_t last_update;
};

/* Function prototypes */

/* Scanner management */
struct wifi_scanner *wifi_scanner_init(void);
void wifi_scanner_free(struct wifi_scanner *scanner);
void wifi_scanner_reset(struct wifi_scanner *scanner);

/* Configuration */
void wifi_scanner_set_channels_2400(struct wifi_scanner *scanner);
void wifi_scanner_set_channels_5000(struct wifi_scanner *scanner);
void wifi_scanner_set_channels_all(struct wifi_scanner *scanner);
void wifi_scanner_set_dwell_time(struct wifi_scanner *scanner, uint16_t ms);
void wifi_scanner_enable_client_monitoring(struct wifi_scanner *scanner);
void wifi_scanner_enable_probe_monitoring(struct wifi_scanner *scanner);

/* Scanning operations */
int wifi_scanner_start(struct wifi_scanner *scanner, const char *interface);
int wifi_scanner_stop(struct wifi_scanner *scanner);
int wifi_scanner_process_beacon(struct wifi_scanner *scanner,
                               const uint8_t *frame, uint16_t frame_len);
int wifi_scanner_process_probe_response(struct wifi_scanner *scanner,
                                       const uint8_t *frame, uint16_t frame_len);

/* Network search */
struct ap_info *wifi_scanner_find_ap(struct wifi_scanner *scanner,
                                     const uint8_t *bssid);
struct ap_info *wifi_scanner_find_ap_by_ssid(struct wifi_scanner *scanner,
                                            const char *ssid);
struct ap_info *wifi_scanner_find_wps_ap(struct wifi_scanner *scanner);

/* Client tracking */
int wifi_scanner_add_client(struct wifi_scanner *scanner, const uint8_t *mac,
                           const uint8_t *bssid);
struct client_info *wifi_scanner_find_client(struct wifi_scanner *scanner,
                                            const uint8_t *mac);
uint32_t wifi_scanner_get_client_count(struct wifi_scanner *scanner,
                                      const uint8_t *bssid);

/* Probe request tracking */
int wifi_scanner_add_probe_request(struct wifi_scanner *scanner,
                                  const uint8_t *source_mac,
                                  const char *ssid);

/* Statistics */
uint32_t wifi_scanner_get_network_count(struct wifi_scanner *scanner);
uint32_t wifi_scanner_get_wps_count(struct wifi_scanner *scanner);
struct ap_info *wifi_scanner_get_strongest_signal(struct wifi_scanner *scanner);
void wifi_scanner_print_summary(struct wifi_scanner *scanner);

/* Vendor lookup */
const char *wifi_scanner_lookup_vendor(const uint8_t *oui);
void wifi_scanner_detect_vendor(struct ap_info *ap);

/* Channel utilities */
uint8_t wifi_scanner_get_channel_for_frequency(uint16_t freq_mhz);
uint16_t wifi_scanner_get_frequency_for_channel(uint8_t channel);
const char *wifi_scanner_get_band_name(uint8_t channel);

#endif /* WIFI_SCANNER_H */
