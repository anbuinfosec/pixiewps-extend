/*
 * wifi_scanner.c - WiFi scanning implementation (stubs for build)
 * Copyright (c) 2026, @anbuinfosec
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "wifi_scanner.h"

struct wifi_scanner *wifi_scanner_init(void)
{
	struct wifi_scanner *scanner = malloc(sizeof(*scanner));
	if (!scanner) return NULL;
	memset(scanner, 0, sizeof(*scanner));
	scanner->max_networks = MAX_NETWORKS;
	scanner->max_clients = MAX_NETWORKS * MAX_CLIENTS_PER_AP;
	scanner->max_probes = MAX_NETWORKS * 10;
	scanner->networks = malloc(sizeof(struct ap_info) * scanner->max_networks);
	scanner->clients = malloc(sizeof(struct client_info) * scanner->max_clients);
	scanner->probes = malloc(sizeof(struct probe_request) * scanner->max_probes);
	if (!scanner->networks || !scanner->clients || !scanner->probes) {
		free(scanner->networks);
		free(scanner->clients);
		free(scanner->probes);
		free(scanner);
		return NULL;
	}
	return scanner;
}

void wifi_scanner_free(struct wifi_scanner *scanner)
{
	if (!scanner) return;
	free(scanner->networks);
	free(scanner->clients);
	free(scanner->probes);
	free(scanner);
}

void wifi_scanner_reset(struct wifi_scanner *scanner)
{
	if (!scanner) return;
	memset(scanner->networks, 0, sizeof(struct ap_info) * scanner->network_count);
	memset(scanner->clients, 0, sizeof(struct client_info) * scanner->client_count);
	scanner->network_count = 0;
	scanner->client_count = 0;
	scanner->probe_count = 0;
}

void wifi_scanner_set_channels_2400(struct wifi_scanner *scanner)
{
	if (!scanner) return;
	uint8_t channels[] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14};
	memcpy(scanner->config.channels, channels, sizeof(channels));
	scanner->config.channel_count = sizeof(channels);
}

void wifi_scanner_set_channels_5000(struct wifi_scanner *scanner)
{
	if (!scanner) return;
	uint8_t channels[] = {36,40,44,48,52,56,60,64,100,104,108,112,116,120,124,128,132,136,140,144,149,153,157,161,165};
	memcpy(scanner->config.channels, channels, sizeof(channels));
	scanner->config.channel_count = sizeof(channels);
}

void wifi_scanner_set_channels_all(struct wifi_scanner *scanner)
{
	if (!scanner) return;
	wifi_scanner_set_channels_2400(scanner);
	uint8_t channels_5g[] = {36,40,44,48,52,56,60,64,100,104,108,112,116,120,124,128,132,136,140,144,149,153,157,161,165};
	int offset = scanner->config.channel_count;
	memcpy(scanner->config.channels + offset, channels_5g, sizeof(channels_5g));
	scanner->config.channel_count += sizeof(channels_5g);
}

void wifi_scanner_set_dwell_time(struct wifi_scanner *scanner, uint16_t ms)
{
	if (scanner) scanner->config.dwell_time_ms = ms;
}

void wifi_scanner_enable_client_monitoring(struct wifi_scanner *scanner)
{
	if (scanner) scanner->config.monitor_clients = 1;
}

void wifi_scanner_enable_probe_monitoring(struct wifi_scanner *scanner)
{
	if (scanner) scanner->config.monitor_probes = 1;
}

int wifi_scanner_start(struct wifi_scanner *scanner, const char *interface)
{
	if (!scanner || !interface) return 0;
	scanner->scanning = 1;
	printf("[*] Starting scan on %s\n", interface);
	return 1;
}

int wifi_scanner_stop(struct wifi_scanner *scanner)
{
	if (!scanner) return 0;
	scanner->scanning = 0;
	printf("[*] Scan stopped\n");
	return 1;
}

int wifi_scanner_process_beacon(struct wifi_scanner *scanner,
                               const uint8_t *frame, uint16_t frame_len)
{
	if (!scanner || !frame) return 0;
	return 1;
}

int wifi_scanner_process_probe_response(struct wifi_scanner *scanner,
                                       const uint8_t *frame, uint16_t frame_len)
{
	if (!scanner || !frame) return 0;
	return 1;
}

struct ap_info *wifi_scanner_find_ap(struct wifi_scanner *scanner, const uint8_t *bssid)
{
	if (!scanner || !bssid) return NULL;
	for (uint32_t i = 0; i < scanner->network_count; i++) {
		if (memcmp(scanner->networks[i].bssid, bssid, 6) == 0)
			return &scanner->networks[i];
	}
	return NULL;
}

struct ap_info *wifi_scanner_find_ap_by_ssid(struct wifi_scanner *scanner, const char *ssid)
{
	if (!scanner || !ssid) return NULL;
	for (uint32_t i = 0; i < scanner->network_count; i++) {
		if (strcmp((char*)scanner->networks[i].ssid, ssid) == 0)
			return &scanner->networks[i];
	}
	return NULL;
}

struct ap_info *wifi_scanner_find_wps_ap(struct wifi_scanner *scanner)
{
	if (!scanner) return NULL;
	for (uint32_t i = 0; i < scanner->network_count; i++) {
		if (scanner->networks[i].wps_enabled)
			return &scanner->networks[i];
	}
	return NULL;
}

int wifi_scanner_add_client(struct wifi_scanner *scanner, const uint8_t *mac, const uint8_t *bssid)
{
	if (!scanner || !mac || scanner->client_count >= scanner->max_clients) return 0;
	memcpy(scanner->clients[scanner->client_count].mac, mac, 6);
	memcpy(scanner->clients[scanner->client_count].bssid, bssid, 6);
	scanner->client_count++;
	return 1;
}

struct client_info *wifi_scanner_find_client(struct wifi_scanner *scanner, const uint8_t *mac)
{
	if (!scanner || !mac) return NULL;
	for (uint32_t i = 0; i < scanner->client_count; i++) {
		if (memcmp(scanner->clients[i].mac, mac, 6) == 0)
			return &scanner->clients[i];
	}
	return NULL;
}

uint32_t wifi_scanner_get_client_count(struct wifi_scanner *scanner, const uint8_t *bssid)
{
	if (!scanner || !bssid) return 0;
	uint32_t count = 0;
	for (uint32_t i = 0; i < scanner->client_count; i++) {
		if (memcmp(scanner->clients[i].bssid, bssid, 6) == 0) count++;
	}
	return count;
}

int wifi_scanner_add_probe_request(struct wifi_scanner *scanner, const uint8_t *source_mac, const char *ssid)
{
	if (!scanner || !source_mac || !ssid || scanner->probe_count >= scanner->max_probes) return 0;
	memcpy(scanner->probes[scanner->probe_count].source_mac, source_mac, 6);
	strncpy((char*)scanner->probes[scanner->probe_count].ssid, ssid, MAX_SSID_LEN);
	scanner->probe_count++;
	return 1;
}

uint32_t wifi_scanner_get_network_count(struct wifi_scanner *scanner)
{
	return scanner ? scanner->network_count : 0;
}

uint32_t wifi_scanner_get_wps_count(struct wifi_scanner *scanner)
{
	if (!scanner) return 0;
	uint32_t count = 0;
	for (uint32_t i = 0; i < scanner->network_count; i++) {
		if (scanner->networks[i].wps_enabled) count++;
	}
	return count;
}

struct ap_info *wifi_scanner_get_strongest_signal(struct wifi_scanner *scanner)
{
	if (!scanner || scanner->network_count == 0) return NULL;
	struct ap_info *strongest = &scanner->networks[0];
	for (uint32_t i = 1; i < scanner->network_count; i++) {
		if (scanner->networks[i].signal_dbm > strongest->signal_dbm)
			strongest = &scanner->networks[i];
	}
	return strongest;
}

void wifi_scanner_print_summary(struct wifi_scanner *scanner)
{
	if (!scanner) return;
	printf("\n[*] WiFi Scanner Summary\n");
	printf("    Networks: %u\n", scanner->network_count);
	printf("    WPS Enabled: %u\n", wifi_scanner_get_wps_count(scanner));
	printf("    Clients: %u\n", scanner->client_count);
	printf("    Probe Requests: %u\n", scanner->probe_count);
}

const char *wifi_scanner_lookup_vendor(const uint8_t *oui)
{
	return "Unknown";
}

void wifi_scanner_detect_vendor(struct ap_info *ap)
{
	if (ap) strncpy(ap->vendor_name, "Unknown", 31);
}

uint8_t wifi_scanner_get_channel_for_frequency(uint16_t freq_mhz)
{
	if (freq_mhz >= 2412 && freq_mhz <= 2484) return ((freq_mhz - 2407) / 5);
	if (freq_mhz >= 5000 && freq_mhz <= 5825) return ((freq_mhz - 5000) / 5);
	return 0;
}

uint16_t wifi_scanner_get_frequency_for_channel(uint8_t channel)
{
	if (channel >= 1 && channel <= 13) return (2407 + channel * 5);
	if (channel >= 36) return (5000 + channel * 5);
	return 0;
}

const char *wifi_scanner_get_band_name(uint8_t channel)
{
	if (channel <= 14) return "2.4 GHz";
	if (channel <= 165) return "5 GHz";
	return "6 GHz";
}
