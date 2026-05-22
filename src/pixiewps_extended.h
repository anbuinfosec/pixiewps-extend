/*
 * pixiewps_extended.h - Comprehensive wireless auditing framework
 * Integrates: WPS, PMKID, Handshake, Injection, Scanning, Recon
 * Copyright (c) 2026, @anbuinfosec
 * SPDX-License-Identifier: GPL-3.0+
 */

#ifndef PIXIEWPS_EXTENDED_H
#define PIXIEWPS_EXTENDED_H

/* Core modules */
#include "wifi_scanner.h"
#include "client_recon.h"
#include "monitor_mode.h"
#include "adapter_intel.h"
#include "packet_injection.h"
#include "wps_engine.h"
#include "pmkid_capture.h"
#include "handshake_capture.h"
#include "wpa3_handler.h"
#include "target_priority.h"

/* Framework Version */
#define PIXIEWPS_EXTENDED_VERSION "2.0.0"
#define FRAMEWORK_BUILD_DATE      "2026-05-23"
#define FRAMEWORK_AUTHOR          "@anbuinfosec"

/* Framework Capabilities */
#define FRAMEWORK_CAP_SCANNING       (1 << 0)
#define FRAMEWORK_CAP_RECON          (1 << 1)
#define FRAMEWORK_CAP_MONITOR        (1 << 2)
#define FRAMEWORK_CAP_INJECTION      (1 << 3)
#define FRAMEWORK_CAP_WPS            (1 << 4)
#define FRAMEWORK_CAP_PMKID          (1 << 5)
#define FRAMEWORK_CAP_HANDSHAKE      (1 << 6)
#define FRAMEWORK_CAP_WPA3           (1 << 7)
#define FRAMEWORK_CAP_TARGETING      (1 << 8)

/* Global Framework Context */
struct pixiewps_framework {
	struct wifi_scanner *scanner;
	struct client_recon_engine *recon;
	struct monitor_manager *monitor;
	struct adapter_manager *adapters;
	struct injection_context *injection;
	struct wps_engine *wps;
	struct pmkid_engine *pmkid;
	struct handshake_engine *handshake;
	struct wpa3_handler *wpa3;
	struct priority_engine *priority;
	
	uint32_t capabilities;
	uint8_t verbose;
	char interface[16];
	char output_dir[256];
};

/* Initialization and Cleanup */
struct pixiewps_framework *pixiewps_framework_init(void);
void pixiewps_framework_free(struct pixiewps_framework *fw);

/* Configuration */
int pixiewps_configure_interface(struct pixiewps_framework *fw, const char *iface);
int pixiewps_check_requirements(struct pixiewps_framework *fw);
int pixiewps_enable_monitor_mode(struct pixiewps_framework *fw);
int pixiewps_disable_monitor_mode(struct pixiewps_framework *fw);

/* Scanning and Discovery */
int pixiewps_start_scan(struct pixiewps_framework *fw);
int pixiewps_stop_scan(struct pixiewps_framework *fw);
void pixiewps_update_scan_results(struct pixiewps_framework *fw);

/* Target Selection and Prioritization */
struct target_priority *pixiewps_select_best_target(struct pixiewps_framework *fw);
int pixiewps_evaluate_all_targets(struct pixiewps_framework *fw);

/* Attack Workflows */
int pixiewps_attack_wps(struct pixiewps_framework *fw, const uint8_t *bssid);
int pixiewps_capture_handshake(struct pixiewps_framework *fw, const uint8_t *bssid);
int pixiewps_capture_pmkid(struct pixiewps_framework *fw, const uint8_t *bssid);
int pixiewps_attack_wpa3_transition(struct pixiewps_framework *fw, const uint8_t *bssid);

/* Real-time Monitoring */
int pixiewps_monitor_clients(struct pixiewps_framework *fw);
int pixiewps_monitor_roaming(struct pixiewps_framework *fw);
int pixiewps_monitor_activities(struct pixiewps_framework *fw);

/* Export and Logging */
int pixiewps_export_results(struct pixiewps_framework *fw, const char *format);
int pixiewps_export_pcap(struct pixiewps_framework *fw, const char *filename);
int pixiewps_export_json(struct pixiewps_framework *fw, const char *filename);
int pixiewps_export_csv(struct pixiewps_framework *fw, const char *filename);
int pixiewps_export_hc22000(struct pixiewps_framework *fw, const char *filename);

/* Status and Statistics */
void pixiewps_print_status(struct pixiewps_framework *fw);
void pixiewps_print_statistics(struct pixiewps_framework *fw);
void pixiewps_print_summary(struct pixiewps_framework *fw);

/* Cleanup and Recovery */
int pixiewps_cleanup_on_exit(struct pixiewps_framework *fw);
int pixiewps_emergency_cleanup(struct pixiewps_framework *fw);

#endif /* PIXIEWPS_EXTENDED_H */
