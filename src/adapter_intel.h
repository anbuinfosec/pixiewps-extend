/*
 * adapter_intel.h - WiFi adapter intelligence and capability detection
 * Copyright (c) 2026, @anbuinfosec
 * SPDX-License-Identifier: GPL-3.0+
 */

#ifndef ADAPTER_INTEL_H
#define ADAPTER_INTEL_H

#include <stdint.h>

/* Popular WiFi Adapter Chipsets */
#define CHIPSET_REALTEK_RTL8812AU   1
#define CHIPSET_MEDIATEK_MT7612U    2
#define CHIPSET_ATHEROS_AR9271      3
#define CHIPSET_MEDIATEK_MT7921     4
#define CHIPSET_REALTEK_RTL8811AU   5
#define CHIPSET_REALTEK_RTL8821CU   6
#define CHIPSET_BROADCOM_BCM4358    7
#define CHIPSET_INTEL_AX200         8
#define CHIPSET_QUALCOMM_AQFP       9
#define CHIPSET_REALTEK_RTL8710     10
#define CHIPSET_RALINK_RT3070       11
#define CHIPSET_REALTEK_RTL8722D    12

/* Capability Flags */
#define ADAPTER_CAP_MONITOR          (1 << 0)
#define ADAPTER_CAP_INJECTION        (1 << 1)
#define ADAPTER_CAP_FRAME_INJECTION  (1 << 2)
#define ADAPTER_CAP_TX_POWER         (1 << 3)
#define ADAPTER_CAP_CHANNEL_SWITCH   (1 << 4)
#define ADAPTER_CAP_HT_40MHZ         (1 << 5)
#define ADAPTER_CAP_VHT_80MHZ        (1 << 6)
#define ADAPTER_CAP_VHT_160MHZ       (1 << 7)
#define ADAPTER_CAP_HE_160MHZ        (1 << 8)  /* WiFi 6 */
#define ADAPTER_CAP_SOFT_MONITOR     (1 << 9)
#define ADAPTER_CAP_FIRMWARE_UPDATE  (1 << 10)
#define ADAPTER_CAP_THERMAL_THROTTLE (1 << 11)

/* Adapter Information */
struct adapter_info {
	char name[16];
	uint16_t usb_vendor_id;
	uint16_t usb_product_id;
	char usb_vendor_name[32];
	char usb_product_name[64];
	
	uint8_t chipset_id;
	char chipset_name[32];
	char driver_name[32];
	char driver_version[16];
	char firmware_version[32];
	
	uint32_t capabilities;
	
	uint8_t supported_bands;  /* Bitmask: 2.4GHz, 5GHz, 6GHz */
	uint8_t max_tx_chains;
	uint8_t max_rx_chains;
	uint32_t max_tx_power_dbm;
	
	uint8_t monitor_support;
	uint8_t injection_support;
	uint8_t wifi6_support;
	uint8_t wifi6e_support;
	uint8_t wifi7_support;
	
	uint32_t max_data_rate_mbps;
	uint16_t mtu_bytes;
	
	/* Termux/Android specific */
	uint8_t is_termux_compatible;
	uint8_t requires_root;
	uint8_t oem_locked;
	
	/* Performance characteristics */
	uint16_t min_channel_dwell_ms;
	uint16_t max_channel_dwell_ms;
	uint32_t max_tx_rate_sustained_mbps;
	int32_t min_tx_power_dbm;
	int32_t max_rx_sensitivity_dbm;
	
	/* Known issues */
	uint8_t has_thermal_issues;
	uint8_t has_sleep_issues;
	uint8_t has_injection_issues;
};

/* Adapter Database Entry */
struct adapter_db_entry {
	uint16_t usb_vendor_id;
	uint16_t usb_product_id;
	uint8_t chipset_id;
	const char *chipset_name;
	const char *driver_name;
	uint32_t capabilities;
	uint8_t monitor_support;
	uint8_t injection_support;
};

/* Adapter Manager */
struct adapter_manager {
	struct adapter_info *adapters;
	uint32_t adapter_count;
	uint32_t max_adapters;
};

/* Function prototypes */

/* Manager management */
struct adapter_manager *adapter_manager_init(void);
void adapter_manager_free(struct adapter_manager *manager);

/* Adapter discovery */
int adapter_manager_scan(struct adapter_manager *manager);
struct adapter_info *adapter_manager_get(struct adapter_manager *manager,
                                        const char *name);
struct adapter_info *adapter_manager_get_best(struct adapter_manager *manager);

/* Capability detection */
int adapter_detect_monitor_support(const char *interface);
int adapter_detect_injection_support(const char *interface);
int adapter_detect_wifi6_support(const char *interface);
int adapter_get_tx_power(const char *interface);
int adapter_get_channel_dwell_time(const char *interface);

/* USB device detection */
int adapter_detect_usb_device(const char *interface, uint16_t *vendor_id,
                             uint16_t *product_id);
int adapter_lookup_usb_device(uint16_t vendor_id, uint16_t product_id,
                             struct adapter_info *info);

/* Driver and firmware info */
const char *adapter_get_driver_name(const char *interface);
const char *adapter_get_driver_version(const char *interface);
const char *adapter_get_firmware_version(const char *interface);

/* Compatibility checking */
int adapter_is_compatible(struct adapter_info *info);
int adapter_supports_feature(struct adapter_info *info, uint32_t feature);
int adapter_check_termux_compatibility(struct adapter_info *info);

/* Performance tuning */
int adapter_set_tx_power(const char *interface, int8_t dbm);
int adapter_set_bitrate(const char *interface, uint32_t rate_mbps);
int adapter_set_antenna(const char *interface, uint8_t tx_antenna,
                       uint8_t rx_antenna);
int adapter_enable_vht(const char *interface);
int adapter_enable_he(const char *interface);  /* WiFi 6 */

/* Thermal and power management */
int adapter_check_temperature(const char *interface);
int adapter_enable_power_save(const char *interface);
int adapter_disable_power_save(const char *interface);

/* Vendor-specific functions */
int adapter_rtl8812au_optimize(const char *interface);
int adapter_mt7612u_optimize(const char *interface);
int adapter_ar9271_optimize(const char *interface);

#endif /* ADAPTER_INTEL_H */
