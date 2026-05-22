/*
 * monitor_mode.h - Monitor mode automation for pixiewps-extend
 * Copyright (c) 2026, @anbuinfosec
 * SPDX-License-Identifier: GPL-3.0+
 */

#ifndef MONITOR_MODE_H
#define MONITOR_MODE_H

#include <stdint.h>

/* Monitor Mode States */
#define MONITOR_STATE_UNKNOWN     0
#define MONITOR_STATE_DISABLED    1
#define MONITOR_STATE_ENABLED     2
#define MONITOR_STATE_SWITCHING   3

/* Process Types to Kill */
#define PROCESS_NETWORKMANAGER   (1 << 0)
#define PROCESS_WLAN_SUPPLICANT  (1 << 1)
#define PROCESS_DHCLIENT         (1 << 2)
#define PROCESS_HOSTAPD          (1 << 3)
#define PROCESS_IFACE_MANAGER    (1 << 4)
#define PROCESS_SYSTEMD_RESOLVED (1 << 5)

/* Interface Backup */
struct interface_backup {
	char interface[16];
	char original_mode[16];
	uint8_t original_mac[6];
	char original_ip[16];
	char original_gateway[16];
	uint8_t backed_up;
	uint8_t restored;
};

/* Monitor Mode Manager */
struct monitor_manager {
	struct interface_backup *backups;
	uint32_t backup_count;
	uint32_t max_backups;
	uint8_t is_termux;
	uint8_t has_root;
};

/* Function prototypes */

/* Manager management */
struct monitor_manager *monitor_manager_init(void);
void monitor_manager_free(struct monitor_manager *manager);

/* Monitor mode control */
int monitor_enable(const char *interface);
int monitor_disable(const char *interface);
int monitor_check_status(const char *interface);
const char *monitor_get_status_name(int status);

/* Conflict process handling */
int monitor_kill_conflicting_processes(uint32_t process_mask);
int monitor_kill_networkmanager(void);
int monitor_kill_wpa_supplicant(void);
int monitor_kill_dhclient(void);
int monitor_detect_conflicts(void);
int monitor_list_conflicting_processes(char *buffer, size_t buflen);

/* Interface backup and restoration */
int monitor_backup_interface(struct monitor_manager *manager,
                            const char *interface);
int monitor_restore_interface(struct monitor_manager *manager,
                             const char *interface);
int monitor_restore_all(struct monitor_manager *manager);

/* Platform-specific */
int monitor_enable_linux(const char *interface);
int monitor_enable_termux(const char *interface);
int monitor_enable_android(const char *interface);

/* MAC address control */
int monitor_change_mac(const char *interface, const uint8_t *mac);
int monitor_reset_mac(const char *interface);
int monitor_randomize_mac(const char *interface);

/* Channel control */
int monitor_set_channel(const char *interface, uint8_t channel);
int monitor_set_bandwidth(const char *interface, uint8_t width_mhz);
int monitor_get_current_channel(const char *interface);

/* TX Power control */
int monitor_set_tx_power(const char *interface, int8_t dbm);
int monitor_get_tx_power(const char *interface);
int monitor_get_tx_power_range(const char *interface, int8_t *min, int8_t *max);

/* Cleanup and restoration */
int monitor_cleanup_on_exit(struct monitor_manager *manager);
int monitor_force_interface_down(const char *interface);
int monitor_reset_to_managed(const char *interface);

/* Termux-specific utilities */
int monitor_check_termux_permissions(void);
int monitor_request_storage_permission(void);
int monitor_setup_termux_environment(void);
int monitor_detect_usb_device(char *device_name, size_t len);

#endif /* MONITOR_MODE_H */
