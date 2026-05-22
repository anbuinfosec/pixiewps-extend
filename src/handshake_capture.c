/*
 * handshake_capture.c - WPA2/WPA3 EAPOL handshake capture implementation
 * Copyright (c) 2026, @anbuinfosec
 * SPDX-License-Identifier: GPL-3.0+
 */

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdio.h>
#include "handshake_capture.h"
#include "utils.h"

/* Initialize handshake engine */
struct handshake_engine *handshake_engine_init(uint32_t max_records)
{
	if (max_records == 0)
		max_records = HANDSHAKE_MAX_RECORDS;

	struct handshake_engine *engine = malloc(sizeof(*engine));
	if (!engine) return NULL;

	engine->records = malloc(sizeof(struct handshake_record) * max_records);
	if (!engine->records) {
		free(engine);
		return NULL;
	}

	memset(engine->records, 0, sizeof(struct handshake_record) * max_records);
	engine->record_count = 0;
	engine->max_records = max_records;
	engine->auto_deauth_enabled = 0;
	engine->deauth_count = 0;
	engine->last_deauth = 0;

	return engine;
}

/* Free handshake engine */
void handshake_engine_free(struct handshake_engine *engine)
{
	if (!engine) return;
	free(engine->records);
	free(engine);
}

/* Parse EAPOL frame */
int handshake_parse_eapol(const uint8_t *frame, uint16_t frame_len,
                          struct handshake_message *msg)
{
	if (!frame || frame_len < sizeof(struct eapol_header) || !msg)
		return 0;

	struct eapol_header *eapol = (struct eapol_header *)frame;

	if (eapol->type != EAPOL_TYPE_KEY)
		return 0;

	if (frame_len < sizeof(struct eapol_header) + sizeof(struct wpa_key_frame))
		return 0;

	struct wpa_key_frame *key_frame = (struct wpa_key_frame *)
		(frame + sizeof(struct eapol_header));

	msg->message_number = 0;
	msg->frame_type = EAPOL_TYPE_KEY;
	msg->key_desc_version = (key_frame->key_info >> 8) & 0x07;
	msg->key_info = end_ntoh16((uint8_t *)&key_frame->key_info);
	msg->key_len = end_ntoh16((uint8_t *)&key_frame->key_len);
	msg->key_data_len = end_ntoh16((uint8_t *)&key_frame->key_data_len);

	memcpy(msg->replay_counter, key_frame->replay_counter, 8);
	memcpy(msg->key_nonce, key_frame->key_nonce, 32);
	memcpy(msg->key_iv, key_frame->key_iv, 16);
	memcpy(msg->key_rsc, key_frame->key_rsc, 8);
	memcpy(msg->key_mic, key_frame->key_mic, 16);

	if (msg->key_data_len > 0 && msg->key_data_len <= 256) {
		memcpy(msg->key_data, key_frame->key_data, msg->key_data_len);
	}

	msg->captured_at = time(NULL);
	return 1;
}

/* Parse WPA Key Frame */
int handshake_parse_wpa_key(const uint8_t *key_data, uint16_t data_len,
                            struct wpa_key_frame *key_frame)
{
	if (!key_data || data_len < sizeof(struct wpa_key_frame) || !key_frame)
		return 0;

	memcpy(key_frame, key_data, sizeof(struct wpa_key_frame));
	return 1;
}

/* Detect handshake message number (1-4) */
int handshake_detect_message_number(const struct wpa_key_frame *key1,
                                    const struct wpa_key_frame *key2)
{
	if (!key1 || !key2)
		return 0;

	uint16_t info1 = end_ntoh16((uint8_t *)&key1->key_info);
	uint16_t info2 = end_ntoh16((uint8_t *)&key2->key_info);

	int ack1 = (info1 & WPA_KEY_INFO_ACK) != 0;
	int mic1 = (info1 & WPA_KEY_INFO_MIC) != 0;
	int secure1 = (info1 & WPA_KEY_INFO_SECURE) != 0;

	int ack2 = (info2 & WPA_KEY_INFO_ACK) != 0;
	int mic2 = (info2 & WPA_KEY_INFO_MIC) != 0;
	int secure2 = (info2 & WPA_KEY_INFO_SECURE) != 0;

	/* Message 1: AP -> Client, ACK=1, MIC=0, Secure=0 */
	if (ack1 && !mic1 && !secure1)
		return 1;

	/* Message 2: Client -> AP, ACK=0, MIC=1, Secure=0 */
	if (!ack2 && mic2 && !secure2)
		return 2;

	/* Message 3: AP -> Client, ACK=1, MIC=1, Secure=1 */
	if (ack2 && mic2 && secure2)
		return 3;

	/* Message 4: Client -> AP, ACK=0, MIC=1, Secure=0/1 */
	if (!ack2 && mic2)
		return 4;

	return 0;
}

/* Add EAPOL message to handshake record */
int handshake_add_message(struct handshake_engine *engine, const uint8_t *bssid,
                          const uint8_t *client_mac, const uint8_t *frame,
                          uint16_t frame_len)
{
	if (!engine || !bssid || !client_mac || !frame)
		return 0;

	struct handshake_message msg;
	if (!handshake_parse_eapol(frame, frame_len, &msg))
		return 0;

	struct handshake_record *record = handshake_find_record(engine, bssid, client_mac);

	if (!record && engine->record_count >= engine->max_records)
		return 0;

	if (!record) {
		/* Create new record */
		record = &engine->records[engine->record_count];
		memcpy(record->bssid, bssid, 6);
		memcpy(record->client_mac, client_mac, 6);
		record->wpa_version = 2; /* Default to WPA2 */
		record->started_at = time(NULL);
		record->timeout_seconds = 60;
		engine->record_count++;
	}

	/* Determine message number */
	int msg_num = 0;
	struct wpa_key_frame *key_frame = (struct wpa_key_frame *)(frame + sizeof(struct eapol_header));

	/* Use simple logic: check replay counter ordering */
	uint64_t *prev_counter = NULL;

	if (record->msg_mask == 0) {
		msg_num = 1;
	} else if (record->msg_mask & 1) { /* Have msg1 */
		if (record->msg_mask & 2) { /* Have msg2 */
			if (record->msg_mask & 4) { /* Have msg3 */
				msg_num = 4;
			} else {
				msg_num = 3;
			}
		} else {
			msg_num = 2;
		}
	}

	if (msg_num < 1 || msg_num > 4)
		msg_num = (record->msg_mask + 1);

	if (msg_num == 1) {
		memcpy(&record->msg1, &msg, sizeof(msg));
		record->msg_mask |= 1;
	} else if (msg_num == 2) {
		memcpy(&record->msg2, &msg, sizeof(msg));
		record->msg_mask |= 2;
	} else if (msg_num == 3) {
		memcpy(&record->msg3, &msg, sizeof(msg));
		record->msg_mask |= 4;
	} else if (msg_num == 4) {
		memcpy(&record->msg4, &msg, sizeof(msg));
		record->msg_mask |= 8;
		record->completed_at = time(NULL);
		record->is_complete = 1;
	}

	handshake_update_priority(record);
	return 1;
}

/* Find handshake record by BSSID and Client MAC */
struct handshake_record *handshake_find_record(struct handshake_engine *engine,
                                              const uint8_t *bssid,
                                              const uint8_t *client_mac)
{
	if (!engine || !bssid || !client_mac)
		return NULL;

	for (uint32_t i = 0; i < engine->record_count; i++) {
		if (memcmp(engine->records[i].bssid, bssid, 6) == 0 &&
		    memcmp(engine->records[i].client_mac, client_mac, 6) == 0) {
			return &engine->records[i];
		}
	}

	return NULL;
}

/* Get best handshake target (highest priority) */
struct handshake_record *handshake_get_best_target(struct handshake_engine *engine)
{
	if (!engine || engine->record_count == 0)
		return NULL;

	struct handshake_record *best = &engine->records[0];
	for (uint32_t i = 1; i < engine->record_count; i++) {
		if (engine->records[i].is_complete &&
		    engine->records[i].priority_score > best->priority_score)
			best = &engine->records[i];
	}

	return best->is_complete ? best : NULL;
}

/* Update handshake priority score */
void handshake_update_priority(struct handshake_record *record)
{
	if (!record) return;

	record->priority_score = 0;

	/* Complete handshake = 100 points */
	if (record->is_complete)
		record->priority_score += 100;
	else
		record->priority_score += record->msg_mask * 20;

	/* WPA3 = 50 points */
	if (record->wpa_version == 3)
		record->priority_score += 50;

	/* Fast Roaming = 10 points */
	if (record->has_ftie)
		record->priority_score += 10;

	/* PMF = 15 points */
	if (record->pmf_capability == 2)
		record->priority_score += 15;
}

/* Check if handshake is complete */
int handshake_is_complete(struct handshake_record *record)
{
	if (!record) return 0;
	return record->msg_mask == 0x0F; /* All 4 messages */
}

/* Validate handshake integrity */
int handshake_is_valid(struct handshake_record *record)
{
	if (!record || !handshake_is_complete(record))
		return 0;

	/* Check replay counter is increasing */
	uint64_t *rc1 = (uint64_t *)record->msg1.replay_counter;
	uint64_t *rc2 = (uint64_t *)record->msg2.replay_counter;
	uint64_t *rc3 = (uint64_t *)record->msg3.replay_counter;
	uint64_t *rc4 = (uint64_t *)record->msg4.replay_counter;

	if (end_ntoh64((uint8_t *)rc1) >= end_ntoh64((uint8_t *)rc2))
		return 0;
	if (end_ntoh64((uint8_t *)rc3) >= end_ntoh64((uint8_t *)rc4))
		return 0;

	return 1;
}

/* Verify handshake MIC (placeholder) */
int handshake_verify_mic(struct handshake_record *record, const uint8_t *pmk,
                        const uint8_t *ptk)
{
	if (!record || !pmk || !ptk)
		return 0;

	/* TODO: Implement proper MIC verification using HMAC-SHA1 or AES-CMAC */
	return 1;
}

/* Export handshake to PCAP format (placeholder) */
int handshake_export_pcap(struct handshake_engine *engine, const char *filename)
{
	if (!engine || !filename)
		return 0;

	FILE *fp = fopen(filename, "wb");
	if (!fp) return 0;

	/* Write PCAP header */
	/* TODO: Implement full PCAP writing */

	fclose(fp);
	return 1;
}

/* Export to hc22000 format (for hashcat) */
int handshake_export_hc22000(struct handshake_record *record, const char *filename)
{
	if (!record || !filename)
		return 0;

	FILE *fp = fopen(filename, "w");
	if (!fp) return 0;

	/* hc22000 format for WPA-PBKDF2-PMK-PSK-PMK
	   ESSID:MAC AP:MAC STA:version:key_version:key_mic:key_data
	*/

	fprintf(fp, "%02x%02x%02x%02x%02x%02x:%02x%02x%02x%02x%02x%02x:",
		record->bssid[0], record->bssid[1], record->bssid[2],
		record->bssid[3], record->bssid[4], record->bssid[5],
		record->client_mac[0], record->client_mac[1], record->client_mac[2],
		record->client_mac[3], record->client_mac[4], record->client_mac[5]);

	/* Write message data */
	for (int i = 0; i < 32; i++)
		fprintf(fp, "%02x", record->msg1.key_nonce[i]);
	fprintf(fp, ":");
	for (int i = 0; i < 16; i++)
		fprintf(fp, "%02x", record->msg2.key_mic[i]);
	fprintf(fp, ":");
	/* More data... */

	fclose(fp);
	return 1;
}

/* Send deauth burst */
int handshake_send_deauth_burst(const uint8_t *interface, const uint8_t *bssid,
                               const uint8_t *client_mac, uint8_t count)
{
	if (!interface || !bssid || !client_mac || count == 0)
		return 0;

	/* TODO: Implement packet injection for deauth frames */
	return 1;
}

/* Monitor for reassociation */
int handshake_monitor_for_reassoc(struct handshake_engine *engine,
                                 const uint8_t *bssid)
{
	if (!engine || !bssid)
		return 0;

	/* TODO: Implement reassociation monitoring */
	return 1;
}

/* Cleanup expired handshakes */
void handshake_cleanup_expired(struct handshake_engine *engine, uint32_t timeout_sec)
{
	if (!engine)
		return;

	time_t now = time(NULL);
	for (uint32_t i = 0; i < engine->record_count; i++) {
		if (!engine->records[i].is_complete) {
			time_t age = now - engine->records[i].started_at;
			if (age > timeout_sec) {
				handshake_reset_record(&engine->records[i]);
				/* Shift array */
				if (i < engine->record_count - 1) {
					memmove(&engine->records[i], &engine->records[i + 1],
						sizeof(struct handshake_record) * 
						(engine->record_count - i - 1));
				}
				engine->record_count--;
				i--;
			}
		}
	}
}

/* Reset handshake record */
void handshake_reset_record(struct handshake_record *record)
{
	if (!record) return;
	memset(record, 0, sizeof(*record));
}

/* Get complete handshake count */
uint32_t handshake_get_complete_count(struct handshake_engine *engine)
{
	if (!engine) return 0;

	uint32_t count = 0;
	for (uint32_t i = 0; i < engine->record_count; i++) {
		if (engine->records[i].is_complete)
			count++;
	}
	return count;
}

/* Get partial handshake count */
uint32_t handshake_get_partial_count(struct handshake_engine *engine)
{
	if (!engine) return 0;

	uint32_t count = 0;
	for (uint32_t i = 0; i < engine->record_count; i++) {
		if (!engine->records[i].is_complete && engine->records[i].msg_mask > 0)
			count++;
	}
	return count;
}

/* Print handshake statistics */
void handshake_print_stats(struct handshake_engine *engine)
{
	if (!engine) return;

	printf("\n=== Handshake Capture Statistics ===\n");
	printf("Total records: %u\n", engine->record_count);
	printf("Complete: %u\n", handshake_get_complete_count(engine));
	printf("Partial: %u\n", handshake_get_partial_count(engine));
	printf("Deauth count: %u\n", engine->deauth_count);
	printf("====================================\n");
}
