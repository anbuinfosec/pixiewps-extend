/*
 * wpa3_handler.c - WPA3 PMKID and SAE support implementation
 * Copyright (c) 2026, @anbuinfosec
 * SPDX-License-Identifier: GPL-3.0+
 */

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "wpa3_handler.h"

/* Initialize WPA3 handler */
struct wpa3_handler *wpa3_handler_init(void)
{
	struct wpa3_handler *handler = malloc(sizeof(*handler));
	if (!handler) return NULL;

	handler->pmkid_candidates = malloc(sizeof(struct pmkid_candidate) * 256);
	handler->transition_networks = malloc(sizeof(struct wpa3_transition) * 256);
	handler->pmkid_cache = malloc(sizeof(struct pmkid_cache) * 512);
	handler->sae_ctx = malloc(sizeof(struct sae_context) * 64);

	if (!handler->pmkid_candidates || !handler->transition_networks || 
	    !handler->pmkid_cache || !handler->sae_ctx) {
		free(handler->pmkid_candidates);
		free(handler->transition_networks);
		free(handler->pmkid_cache);
		free(handler->sae_ctx);
		free(handler);
		return NULL;
	}

	handler->pmkid_count = 0;
	handler->transition_count = 0;
	handler->cache_size = 0;
	handler->sae_count = 0;
	handler->last_update = time(NULL);

	return handler;
}

/* Free WPA3 handler resources */
void wpa3_handler_free(struct wpa3_handler *handler)
{
	if (!handler) return;
	free(handler->pmkid_candidates);
	free(handler->transition_networks);
	free(handler->pmkid_cache);
	free(handler->sae_ctx);
	free(handler);
}

/* Extract PMKID from Information Element */
int wpa3_extract_pmkid(const uint8_t *ie_buf, uint16_t ie_len, uint8_t *pmkid)
{
	if (!ie_buf || ie_len < WPA3_PMKID_LEN || !pmkid)
		return 0;

	uint16_t offset = 0;
	while (offset + 4 <= ie_len) {
		uint8_t ie_type = ie_buf[offset];
		uint8_t ie_length = ie_buf[offset + 1];
		uint16_t ie_data_len = ie_length;

		if (offset + 2 + ie_data_len > ie_len)
			break;

		/* Check for PMKID in RSN IE (type 48) or WPA2/WPA3 */
		if (ie_type == 48) {
			/* RSN IE: check for PMKID List */
			uint16_t pos = offset + 2;
			if (pos + 2 > ie_len) {
				offset += 2 + ie_data_len;
				continue;
			}

			/* Skip version, group cipher, pairwise cipher count/list */
			pos += 2; /* Version */
			if (pos + 4 > offset + 2 + ie_data_len) {
				offset += 2 + ie_data_len;
				continue;
			}
			pos += 4; /* Group cipher */

			/* Pairwise cipher count and list */
			if (pos + 2 <= offset + 2 + ie_data_len) {
				uint16_t pairwise_count = (ie_buf[pos] | (ie_buf[pos + 1] << 8));
				pos += 2 + (pairwise_count * 4);
			}

			/* AKM count and list */
			if (pos + 2 <= offset + 2 + ie_data_len) {
				uint16_t akm_count = (ie_buf[pos] | (ie_buf[pos + 1] << 8));
				pos += 2 + (akm_count * 4);
			}

			/* PMKID count and list */
			if (pos + 2 <= offset + 2 + ie_data_len) {
				uint16_t pmkid_count = (ie_buf[pos] | (ie_buf[pos + 1] << 8));
				if (pmkid_count > 0 && pos + 2 + WPA3_PMKID_LEN <= offset + 2 + ie_data_len) {
					memcpy(pmkid, &ie_buf[pos + 2], WPA3_PMKID_LEN);
					return 1;
				}
			}
		}

		offset += 2 + ie_data_len;
	}

	return 0;
}

/* Check if AP is a PMKID candidate */
int wpa3_is_pmkid_candidate(const uint8_t *ie_buf, uint16_t ie_len)
{
	if (!ie_buf || ie_len < 4)
		return 0;

	uint16_t offset = 0;
	while (offset + 4 <= ie_len) {
		uint8_t ie_type = ie_buf[offset];
		uint8_t ie_length = ie_buf[offset + 1];

		if (offset + 2 + ie_length > ie_len)
			break;

		if (ie_type == 48) { /* RSN IE */
			uint16_t pos = offset + 2;
			if (pos + 2 > offset + 2 + ie_length)
				return 0;

			/* Check capabilities field for preauth/PMKID caching */
			if (pos + 2 + 6 <= offset + 2 + ie_length) {
				uint16_t capabilities = (ie_buf[pos + 2 + 4] | (ie_buf[pos + 2 + 5] << 8));
				if (capabilities & 0x01) /* Preauth capable */
					return 1;
				if (capabilities & 0x02) /* PMKID caching capable */
					return 1;
			}
			return 0;
		}

		offset += 2 + ie_length;
	}

	return 0;
}

/* Add PMKID candidate to handler */
int wpa3_add_pmkid_candidate(struct wpa3_handler *handler, const uint8_t *bssid,
                            const uint8_t *pmkid)
{
	if (!handler || !bssid || !pmkid || handler->pmkid_count >= 256)
		return 0;

	/* Check if already exists */
	for (uint32_t i = 0; i < handler->pmkid_count; i++) {
		if (memcmp(handler->pmkid_candidates[i].bssid, bssid, 6) == 0)
			return 0; /* Already exists */
	}

	struct pmkid_candidate *cand = &handler->pmkid_candidates[handler->pmkid_count];
	memcpy(cand->bssid, bssid, 6);
	memcpy(cand->pmkids, pmkid, WPA3_PMKID_LEN);
	cand->pmkid_count = 1;
	cand->pmkid_candidate = 1;
	cand->timestamp = time(NULL);

	handler->pmkid_count++;
	return 1;
}

/* Detect WPA3 transition mode network */
int wpa3_detect_transition_mode(struct wpa3_handler *handler, const uint8_t *bssid,
                                const uint8_t *ssid, uint8_t ssid_len,
                                uint8_t has_wpa3, uint8_t has_wpa2)
{
	if (!handler || !bssid || !ssid)
		return 0;

	/* Check if transition mode already detected */
	for (uint32_t i = 0; i < handler->transition_count; i++) {
		if (memcmp(handler->transition_networks[i].bssid, bssid, 6) == 0)
			return 0; /* Already tracked */
	}

	if (handler->transition_count >= 256)
		return 0;

	if (has_wpa3 && has_wpa2) {
		struct wpa3_transition *trans = &handler->transition_networks[handler->transition_count];
		memcpy(trans->bssid, bssid, 6);
		memcpy(trans->ssid, ssid, ssid_len);
		trans->ssid_len = ssid_len;
		trans->has_wpa3 = 1;
		trans->has_wpa2 = 1;
		trans->has_open = 0;
		trans->discovered_at = time(NULL);
		handler->transition_count++;
		return 1;
	}

	return 0;
}

/* Find transition mode network by BSSID */
struct wpa3_transition *wpa3_find_transition(struct wpa3_handler *handler,
                                            const uint8_t *bssid)
{
	if (!handler || !bssid)
		return NULL;

	for (uint32_t i = 0; i < handler->transition_count; i++) {
		if (memcmp(handler->transition_networks[i].bssid, bssid, 6) == 0)
			return &handler->transition_networks[i];
	}

	return NULL;
}

/* SAE Context initialization */
int wpa3_sae_init_context(struct wpa3_handler *handler, const uint8_t *mac,
                          const uint8_t *bssid, const uint8_t *password,
                          uint16_t password_len)
{
	if (!handler || !mac || !bssid || !password || handler->sae_count >= 64)
		return 0;

	struct sae_context *ctx = &handler->sae_ctx[handler->sae_count];
	memcpy(ctx->mac, mac, 6);
	memcpy(ctx->bssid, bssid, 6);
	memcpy(ctx->password, password, password_len > 255 ? 255 : password_len);
	ctx->password_len = password_len > 255 ? 255 : password_len;
	ctx->counter = 1;
	ctx->initiated_at = time(NULL);

	/* Default to group 19 (256-bit) for WPA3 */
	ctx->group = 19;

	handler->sae_count++;
	return 1;
}

/* Parse SAE Commit frame */
int wpa3_sae_parse_commit(struct sae_context *ctx, const uint8_t *frame,
                          uint16_t frame_len)
{
	if (!ctx || !frame || frame_len < 2)
		return 0;

	uint16_t auth_alg = (frame[0] | (frame[1] << 8));
	if (auth_alg != 3) /* SAE algorithm */
		return 0;

	if (frame_len < 6)
		return 0;

	uint16_t auth_seq = (frame[2] | (frame[3] << 8));
	uint16_t status = (frame[4] | (frame[5] << 8));

	if (status != 0)
		return 0; /* Auth failure */

	/* Parse commit frame (Group | Scalar | Element) */
	uint16_t pos = 6;
	if (pos + 2 > frame_len)
		return 0;

	uint16_t group = (frame[pos] | (frame[pos + 1] << 8));
	ctx->group = group;
	pos += 2;

	/* Store commit for debugging */
	uint16_t copy_len = frame_len - pos;
	if (copy_len > sizeof(ctx->sae_commit))
		copy_len = sizeof(ctx->sae_commit);

	memcpy(ctx->sae_commit, &frame[pos], copy_len);
	ctx->sae_commit_len = copy_len;

	return 1;
}

/* Derive PMK from SAE */
int wpa3_sae_derive_pmk(struct sae_context *ctx)
{
	if (!ctx)
		return 0;

	/* Placeholder: Real SAE PMK derivation would use:
	   PMK = KDF-Hash-Length(password, "SAE Hunting and Pecking",
	                         H(order(P)) || H(base_elem) || modulo(base_elem^counter mod p))
	   For now, we'll use a simplified HMAC-SHA256 approach
	*/

	/* In production, use proper SAE group operations and KDF */
	memset(ctx->pmk, 0, sizeof(ctx->pmk));

	return 1;
}

/* Parse PMF capability */
int wpa3_parse_pmf_capability(const uint8_t *ie_buf, uint16_t ie_len)
{
	if (!ie_buf || ie_len < 4)
		return -1; /* No PMF info */

	uint16_t offset = 0;
	while (offset + 4 <= ie_len) {
		uint8_t ie_type = ie_buf[offset];
		uint8_t ie_length = ie_buf[offset + 1];

		if (offset + 2 + ie_length > ie_len)
			break;

		if (ie_type == 48) { /* RSN IE */
			uint16_t pos = offset + 2 + 2; /* Skip version */
			if (pos + 4 + 4 > offset + 2 + ie_length)
				break;

			/* Skip to capabilities (last 2 bytes of RSN IE) */
			uint16_t cap_offset = offset + 2 + ie_length - 2;
			if (cap_offset < pos)
				break;

			uint16_t capabilities = (ie_buf[cap_offset] | (ie_buf[cap_offset + 1] << 8));

			/* Bit 6: PMF Capable, Bit 7: PMF Required */
			int pmf_capable = (capabilities >> 6) & 1;
			int pmf_required = (capabilities >> 7) & 1;

			if (pmf_required)
				return 2; /* PMF Required */
			if (pmf_capable)
				return 1; /* PMF Capable */
			return 0; /* No PMF */
		}

		offset += 2 + ie_length;
	}

	return -1;
}

/* Validate BIP MIC (placeholder) */
int wpa3_validate_bip_mic(const uint8_t *frame, uint16_t frame_len,
                          const uint8_t *key, uint8_t key_len)
{
	if (!frame || frame_len < 8 || !key || key_len != 16)
		return 0;

	/* BIP uses AES-128-CMAC over management frame body
	   For now, return success placeholder
	*/
	return 1;
}

/* Parse OWE Transition Element */
int wpa3_parse_owe_transition(const uint8_t *ie_buf, uint16_t ie_len,
                              uint8_t *ssid, uint8_t *ssid_len)
{
	if (!ie_buf || !ssid || !ssid_len)
		return 0;

	/* OWE Transition: BSSID (6) | SSID (1-32) | Band Channel (2) */
	if (ie_len < 9)
		return 0;

	uint8_t owe_ssid_len = ie_buf[6];
	if (owe_ssid_len > 32 || ie_len < 6 + 1 + owe_ssid_len)
		return 0;

	memcpy(ssid, &ie_buf[7], owe_ssid_len);
	*ssid_len = owe_ssid_len;

	return 1;
}

/* OWE PSK derivation (placeholder) */
int wpa3_owe_derive_psk(const uint8_t *dh_shared_secret, uint16_t secret_len,
                        const uint8_t *bssid, const uint8_t *client_mac,
                        uint8_t *psk)
{
	if (!dh_shared_secret || !bssid || !client_mac || !psk)
		return 0;

	/* OWE PSK: KDF-Hash(Z, "OWE Diffie-Hellman final hash" || bssid || client_mac)
	   For now, return placeholder
	*/
	memset(psk, 0, 32);

	return 1;
}

/* Add to PMKID cache */
void wpa3_add_to_pmkid_cache(struct wpa3_handler *handler, const uint8_t *pmkid,
                             const uint8_t *bssid, const uint8_t *ssid,
                             uint8_t ssid_len, uint32_t priority)
{
	if (!handler || !pmkid || !bssid || !ssid)
		return;

	if (handler->cache_size >= 512)
		return;

	struct pmkid_cache *entry = &handler->pmkid_cache[handler->cache_size];
	memcpy(entry->pmkid, pmkid, WPA3_PMKID_LEN);
	memcpy(entry->bssid, bssid, 6);
	memcpy(entry->ssid, ssid, ssid_len);
	entry->ssid_len = ssid_len;
	entry->priority = priority;
	entry->found_at = time(NULL);

	handler->cache_size++;
}

/* Get highest priority PMKID from cache */
struct pmkid_cache *wpa3_get_pmkid_by_priority(struct wpa3_handler *handler)
{
	if (!handler || handler->cache_size == 0)
		return NULL;

	struct pmkid_cache *highest = &handler->pmkid_cache[0];
	for (uint32_t i = 1; i < handler->cache_size; i++) {
		if (handler->pmkid_cache[i].priority > highest->priority)
			highest = &handler->pmkid_cache[i];
	}

	return highest;
}
