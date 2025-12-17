#include "aes_block.h"
#include <stdint.h>

static void KeyExpansion(const uint8_t* key, uint8_t roundKeys[176]) {
	for (int i = 0; i < 16; i++) {
		roundKeys[i] = key[i];
	}
	uint8_t temp[4];
	int bytesGenerated = 16;
	int rconIter = 1;

	while (bytesGenerated < 176) {
		for (int i = 0; i < 4; ++i) temp[i] = roundKeys[bytesGenerated - 4 + i];
		if (bytesGenerated % 16 == 0) {
			// rotate
			uint8_t t = temp[0]; temp[0] = temp[1]; temp[1] = temp[2]; temp[2] = temp[3]; temp[3] = t;
			// sub
			for (int i = 0; i < 4; ++i) temp[i] = sbox[temp[i]];
			temp[0] ^= rcon[rconIter++];
		}
		for (int i = 0; i < 4; ++i) {
			roundKeys[bytesGenerated] = roundKeys[bytesGenerated - 16] ^ temp[i];
			++bytesGenerated;
		}
	}
}

static uint8_t xtime(uint8_t x) { return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1b : 0x00)); }
static uint8_t mul(uint8_t x, uint8_t m) {
	switch (m) {
	case 0x01: return x;
	case 0x02: return xtime(x);
	case 0x03: return (uint8_t)(xtime(x) ^ x);
	case 0x09: return (uint8_t)(xtime(xtime(xtime(x))) ^ x);
	case 0x0b: return (uint8_t)(xtime(xtime(xtime(x))) ^ xtime(x) ^ x);
	case 0x0d: return (uint8_t)(xtime(xtime(xtime(x))) ^ xtime(xtime(x)) ^ x);
	case 0x0e: return (uint8_t)(xtime(xtime(xtime(x))) ^ xtime(xtime(x)) ^ xtime(x));
	default: return 0;
	}
}

static void SubBytes(uint8_t* s) { for (int i = 0; i < 16; ++i) s[i] = sbox[s[i]]; }
static void ShiftRows(uint8_t* s) {
	uint8_t t[16];
	t[0] = s[0]; t[1] = s[5]; t[2] = s[10]; t[3] = s[15];
	t[4] = s[4]; t[5] = s[9]; t[6] = s[14]; t[7] = s[3];
	t[8] = s[8]; t[9] = s[13]; t[10] = s[2]; t[11] = s[7];
	t[12] = s[12]; t[13] = s[1]; t[14] = s[6]; t[15] = s[11];
	for (int i = 0; i < 16; i++) {
		s[i] = t[i];
	}
}
static void MixColumns(uint8_t* s) {
	for (int c = 0; c < 4; ++c) {
		int i = 4 * c;
		uint8_t a0 = s[i], a1 = s[i + 1], a2 = s[i + 2], a3 = s[i + 3];
		s[i] = (uint8_t)(mul(a0, 0x02) ^ mul(a1, 0x03) ^ a2 ^ a3);
		s[i + 1] = (uint8_t)(a0 ^ mul(a1, 0x02) ^ mul(a2, 0x03) ^ a3);
		s[i + 2] = (uint8_t)(a0 ^ a1 ^ mul(a2, 0x02) ^ mul(a3, 0x03));
		s[i + 3] = (uint8_t)(mul(a0, 0x03) ^ a1 ^ a2 ^ mul(a3, 0x02));
	}
}
static void AddRoundKey(uint8_t* s, const uint8_t* rk) { for (int i = 0; i < 16; ++i) s[i] ^= rk[i]; }

static void InvSubBytes(uint8_t* s) {
	for (int i = 0; i < 16; i++) {
		s[i] = inv_sbox[s[i]];
	}
}

static void InvShiftRows(uint8_t* s) {
	uint8_t t[16];
	t[0] = s[0]; t[1] = s[13]; t[2] = s[10]; t[3] = s[7];
	t[4] = s[4]; t[5] = s[1]; t[6] = s[14]; t[7] = s[11];
	t[8] = s[8]; t[9] = s[5]; t[10] = s[2]; t[11] = s[15];
	t[12] = s[12]; t[13] = s[9]; t[14] = s[6]; t[15] = s[3];
	for (int i = 0; i < 16; i++) {
		s[i] = t[i];
	}
}
static void InvMixColumns(uint8_t* s) {
	for (int c = 0; c < 4; ++c) {
		int i = 4 * c;
		uint8_t a0 = s[i], a1 = s[i + 1], a2 = s[i + 2], a3 = s[i + 3];
		s[i] = (uint8_t)(mul(a0, 0x0e) ^ mul(a1, 0x0b) ^ mul(a2, 0x0d) ^ mul(a3, 0x09));
		s[i + 1] = (uint8_t)(mul(a0, 0x09) ^ mul(a1, 0x0e) ^ mul(a2, 0x0b) ^ mul(a3, 0x0d));
		s[i + 2] = (uint8_t)(mul(a0, 0x0d) ^ mul(a1, 0x09) ^ mul(a2, 0x0e) ^ mul(a3, 0x0b));
		s[i + 3] = (uint8_t)(mul(a0, 0x0b) ^ mul(a1, 0x0d) ^ mul(a2, 0x09) ^ mul(a3, 0x0e));
	}
}

static void AES128EncryptBlock(const uint8_t* key, const uint8_t* in, uint8_t* out) {
	uint8_t state[16];
	uint8_t roundKeys[176];
	for (int i = 0; i < 16; i++) {
		state[i] = in[i];
	}

	KeyExpansion(key, roundKeys);
	AddRoundKey(state, roundKeys);
	for (int r = 1; r <= 9; ++r) {
		SubBytes(state);
		ShiftRows(state);
		MixColumns(state);
		AddRoundKey(state, roundKeys + 16 * r);
	}
	SubBytes(state);
	ShiftRows(state);
	AddRoundKey(state, roundKeys + 160);
	for (int i = 0; i < 16; i++) {
		out[i] = state[i];
	}
}

static void AES128DecryptBlock(const uint8_t* key, const uint8_t* in, uint8_t* out) {
	uint8_t state[16];
	uint8_t roundKeys[176];
	for (int i = 0; i < 16; i++) {
		state[i] = in[i];
	}

	KeyExpansion(key, roundKeys);
	AddRoundKey(state, roundKeys + 160);
	for (int r = 9; r >= 1; --r) {
		InvShiftRows(state);
		InvSubBytes(state);
		AddRoundKey(state, roundKeys + 16 * r);
		InvMixColumns(state);
	}
	InvShiftRows(state);
	InvSubBytes(state);
	AddRoundKey(state, roundKeys);
	for (int i = 0; i < 16; i++) {
		out[i] = state[i];
	}
}

void aes_accelerator(
	uint8_t key[16],
	uint8_t data_in[16],
	uint8_t data_out[16],
	bool encrypt
) {
	if (encrypt) {
		AES128EncryptBlock(key, data_in, data_out);
	}
	else {
		AES128DecryptBlock(key, data_in, data_out);
	}
}