#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "aes_block.h"

// ------------------- Utilities ---------------------
void print_hex(const char* label, const uint8_t data[16]) {
	printf("%s: ", label);
	for (int i = 0; i < 16; i++)
		printf("%02X ", data[i]);
	printf("\n");
}

void run_test(
	const char* test_name,
	uint8_t key[16],
	uint8_t plaintext[16],
	const uint8_t expected_cipher[16],
	const char* rawtext
) {
	uint8_t cipher[16] = { 0 };
	uint8_t decrypted[16] = { 0 };
	int mismatch = 0;

	printf("\n=== %s ===\n", test_name);

	aes_accelerator(key, plaintext, cipher, true);

	if (rawtext)
		printf("Plaintext       : %s\n", rawtext);
	print_hex("Plaintext (HEX) ", plaintext);
	print_hex("Key             ", key);
	print_hex("Cipher(HW)      ", cipher);
	if (expected_cipher)
		print_hex("Cipher(EXP)     ", expected_cipher);

	// Compare to expected if available
	if (expected_cipher) {
		for (int i = 0; i < 16; i++) {
			if (cipher[i] != expected_cipher[i]) mismatch = 1;
		}
		if (mismatch) printf("ENCRYPT mismatch!\n");
		else printf("ENCRYPT matches expected ciphertext.\n");
	}

	// Decrypt back
	aes_accelerator(key, cipher, decrypted, false);
	print_hex("Decrypted (HEX) ", decrypted);
	if (rawtext) {
		char output[17];
		for (int i = 0; i < 16; i++) {
			output[i] = (char)decrypted[i];
		}
		output[16] = '\0';
		printf("Decrypted Text  : %s\n", output);
	}

	mismatch = 0;
	for (int i = 0; i < 16; i++) {
		if (decrypted[i] != plaintext[i]) mismatch = 1;
	}

	if (mismatch) printf("DECRYPT mismatch!\n");
	else printf("DECRYPT recovered original plaintext.\n");
}

int main2() {
	printf("=== AES Accelerator HLS Testbench ===\n");

	// ---------- Test Vector 1 ----------
	uint8_t key1[16] = {
		0x2b,0x7e,0x15,0x16,
		0x28,0xae,0xd2,0xa6,
		0xab,0xf7,0x15,0x88,
		0x09,0xcf,0x4f,0x3c
	};
	uint8_t pt1[16] = {
		0x32,0x43,0xf6,0xa8,
		0x88,0x5a,0x30,0x8d,
		0x31,0x31,0x98,0xa2,
		0xe0,0x37,0x07,0x34
	};
	uint8_t exp1[16] = {
		0x39,0x25,0x84,0x1d,
		0x02,0xdc,0x09,0xfb,
		0xdc,0x11,0x85,0x97,
		0x19,0x6a,0x0b,0x32
	};

	run_test("TEST 1: Random Example", key1, pt1, exp1, NULL);

	// ---------- Test Vector 2 (Zero key, zero block) ----------
	uint8_t key2[16] = { 0 };
	uint8_t pt2[16] = { 0 };
	uint8_t exp2[16] = {
		0x66,0xe9,0x4b,0xd4,
		0xef,0x8a,0x2c,0x3b,
		0x88,0x4c,0xfa,0x59,
		0xca,0x34,0x2b,0x2e
	};

	run_test("TEST 2: Zero Key / Zero Plaintext", key2, pt2, exp2, NULL);

	// ---------- Test Vector 3 Readable text ----------
	const char* input = "Birnir";
	uint8_t userKey[16] = {
		0x00,0x01,0x02,0x03,
		0x04,0x05,0x06,0x07,
		0x08,0x09,0x0A,0x0B,
		0x0C,0x0D,0x0E,0x0F
	};
	uint8_t userPT[16] = { 0 };

	for (int i = 0; i < 16 && input[i] != '\0'; i++)
		userPT[i] = (uint8_t)input[i];

	run_test("TEST 3: Readable Text Input", key1, userPT, NULL, input);

	return 0;
}