#pragma once
#include "aes_state.h"
#include "aes_mode.h"
#include <string>
#include "memory"
#include <cstdint>

class AESEncryptionSystem {
public:
	AESEncryptionSystem();
	~AESEncryptionSystem();

	// Commands
	void load_key(const uint8_t* key);
	void set_mode(AESMode mode);
	void load_data(const uint8_t* data);
	void start();
	void read_result(uint8_t* out);
	void invalid_command();
	void reset();

private:
	friend class Idle;
	friend class KeyLoaded;
	friend class ModeSelected;
	friend class DataLoaded;
	friend class Processing;
	friend class Done;
	friend class ErrorState;

	void setMode(AESMode mode);
	void setState(AESState*);
	AESState* currentState;

	AESMode currentMode;

	uint8_t key_[16] = {0};
	uint8_t data_in_[16] = {0};
	uint8_t data_out_[16] = {0};

	void setKey(const uint8_t* key);
	void setData(const uint8_t* data);
	void compute();
	void readResult(uint8_t* out);
};