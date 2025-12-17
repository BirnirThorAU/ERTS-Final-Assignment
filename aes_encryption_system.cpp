#include "aes_encryption_system.h"
#include <iostream>
#include "aes_block.h"

#define LOG(x) std::cout << x << std::endl

AESEncryptionSystem::AESEncryptionSystem() {
    currentState = Idle::instance();
	currentMode = AESMode::NONE;
    LOG("[Context] Created. Initial state = " << currentState->name());
}

AESEncryptionSystem::~AESEncryptionSystem() { LOG("[Context] Destroyed."); }

void AESEncryptionSystem::setMode(AESMode mode) {
	LOG("[Context] Mode set to " << (mode == AESMode::ENCRYPT ? "Encrypt" : "Decrypt"));
    currentMode = mode;
}

void AESEncryptionSystem::setState(AESState* newState) {
    LOG("[Context] Transition: " << currentState->name() << " -> " << newState->name());
    currentState = newState;
    currentState->onEntry(this);
}

void AESEncryptionSystem::load_key(const uint8_t* key) {
    currentState->load_key(this, key);
}

void AESEncryptionSystem::set_mode(AESMode mode) {
    currentState->set_mode(this, mode);
}

void AESEncryptionSystem::load_data(const uint8_t* data) {
    currentState->load_data(this, data);
}

void AESEncryptionSystem::start() {
    currentState->start(this);
}

void AESEncryptionSystem::read_result(uint8_t* out) {
    currentState->read_result(this, out);
}

void AESEncryptionSystem::invalid_command() {
    currentState->invalid_command(this);
}

void AESEncryptionSystem::reset() {
    currentState->reset(this);
}

// Helpers
void AESEncryptionSystem::setKey(const uint8_t* key) {
	std::memcpy(key_, key,16);
}

void AESEncryptionSystem::setData(const uint8_t* data) {
	std::memcpy(data_in_, data,16);
}

void AESEncryptionSystem::readResult(uint8_t* out) {
	std::memcpy(out, data_out_,16);
}

void AESEncryptionSystem::compute() {
    bool encrypt = (currentMode == AESMode::ENCRYPT);
	// HLS safe call to AES accelerator
    aes_accelerator(key_, data_in_, data_out_, encrypt);
}
