#include "aes_encryption_system.h"
#include "aes_state.h"
#include <iostream>

#define LOG(x) std::cout << x << std::endl

void DataLoaded::start(AESEncryptionSystem* sys) {
	if (!sys) {
		LOG("DataLoaded::start: system is null");
		return;
	}

	LOG("DataLoaded::start: starting processing");
	sys->setState(Processing::instance());
}

void DataLoaded::invalid_command(AESEncryptionSystem* sys) {
	LOG("DataLoaded::invalid_command: invalid command in DataLoaded state");
	sys->setState(ErrorState::instance());
} 