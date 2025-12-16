#include "aes_encryption_system.h"
#include "aes_state.h"
#include <iostream>

#define LOG(x) std::cout << x << std::endl

void Processing::invalid_command(AESEncryptionSystem* sys) {
	LOG("Processing::invalid_command: invalid command in Processing state");
	sys->setState(ErrorState::instance());
}

void Processing::onEntry(AESEncryptionSystem* sys) {
	LOG("Processing::onEntry: computing block");
	sys->compute();
	sys->setState(Done::instance());
}
