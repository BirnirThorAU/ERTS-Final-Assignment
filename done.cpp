#include "aes_encryption_system.h"
#include "aes_state.h"
#include <iostream>
#include <cstring>

#define LOG(x) std::cout << x << std::endl

void Done::read_result(AESEncryptionSystem* sys, uint8_t* out) {
	if (!sys || !out) {
		LOG("Done::read_result: invalid args");
		if (sys) sys->invalid_command();
		return;
	}

	sys->readResult(out);
	LOG("Done::read_result: providing result and returning to KeyLoaded");
	sys->setState(KeyLoaded::instance());
}

void Done::invalid_command(AESEncryptionSystem* sys) {
	LOG("Done::invalid_command: invalid command in Done state");
	sys->setState(ErrorState::instance());
}
