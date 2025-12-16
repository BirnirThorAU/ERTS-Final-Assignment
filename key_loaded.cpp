#include "aes_encryption_system.h"
#include "aes_state.h"
#include "aes_mode.h"
#include <iostream>

#define LOG(x) std::cout << x << std::endl

void KeyLoaded::set_mode(AESEncryptionSystem* sys, AESMode mode) {
	if (!sys) {
		LOG("KeyLoaded::set_mode: invalid args");
		if (sys) sys->invalid_command();
		return;
	}

	// Store the mode in context
	sys->setMode(mode);
	LOG("KeyLoaded::set_mode: mode accepted");
	sys->setState(ModeSelected::instance());
}

void KeyLoaded::invalid_command(AESEncryptionSystem* sys) {
	LOG("KeyLoaded::invalid_command: invalid command in KeyLoaded state");
	sys->setState(ErrorState::instance());
}
