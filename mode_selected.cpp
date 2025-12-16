#include "aes_encryption_system.h"
#include "aes_state.h"
#include <iostream>

#define LOG(x) std::cout << x << std::endl

void ModeSelected::load_data(AESEncryptionSystem* sys, const uint8_t* data) {
	if (!sys || !data) {
		LOG("ModeSelected::load_data: invalid args");
		if (sys) sys->invalid_command();
		return;
	}

	sys->setData(data);
	LOG("ModeSelected::load_data: data loaded");
	sys->setState(DataLoaded::instance());
}

void ModeSelected::invalid_command(AESEncryptionSystem* sys) {
	LOG("ModeSelected::invalid_command: invalid command in ModeSelected state");
	sys->setState(ErrorState::instance());
}
