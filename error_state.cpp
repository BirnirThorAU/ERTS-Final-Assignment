#include "aes_encryption_system.h"
#include "aes_state.h"
#include <iostream>

#define LOG(x) std::cout << x << std::endl

void ErrorState::reset(AESEncryptionSystem* sys) {
	if (!sys) return;
	LOG("ErrorState::reset: returning to Idle");
	sys->setState(Idle::instance());
}
