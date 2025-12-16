#include "aes_encryption_system.h"
#include "aes_state.h"
#include <iostream>

#define LOG(x) std::cout << x << std::endl

void Idle::load_key(AESEncryptionSystem* sys, const uint8_t* key) {
    if (sys == nullptr) {
        LOG("Idle::load_key: system pointer is null");
        return;
    }

    if (key == nullptr) {
        LOG("Idle::load_key: null key provided");
        sys->invalid_command();
        return;
    }

    // Load key into the context
    sys->setKey(key);
    LOG("Idle::load_key: key loaded successfully");

    // Transition to KeyLoaded state
    sys->setState(KeyLoaded::instance());
}

void Idle::invalid_command(AESEncryptionSystem* sys) {
    LOG("Idle::invalid_command: invalid command in Idle state");
    sys->setState(ErrorState::instance());
}


