#pragma once
#include "aes_mode.h"
#include <string>
#include <cstdint>

// Forward declarations to avoid circular includes
class AESEncryptionSystem;

class AESState {
public:
	virtual ~AESState() {}

	// Commands
	virtual void load_key(AESEncryptionSystem* system, const uint8_t* key) {}
	virtual void set_mode(AESEncryptionSystem* system, AESMode mode) {}
	virtual void load_data(AESEncryptionSystem* system, const uint8_t* data) {}
	virtual void start(AESEncryptionSystem* system) {}
	virtual void read_result(AESEncryptionSystem* system, uint8_t* out) {}
	virtual void invalid_command(AESEncryptionSystem* system) {}
	virtual void reset(AESEncryptionSystem* system) {}

	virtual void onEntry(AESEncryptionSystem* system) {}

	virtual std::string name() const =0;

protected:
	AESState() {}
};

class Idle : public AESState {
public:
	static Idle* instance() {
		static Idle instance;
		return &instance;
	}

	virtual void load_key(AESEncryptionSystem* system, const uint8_t* key) override;
	virtual void invalid_command(AESEncryptionSystem* system) override;

	std::string name() const override { return "Idle"; }

protected:
	Idle() = default;
};

class KeyLoaded : public AESState {
public:
	static KeyLoaded* instance() {
	 static KeyLoaded instance;
	 return &instance;
	}

	virtual void set_mode(AESEncryptionSystem* system, AESMode mode) override;
	virtual void invalid_command(AESEncryptionSystem* system) override;

	std::string name() const override { return "KeyLoaded"; }

protected:
	KeyLoaded() = default;
};

class ModeSelected : public AESState {
public:
	static ModeSelected* instance() {
	 static ModeSelected instance;
	 return &instance;
	}

	virtual void load_data(AESEncryptionSystem* system, const uint8_t* data) override;
	virtual void invalid_command(AESEncryptionSystem* system) override;

	std::string name() const override { return "ModeSelected"; }

protected:
	ModeSelected() = default;
};

class DataLoaded : public AESState {
public:
	static DataLoaded* instance() {
	 static DataLoaded instance;
	 return &instance;
	}

	virtual void start(AESEncryptionSystem* system) override;
	virtual void invalid_command(AESEncryptionSystem* system) override;

	std::string name() const override { return "DataLoaded"; }

protected:
	DataLoaded() = default;
};

class Processing : public AESState {
public:
	static Processing* instance() {
	 static Processing instance;
	 return &instance;
	}

	// Processing Complete command?
	virtual void invalid_command(AESEncryptionSystem* system) override;
	virtual void onEntry(AESEncryptionSystem* system) override;

	std::string name() const override { return "Processing"; }

protected:
	Processing() = default;
};

class Done : public AESState {
public:
	static Done* instance() {
	 static Done instance;
	 return &instance;
	}

	virtual void read_result(AESEncryptionSystem* system, uint8_t* out) override;
	virtual void invalid_command(AESEncryptionSystem* system) override;

	std::string name() const override { return "Done"; }

protected:
	Done() = default;
};

class ErrorState : public AESState {
public:
	static ErrorState* instance() {
	 static ErrorState instance;
	 return &instance;
	}

	virtual void reset(AESEncryptionSystem* system) override;

	std::string name() const override { return "ErrorState"; }

protected:
	ErrorState() = default;
};