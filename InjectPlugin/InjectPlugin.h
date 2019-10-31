#pragma once
#include "PluginInterface.h"
#include "EventsUMInterfaces.h"

typedef enum {
	CallbackProcessCreate,
	CallbackProcessExit,
	CallbackThreadCreate,
} CALLBACK_ID;

class InjectContext
{
public:
	InjectContext(ILogger* logger, int PID, std::string imageName);
	
	// getters setters
	void setInjected() { this->injected = true; }
	bool wasInjected() { return this->injected; }
	void setTID(int TID) { this->apcInfo.TID = TID; }
	int getTID() { return this->apcInfo.TID; }
#ifdef _WIN64
	bool getWow64() { return this->Wow64; }
#endif
	void* getApcInfoPtr() { return &this->apcInfo; }

	

private:
	APC_INFO apcInfo; // holds the buffer that will be passed to KM

	std::string imageName;
	ILogger* logger;
	bool injected;
#ifdef _WIN64
	bool Wow64;
#endif
};

typedef std::map<int, InjectContext*> ProcessMap;

class AVInject : public IPlugin
{
public:
	// Inherited via IPlugin
	virtual ~AVInject() override;
	AV_EVENT_RETURN_STATUS callback(int, void*, void**) override;
	void init(IManager* manager, HMODULE module, IConfig* configManager) override;
	void deinit() override;

	virtual std::string& getName() override;
	virtual HMODULE getModule() override;
	virtual std::string& getDescription() override;
	virtual IConfig* getConfig() override;
private:
	std::string name = std::string("InjectPlugin");
	std::string description = std::string("TODO");
	HMODULE module;
	IConfig* configManager;
	ILogger* logger;
	
	ProcessMap processMap;
};