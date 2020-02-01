#pragma once
#include "PluginInterface.h"
#include "EventsUMInterfaces.h"

typedef enum {
	CallbackApcProcessInject,
} CALLBACK_ID;

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
	virtual unsigned int getVersion() override
	{
		return 1;
	}
	virtual std::string& getDescription() override;
	virtual IConfig* getConfig() override;

	virtual int processCommand(std::string name, std::string args) override;
private:
	std::string name = std::string("InjectPlugin");
	std::string description = std::string("TODO");
	HMODULE module;
	IConfig* configManager;
	ILogger* logger;
};