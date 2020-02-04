#pragma once
#include "CloudScanner.h"
#include "PluginInterface.h"
#include "EventsUMInterfaces.h"

class CloudPlugin : public IPlugin
{
public:
	// Inherited via IPlugin
	virtual ~CloudPlugin() override;
	AV_EVENT_RETURN_STATUS callback(int, void*, void**) override;
	void init(IManager* manager, HMODULE module, IConfig* configManager) override;
	void deinit() override;
	virtual int processCommand(std::string name, std::string args) override;
	virtual unsigned int getVersion() override;

	virtual std::string& getName() override;
	virtual HMODULE getModule() override;
	virtual std::string& getDescription() override;
	virtual IConfig* getConfig() override;

private:
	std::string name = std::string("CloudPlugin");
	std::string description = std::string("Just a cloud plugin.");
	HMODULE module;
	IConfig* configManager;
	ILogger* logger;
	IMessageManager* messageManager;
	CloudScanner* cloudScanner = NULL;
};