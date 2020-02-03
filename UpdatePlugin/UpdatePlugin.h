#pragma once
#include "PluginInterface.h"
#include "EventsUMInterfaces.h"
#include "httplib.h"
#include "json.hpp"
#include <thread>

class UpdatePlugin : public IPlugin
{
public:
	// Inherited via IPlugin
	virtual ~UpdatePlugin() override;
	AV_EVENT_RETURN_STATUS callback(int, void*, void**) override;
	void init(IManager* manager, HMODULE module, IConfig* configManager) override;
	void deinit() override;

	virtual std::string& getName() override;
	virtual HMODULE getModule() override;
	virtual unsigned int getVersion() override
	{
		return 1; // we won't be able to update ourselves
	}
	virtual std::string& getDescription() override;
	virtual IConfig* getConfig() override;

	virtual int processCommand(std::string name, std::string args) override;
private:
	std::thread worker;
	std::string name = std::string("UpdatePlugin");
	std::string description = std::string("Manages other plugins' updates.");
	HMODULE module;
	IConfig* configManager;
	ILogger* logger;
	IManager* pluginManager;

	std::mutex updateMutex; // syncronizes deinit with update loop.

	void updateLoop();
	void doUpdate();
};