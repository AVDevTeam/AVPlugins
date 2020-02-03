#pragma once
#include "pch.h"
#include "PluginInterface.h"
#include "EventsUMInterfaces.h"
#include <regex>

typedef enum 
{
	CallbackWinApiCall
} CALLBACK_ID;



class APIMonPlugin : public IPlugin
{
public:
	// Inherited via IPlugin
	virtual ~APIMonPlugin() override;
	AV_EVENT_RETURN_STATUS callback(int, void*, void**) override;
	void init(IManager* manager, HMODULE module, IConfig* configManager) override;
	void deinit() override;

	virtual std::string& getName() override { return this->name; }
	virtual HMODULE getModule() override { return this->module; }
	virtual unsigned int getVersion() override { return 1; }
	virtual std::string& getDescription() override { return this->description; }
	virtual IConfig* getConfig() override { return this->configManager; }

	virtual int processCommand(std::string name, std::string args) override { return 0;  }
private:
	std::string name = std::string("APIMonPlugin");
	std::string description = std::string("Dynamic threat prevention based on UM events analyzis.");
	HMODULE module;
	IConfig* configManager;
	ILogger* logger;

	AV_EVENT_RETURN_STATUS processApiCreateFileW(std::list<std::string> args)
	{
		return AvEventStatusAllow;
	}
	AV_EVENT_RETURN_STATUS processApiCreateProcessW(std::list<std::string> args);
		
	// API handler method typedef
	using ApiHandler = AV_EVENT_RETURN_STATUS(APIMonPlugin::*)(std::list<std::string>);
	// map of supported API functions
	std::map<std::string, ApiHandler> apiMap =
	{
		{"CreateFileW", &APIMonPlugin::processApiCreateFileW},
		{"CreateProcessW", &APIMonPlugin::processApiCreateProcessW}
	};
};