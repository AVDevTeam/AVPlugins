#pragma once
#include "PluginInterface.h"
#include "EventsUMInterfaces.h"
#include <yaracpp/yaracpp.h>
#include <vector>

typedef enum {
	CallbackFileCreate,
} CALLBACK_ID;

class FileScanner : public IPlugin
{
public:
	// Inherited via IPlugin
	virtual ~FileScanner() override;
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
	std::string name = std::string("FileScanner");
	std::string description = std::string("Just a file signature scanner.");
	HMODULE module;
	IConfig* configManager;
	ILogger* logger;
	IMessageManager* messageManager;

	yaracpp::YaraDetector *yara;
	std::vector<std::string> rules;
	std::string rulesPath;
	BOOL scanFile(std::string path);
	yaracpp::YaraDetector* newDetector();
	void readRules(std::string path);
};