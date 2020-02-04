#pragma once
#include "PluginInterface.h"
#include "EventsUMInterfaces.h"
#include <yaracpp/yaracpp.h>
#include <vector>
#include <stack>
#include <condition_variable>
#include <mutex>
#include <thread>
#include <set>
#include <queue>

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

	BOOL avDown = FALSE;
	std::vector<std::string> scanPath;
	int scanPeriod;
	FILETIME lastScanTime = { 0 };
	BOOL scannerInited = FALSE;
	
	void scanFiles();
	void shutdownThreads();
	void wakeupScanThead();
	template<class Duration>
	bool waitForScanThread(Duration duration);

	std::condition_variable schedulingLoopCondition;
	std::mutex scanSchedulingMutex;
	bool scanSchedulingLoopStop = false;
	std::thread *scanThread;

	std::mutex scanMutex;

	std::mutex verifyMutex;
	std::condition_variable verifyNotifier;
	std::queue<std::string> filesToVerify;
	std::thread* notifyThread = NULL;

	yaracpp::YaraDetector *yara;
	std::vector<std::string> rules;
	std::string rulesPath;
	BOOL scanFile(std::string path);
	yaracpp::YaraDetector* newDetector();
	void readRules(std::string path);
	void addFileToUserVerify(std::string path);
	void verifyFiles();
};