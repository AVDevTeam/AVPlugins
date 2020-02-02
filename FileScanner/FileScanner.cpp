#include "FileScanner.h"
#include "EventsUMInterfaces.h"
#include "KMUMcomm.h"
#include "Utils.h"
#include <vector>
#include <filesystem>
#include <fstream>

AV_EVENT_RETURN_STATUS FileScanner::callback(int callbackId, void* event, void** umMessage)
{
	if (callbackId == CallbackFileCreate) {
		IEventFSCreate* eventFSCreate = reinterpret_cast<IEventFSCreate*>(event);
		scanFile(eventFSCreate->getFilePath());
	}
	return AV_EVENT_RETURN_STATUS::AvEventStatusAllow;
}

BOOL FileScanner::scanFile(std::string path) {
	try {
		if (path.find("C:\\Users\\user\\Documents") != -1 &&
			path.find("AV") == -1 &&
			path.find(this->rulesPath) == -1 &&
			(path.find(".exe") != -1 || path.find(".dll") != -1) &&
			this->yara->analyze(path) && this->yara->getDetectedRules().size() > 0) {
			
			DeleteFileA(path.c_str());

			std::string message = "detected malware " + path + ", rule " + this->yara->getDetectedRules()[0].getName();
			this->logger->log(message);
			this->messageManager->outAlert(message);
			delete this->yara;
			this->yara = newDetector();
		}
	}
	catch (int e) {
		this->logger->log("File scan error");
	}
}

void FileScanner::init(IManager* manager, HMODULE module, IConfig* configManager)
{
	this->module = module;
	this->logger = manager->getLogger();
	this->logger->log("FileScanner");
	this->messageManager = manager->getMessageManager();
	this->configManager = configManager;
	std::vector<std::string> scanPaths = split(configManager->getStringParam("ScanPaths"), ";");
	this->rulesPath = configManager->getStringParam("RulesPath");
	int scanPeriod = configManager->getDwordParam("ScanPeriod");

	this->logger->log("AVFileScanner | loading rules");

	this->readRules(rulesPath);
	this->yara = newDetector();

	manager->registerCallback(this, CallbackFileCreate, AvFileCreate, 100);

	this->logger->log("AVFileScanner | started");
}

void FileScanner::readRules(std::string rulesPath) {
	for (auto& p : std::filesystem::directory_iterator(rulesPath)) {
		if (p.path().extension().string() != ".yar") continue;
		std::ifstream f(p.path().string());
		std::string rule((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
		rules.push_back(rule);
		f.close();
	}
}

yaracpp::YaraDetector* FileScanner::newDetector() {
	yaracpp::YaraDetector* yara = new yaracpp::YaraDetector();
	for (std::string rule : this->rules) {
		yara->addRules(rule.c_str());
	}
	return yara;
}

void FileScanner::deinit()
{
	delete yara;
}

FileScanner::~FileScanner()
{
}

int FileScanner::processCommand(std::string name, std::string args)
{
	return 0;
}

unsigned int FileScanner::getVersion()
{
	return 1;
}

std::string& FileScanner::getName()
{
	return this->name;
}

HMODULE FileScanner::getModule()
{
	return this->module;
}

std::string& FileScanner::getDescription()
{
	return this->description;
}

IConfig* FileScanner::getConfig()
{
	return this->configManager;
}
