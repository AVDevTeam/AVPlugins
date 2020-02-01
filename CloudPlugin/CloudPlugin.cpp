#include "CloudPlugin.h"
#include "CloudScanner.h"
#include "EventsUMInterfaces.h"
#include "KMUMcomm.h"
#include "Utils.h"

/*
This file contains the actual plugin logic.
*/

CloudPlugin::~CloudPlugin()
{
}

AV_EVENT_RETURN_STATUS CloudPlugin::callback(int callbackId, void* event, void** umMessage)
{
	return AvEventStatusAllow;
}

void CloudPlugin::init(IManager* manager, HMODULE module, IConfig* config)
{
	this->module = module;
	this->logger = manager->getLogger();
	this->logger->log("CloudPlugin");
	this->configManager = config;
	std::vector<std::string> scanPaths = split(config->getStringParam("ScanPaths"), ";");
	std::string filesScanned = config->getStringParam("ScannedFiles");
	int scanPeriod = config->getDwordParam("ScanPeriod");
	int cuckooScanPeriod = config->getDwordParam("CuckooScanPeriod");
	
	for (auto s : scanPaths)
		this->logger->log(s);
	this->logger->log(filesScanned);
	cloudScanner = new CloudScanner(scanPaths, filesScanned, scanPeriod, cuckooScanPeriod, this->logger);
	cloudScanner->run();
}

void CloudPlugin::deinit()
{
	cloudScanner->stop();
	delete cloudScanner;
	delete this->configManager->getParamMap();
	delete this;
}

std::string& CloudPlugin::getName()
{
	return this->name;
}

HMODULE CloudPlugin::getModule()
{
	return this->module;
}

std::string& CloudPlugin::getDescription()
{
	return this->description;
}

IConfig* CloudPlugin::getConfig()
{
	return this->configManager;
}

int CloudPlugin::processCommand(std::string name, std::string args)
{
	return 0;
}
