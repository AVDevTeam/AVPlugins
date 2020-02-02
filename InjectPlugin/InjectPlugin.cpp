#include "InjectPlugin.h"

AVInject::~AVInject()
{
}

AV_EVENT_RETURN_STATUS AVInject::callback(int callbackId, void* event, void** umMessage)
{
	if (callbackId == CallbackApcProcessInject)
	{
		IEventProcessCreate* eventApcProcessInject = reinterpret_cast<IEventProcessCreate*>(event);
		this->logger->log("CallbackApcProcessInject");

		this->logger->log("Injecting dll to " + std::to_string(eventApcProcessInject->getPID()) + " via APC (injdrv)");
		// send any other Status to block dll injection.
		if (eventApcProcessInject->getImageFileName().find("cmd") != std::string::npos)
			return AvEventStatusAllow; // inject
		return AvEventStatusBlock;
	}
	return AvEventStatusAllow;
}

void AVInject::init(IManager* manager, HMODULE module, IConfig* configManager)
{
	this->module = module;
	this->logger = manager->getLogger();

	// parameter settings
	this->configManager = configManager;
	paramMap* paramMap = new std::map<std::string, ConfigParamType>();
	paramMap->insert(paramPair("exceptions", ListParam));

	this->configManager->setParamMap(paramMap);

	// callbacks settings
	manager->registerCallback(this, CallbackApcProcessInject, AvApcProcessInject, 1);
}

void AVInject::deinit()
{
	delete this->configManager->getParamMap();
	delete this;
}

std::string& AVInject::getName()
{
	return this->name;
}

HMODULE AVInject::getModule()
{
	return this->module;
}

std::string& AVInject::getDescription()
{
	return this->description;
}

IConfig* AVInject::getConfig()
{
	return this->configManager;
}

int AVInject::processCommand(std::string name, std::string args)
{
	return 0;
}
