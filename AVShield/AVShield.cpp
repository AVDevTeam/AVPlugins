#include "pch.h"
#include "AVShield.h"

AVShield::~AVShield()
{
}

AV_EVENT_RETURN_STATUS AVShield::callback(int callbackId, void* event, void** umMessage)
{
	if (callbackId == CallbackFileCreate)
	{
		IEventFSCreate* eventFSCreate = reinterpret_cast<IEventFSCreate*>(event);
		std::string filePath = eventFSCreate->getFilePath();
		std::list<std::string>* blocked = this->configManager->getListParam("ProtectedFolders");
		for (std::list<std::string>::iterator it = blocked->begin(); it != blocked->end(); it++)
		{
			int pid = eventFSCreate->getRequestorPID();
			if (filePath.find((*it)) != std::string::npos && pid)
			{
				this->logger->log("\tAccess attemp from " + std::to_string(eventFSCreate->getRequestorPID()));
				this->logger->log("\t" + this->getName() + ": blocked access to protected folder " + (*it));
				return AvEventStatusBlock;
			}
		}
	}
	else if (callbackId == CallbackRegCreateKey)
	{
		IEventRegCreateKey* eventRegCreateKey = reinterpret_cast<IEventRegCreateKey*>(event);
		std::string keyPath = eventRegCreateKey->getKeyPath();
		std::list<std::string>* blocked = this->configManager->getListParam("ProtectedKeys");
		for (std::list<std::string>::iterator it = blocked->begin(); it != blocked->end(); it++)
		{
			if (keyPath.find((*it)) != std::string::npos)
			{
				this->logger->log("\t" + this->getName() + ": blocked access to protected key " + (*it));
				return AvEventStatusBlock;
			}
		}
	}
	else if (callbackId == CallbackRegOpenKey)
	{
		IEventRegOpenKey* eventRegOpenKey = reinterpret_cast<IEventRegOpenKey*>(event);
		std::string keyPath = eventRegOpenKey->getKeyPath();
		std::list<std::string>* blocked = this->configManager->getListParam("ProtectedKeys");
		for (std::list<std::string>::iterator it = blocked->begin(); it != blocked->end(); it++)
		{
			if (keyPath.find((*it)) != std::string::npos)
			{
				this->logger->log("\t" + this->getName() + ": blocked access to protected key " + (*it));
				return AvEventStatusBlock;
			}
		}
	}
	return AvEventStatusAllow;
}

void AVShield::init(IManager* manager, HMODULE module, IConfig* configManager)
{
	this->module = module;
	this->logger = manager->getLogger();

	this->configManager = configManager;
	paramMap* paramMap = new std::map<std::string, ConfigParamType>();

	paramMap->insert(paramPair("ProtectedFolders", ListParam));
	paramMap->insert(paramPair("ProtectedKeys", ListParam));

	this->configManager->setParamMap(paramMap);

	std::string param = "ProtectedFolders";
	if (!this->configManager->checkParamSet(param))
	{
		std::list<std::string> emptyList;
		this->configManager->setListParam(param, emptyList);
	}
	param = "ProtectedKeys";
	if (!this->configManager->checkParamSet(param))
	{
		std::list<std::string> emptyList;
		this->configManager->setListParam(param, emptyList);
	}

	manager->registerCallback(this, CallbackFileCreate, AvFileCreate, 5);
	manager->registerCallback(this, CallbackRegCreateKey, AvRegCreateKey, 5);
	manager->registerCallback(this, CallbackRegOpenKey, AvRegOpenKey, 5);
}

void AVShield::deinit()
{
	delete this->configManager->getParamMap();
	delete this;
}

std::string& AVShield::getName()
{
	return this->name;
}

HMODULE AVShield::getModule()
{
	return this->module;
}

std::string& AVShield::getDescription()
{
	return this->description;
}

IConfig* AVShield::getConfig()
{
	return this->configManager;
}

int AVShield::processCommand(std::string name, std::string args)
{
	return 0;
}
