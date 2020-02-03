#include "pch.h"
#include "AVShield.h"

#include <iostream>

AVShield::~AVShield()
{
}

AV_EVENT_RETURN_STATUS AVShield::callback(int callbackId, void* event, void** umMessage)
{
	if (callbackId == CallbackFileCreate)
	{
		IEventFSCreate* eventFSCreate = reinterpret_cast<IEventFSCreate*>(event);
		int pid = eventFSCreate->getRequestorPID();
		if (!this->checkProcessExcluded(pid))
		{
			std::string filePath = eventFSCreate->getFilePath();
			std::list<std::string>* blocked = this->configManager->getListParam("ProtectedFolders");
			for (std::list<std::string>::iterator it = blocked->begin(); it != blocked->end(); it++)
			{
				if (filePath.find((*it)) != std::string::npos)
				{
					this->logger->log("\tAccess attempt from " + std::to_string(eventFSCreate->getRequestorPID()));
					this->logger->log("\t" + this->getName() + ": blocked access to protected folder " + (*it));
					delete blocked;
					return AvEventStatusBlock;
				}
			}
			delete blocked;
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
				delete blocked;
				return AvEventStatusBlock;
			}
		}
		delete blocked;
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
				delete blocked;
				return AvEventStatusBlock;
			}
		}
		delete blocked;
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
	paramMap->insert(paramPair("Exceptions", ListParam));

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
	param = "Exceptions";
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

bool AVShield::checkProcessExcluded(int pid)
{
	bool result = false;
	HANDLE Handle = OpenProcess(
		PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
		FALSE,
		pid
	);
	if (Handle)
	{
		char Buffer[MAX_PATH];
		if (GetModuleFileNameExA(Handle, 0, Buffer, MAX_PATH))
		{
			std::string processPath(Buffer);
			std::list<std::string> * exceptions = this->configManager->getListParam("Exceptions");
			for (std::list<std::string>::iterator it = exceptions->begin(); it != exceptions->end(); ++it)
			{
				if (processPath.find((*it)) != std::string::npos)
				{
					result = true;
					break;
				}
			}
			delete exceptions;
		}
		CloseHandle(Handle);
	}
	else
	{
		result = GetLastError() == 5;
	}
	return result;
}
