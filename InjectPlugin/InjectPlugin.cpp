#include "pch.h"
#include "InjectPlugin.h"

#ifdef _WIN64
#define LoadLibraryAPCoffset 0x18
#define LoadLibraryAPCoffsetWOW64 0x8
#define LoadLibraryAExport "LoadLibraryA"
#else
#define LoadLibraryAPCoffset 0x8
#define LoadLibraryAExport "LoadLibraryA"
#endif

#ifdef _WIN64
UCHAR APCPayloadBufferWOW64[1024] =
#else
UCHAR APCPayloadBuffer[1024] =
#endif
{
	0x83, 0xC0, 0x0C,	// add    eax,0x0C
	0x50,				// push   eax
	0xFF, 0x50, 0xFC,	// call   DWORD PTR [eax-0x4]
	0xC3,				// ret
	0xFF, 0xFF, 0xFF, 0xFF // LoadLibraryAStup address placeholder
	// dll path will be here
};

#ifdef _WIN64
UCHAR APCPayloadBuffer[1024] =
{ 
	0x48, 0x89, 0xC1,		// mov    rcx,rax
	0x48, 0x83, 0xC1, 0x20, // add    rcx,0x20
	0x48, 0x83, 0xEC, 0x20, // sub    rsp,0x20
	0xFF, 0x50, 0x18,		// call   QWORD PTR [rax+0x18]
	0x48, 0x83, 0xC4, 0x20, // add    rsp,0x20
	0xC3,					// ret

	0xCC, 0xCC, 0xCC, 0xCC, 0xCC, // padding

	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF // LoadLibraryAStup address placeholder
	// dll path will be here
};
#endif

AVInject::~AVInject()
{
}

AV_EVENT_RETURN_STATUS AVInject::callback(int callbackId, void* event, void** umMessage)
{
	if (callbackId == CallbackProcessCreate)
	{
		IEventProcessCreate* eventProcessCreate = reinterpret_cast<IEventProcessCreate*>(event);
		this->logger->log("CallbackProcessCreate");
		int PID = eventProcessCreate->getPID();
		this->logger->log("Process (" + eventProcessCreate->getImageFileName() + ") with PID " + std::to_string(PID) + " was created");
		InjectContext* injectContext = new InjectContext(this->logger, PID, eventProcessCreate->getImageFileName());

		this->processMap.insert(std::pair<int, InjectContext*>(PID, injectContext));
	}
	else if (callbackId == CallbackProcessExit)
	{
		IEventProcessExit* eventProcessExit = reinterpret_cast<IEventProcessExit*>(event);
		int PID = eventProcessExit->getPID();
		if (this->processMap.find(PID) != this->processMap.end())
		{
			this->logger->log("Deleting InjectContext for " + std::to_string(PID));
			delete this->processMap[PID];
			this->processMap.erase(PID);
		}
		this->logger->log("CallbackProcessExit");
	}
	else if (callbackId == CallbackThreadCreate)
	{
		IEventThreadCreate* eventThreadCreate = reinterpret_cast<IEventThreadCreate*>(event);
		this->logger->log("CallbackThreadCreate");
		int PID = eventThreadCreate->getPID();
		int TID = eventThreadCreate->getTID();
		if (this->processMap.find(PID) != this->processMap.end())
		{
			InjectContext* context = this->processMap[PID];
			this->logger->log("Process with PID " + std::to_string(PID) + " created thread " + std::to_string(TID));
			if (context->getTID() == NULL)
				context->setTID(TID);
			if (!context->wasInjected())
			{
				this->logger->log("START INJECT");
				(*umMessage) = (void*)context->getApcInfoPtr();
				context->setInjected();
				return AvEventStatusInjectAPC;
			}
		}
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
	paramMap->insert(paramPair("dll", StringParam));
#ifdef _WIN64
	paramMap->insert(paramPair("dllWOW64", StringParam));
#endif
	this->configManager->setParamMap(paramMap);
	std::string paramName = "dll";
	std::string dllPath = "C:\\Users\\user\\desktop\\AVCore\\AVInjectAgent.dll";
	this->configManager->setStringParam(paramName, dllPath);

	// prepare APC payload buffers
	HMODULE kernel32module = LoadLibraryA("kernel32.dll");
	PVOID loadLibraryAdrr = GetProcAddress(kernel32module, LoadLibraryAExport); // get address of loadlibrary to put it into APC buffer
	// put loadlibrary offset into the buffer
	PVOID* APCPayloadLoadLibraryPlacehod = (PVOID*)(APCPayloadBuffer + LoadLibraryAPCoffset);
	*APCPayloadLoadLibraryPlacehod = loadLibraryAdrr;
	// put dll path into apc buffer
	PVOID dllPathOffset = (PVOID)(APCPayloadBuffer + LoadLibraryAPCoffset + sizeof(PVOID));
	memcpy(dllPathOffset, this->configManager->getStringParam("dll").c_str(), this->configManager->getStringParam("dll").length());

	

	manager->registerCallback(this, CallbackProcessCreate, AvProcessCreate, 1);
	manager->registerCallback(this, CallbackProcessExit, AvProcessExit, 1);
	manager->registerCallback(this, CallbackThreadCreate, AvThreadCreate, 1);
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

InjectContext::InjectContext(ILogger* logger, int PID, std::string imageName)
{
	this->injected = false;
	this->logger = logger;
	this->imageName = imageName;
	this->apcInfo.TID = NULL;
	this->apcInfo.PID = PID;
	this->apcInfo.apcBuffer = APCPayloadBuffer;
	this->apcInfo.apcBufferSize = sizeof(APCPayloadBuffer);
#ifdef _WIN64
	HANDLE pHandle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, this->apcInfo.PID);
	if (pHandle)
	{
		if (!IsWow64Process(pHandle, (PBOOL)& this->Wow64))
		{
			throw "ERROR IsWow64Process";
		}
		CloseHandle(pHandle);
	}
	else
	{
		throw "OPEN PROCESS ERROR";
	}
	if (this->Wow64)
		this->logger->log("WOW64");

#endif
}
