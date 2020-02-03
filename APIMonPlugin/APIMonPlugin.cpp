#include "pch.h"
#include "APIMonPlugin.h"

APIMonPlugin::~APIMonPlugin()
{
}

AV_EVENT_RETURN_STATUS APIMonPlugin::callback(int callbackId, void* event, void** umMessage)
{
	if (callbackId == CallbackWinApiCall)
	{
		// get event parameters (api function name and arguments list)
		IEventWinApiCall* eventWinApiCall = reinterpret_cast<IEventWinApiCall*>(event);
		int pid = eventWinApiCall->getPID();
		std::string funcName = eventWinApiCall->getFunctionName();
		std::list<std::string> funcArgs = eventWinApiCall->getFunctionArgs();
		
		// check if handler exists
		if (this->apiMap.find(funcName) != this->apiMap.end())
		{
			ApiHandler handler = this->apiMap.at(funcName); // get corresponding handler
			return (this->*handler)(funcArgs);
		}
	}
	return AvEventStatusAllow;
}

void APIMonPlugin::init(IManager* manager, HMODULE module, IConfig* configManager)
{
	this->module = module;
	this->logger = manager->getLogger();

	this->configManager = configManager;
	paramMap* paramMap = new std::map<std::string, ConfigParamType>();
	paramMap->insert(paramPair("signatures", ListParam));

	this->configManager->setParamMap(paramMap);

	// set default values.
	std::string param("signatures");
	if (!this->configManager->checkParamSet(param))
	{
		std::list<std::string> value = 
		{ 
			"net\\s+user", "net\\s+group", "net\\s+localgroup", // Account Discovery
			"Nltest",											// Domain Trust Discovery
			"net\\s+view\\s+\\\\remotesystem", "net\\s+share",	// Network Share Discovery
			"net\\s+accounts", "net\\s+accounts\\s+\\/domain",	// Network Share Discovery
			"netstat", "net\\s+use", "net\\s+session"			// Password Policy Discovery
		};
		this->configManager->setListParam(param, value);
	}

	// register event callback
	manager->registerCallback(this, CallbackWinApiCall, AvWinApiCall, 5);
}

void APIMonPlugin::deinit()
{
}

AV_EVENT_RETURN_STATUS APIMonPlugin::processApiCreateProcessW(std::list<std::string> args)
{
	std::list<std::string>::iterator args_it = args.begin();
	std::advance(args_it, 1);
	std::string command_line = (*args_it);
	this->logger->log("cmd line: " + command_line);
	std::list<std::string>* signatures = this->configManager->getListParam("signatures");
	for (std::list<std::string>::iterator it = signatures->begin(); it != signatures->end(); ++it)
	{ 
		using namespace std::regex_constants;
		try
		{
			std::regex signature_regex((*it), icase);
			std::cmatch cm;
			std::regex_search(command_line.c_str(), cm, signature_regex);
			if (cm.size() != 0)
			{
				this->logger->log("Blocked cmd line " + command_line + " by signature " + (*it));
				delete signatures;
				return AvEventStatusBlock;
			}
		}
		catch (std::regex_error e)
		{
			this->logger->log("error in regex: " + (*it));
			continue; // ignore invalid regexes.
		}
	}
	delete signatures;
	return AvEventStatusAllow;
}
