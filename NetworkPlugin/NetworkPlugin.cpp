#include "NetworkPlugin.h"
#include "EventsUMInterfaces.h"
#include "KMUMcomm.h"

NetworkPlugin::~NetworkPlugin() {}

AV_EVENT_RETURN_STATUS NetworkPlugin::callback(int callbackId, void* event, void** umMessage) {
	if (callbackId == CallbackNetworkPacket)
	{
		IEventNetwork* eventNetwork = reinterpret_cast<IEventNetwork*>(event);
		Rule* rule = this->rules->makeDecision(
			eventNetwork->getLocalAddressStr(),
			eventNetwork->getRemoteAddressStr(),
			eventNetwork->getLocalPort(),
			eventNetwork->getRemotePort(),
			eventNetwork->getData(),
			eventNetwork->getDataLength()
		);
		
		char message[1024] = { 0 };
		switch (rule->getAction())
		{
		case Rule::action_t::alert:
			sprintf_s(message, "CallbackNetworkPacket\n\tAlert: %s (CVE %s)\nRemote addr %s:%uh -> Local addr %s:uh",
				rule->getMsg().c_str(),
				rule->getCVE().c_str(),
				eventNetwork->getRemoteAddressStr(),
				eventNetwork->getRemotePort(),
				eventNetwork->getLocalAddressStr(),
				eventNetwork->getLocalPort());
			this->logger->log(message);
			return AvEventStatusAllow;

		case Rule::action_t::allow:
			sprintf_s(message, "CallbackNetworkPacket\n\tAllow: %s (CVE %s)\nRemote addr %s:%uh -> Local addr %s:uh",
				rule->getMsg().c_str(),
				rule->getCVE().c_str(),
				eventNetwork->getRemoteAddressStr(),
				eventNetwork->getRemotePort(),
				eventNetwork->getLocalAddressStr(),
				eventNetwork->getLocalPort());
			this->logger->log(message);
			return AvEventStatusAllow;

		case Rule::action_t::block:
			sprintf_s(message, "CallbackNetworkPacket\n\tBlock: %s (CVE %s)\nRemote addr %s:%uh -> Local addr %s:uh",
				rule->getMsg().c_str(),
				rule->getCVE().c_str(),
				eventNetwork->getRemoteAddressStr(),
				eventNetwork->getRemotePort(),
				eventNetwork->getLocalAddressStr(),
				eventNetwork->getLocalPort());
			this->logger->log(message);
			return AvEventStatusBlock;

		case Rule::action_t::no_action:
			return AvEventStatusAllow;
		}
	}
	return AvEventStatusAllow;
}

void NetworkPlugin::init(IManager* manager, HMODULE module, IConfig* config)
{
	this->module = module;
	this->logger = manager->getLogger();
	this->logger->log("AV : NetworkPlugin : init");
	this->configManager = config;
	std::string rulesPath = config->getStringParam("RulesPath");
	this->rules = new Rules(rulesPath);
	this->logger->log(string("AV : NetworkPlugin : Rules size ") + to_string(this->rules->size()));
	manager->registerCallback(this, CallbackNetworkPacket, AvNetwork, 100);
	this->logger->log("AV : NetworkPlugin : init : call register");
}

void NetworkPlugin::deinit()
{
	delete this->rules;
	delete this->configManager->getParamMap();
	delete this;
}

std::string& NetworkPlugin::getName()
{
	return this->name;
}

HMODULE NetworkPlugin::getModule()
{
	return this->module;
}

std::string& NetworkPlugin::getDescription()
{
	return this->description;
}

IConfig* NetworkPlugin::getConfig()
{
	return this->configManager;
}
