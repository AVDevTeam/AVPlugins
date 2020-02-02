#include "pch.h"
#include "UpdatePlugin.h"
#include "EventsUMInterfaces.h"
#include "KMUMcomm.h"
#include <iostream>
#include <fstream>
#include <mutex>

using json = nlohmann::json;

UpdatePlugin::~UpdatePlugin()
{
}

AV_EVENT_RETURN_STATUS UpdatePlugin::callback(int, void*, void**)
{
	return AvEventStatusBlock; // this plugin doesn't register any event callbacks.
}

void UpdatePlugin::init(IManager* manager, HMODULE module, IConfig* configManager)
{
	this->pluginManager = manager;
	this->module = module;
	this->logger = manager->getLogger();

	this->configManager = configManager;
	paramMap* paramMap = new std::map<std::string, ConfigParamType>();
	paramMap->insert(paramPair("server", StringParam));
	paramMap->insert(paramPair("interval", DwordParam));
	paramMap->insert(paramPair("pluginsDir", StringParam));

	this->configManager->setParamMap(paramMap);

	// set default values.
	std::string param("server");
	std::string value("192.168.1.209");
	if (!this->configManager->checkParamSet(param))
	{
		this->configManager->setStringParam(param, value);
	}
	param = "interval";
	if (!this->configManager->checkParamSet(param))
	{
		this->configManager->setDwordParam(param, 180);
	}
	param = "pluginsDir";
	if (!this->configManager->checkParamSet(param))
	{
		value = "C:\\Users\\user\\Desktop\\AVCore\\Plugins\\";
		this->configManager->setStringParam(param, value);
	}
	this->worker = std::thread(&UpdatePlugin::updateLoop, this);
}

void UpdatePlugin::deinit()
{
	this->updateMutex.lock();
}

std::string& UpdatePlugin::getName()
{
	return this->name;
}

HMODULE UpdatePlugin::getModule()
{
	return this->module;
}

std::string& UpdatePlugin::getDescription()
{
	return this->description;
}

IConfig* UpdatePlugin::getConfig()
{
	return this->configManager;
}

void UpdatePlugin::updateLoop()
{
	while (1)
	{
		Sleep(this->configManager->getDwordParam("interval") * 1000); // sleep for interval seconds
		this->doUpdate();
	}
}

void UpdatePlugin::doUpdate()
{
	this->updateMutex.lock(); // enter critical section.
	std::string serverUrl = this->configManager->getStringParam("server"); // get server URL from parameter

	httplib::Client cli(serverUrl, 80); // connect to server
	auto res = cli.Get("updates/meta.json"); // load plugin updates list
	if (res && res->status == 200)
	{
		// parse json metadata
		json updateMeta = json::parse(res->body);
		json plugins = updateMeta["plugins"];
		if (plugins.is_object())
		{
			// iterate through list of updates
			for (auto it = plugins.begin(); it != plugins.end(); ++it)
			{
				json curPlugin = (*it);
				if (!curPlugin.is_object())
					continue;
				json name = curPlugin["name"];
				json version = curPlugin["version"];
				if (name.is_string() && version.is_string())
				{
					// try to get correspondant plugin from current plugin list
					IPlugin* plugin = this->pluginManager->getPluginByName(name.get<std::string>());
					unsigned int newVersion = 0;
					try
					{
						// parse version from json
						newVersion = std::stoi(version.get<std::string>());
					}
					catch (std::invalid_argument const& e)
					{
						continue;
					}
					catch (std::out_of_range const& e)
					{
						continue;
					}
					if (
						plugin != nullptr // we will update only loaded plugis
						&& plugin != this // we cannot update ourself (UpdatePlugin)
						&& plugin->getVersion() < newVersion // check if the version on server is newer than current version
						)
					{
						// unload plugin that will be updated
						this->pluginManager->unloadPlugin(name.get<std::string>());
						std::string pluginPath = this->configManager->getStringParam("pluginsDir") + name.get<std::string>() + ".dll";
						std::ofstream wf(pluginPath, std::ios::out | std::ios::binary);
						// download plugin from server
						auto res = cli.Get(("updates/" + name.get<std::string>() + ".dll").c_str(),
							// lambda to process batches of response body
							[&](const char* data, uint64_t data_length) {
								wf.write(data, data_length);
								return true;
							});

						wf.flush();
						wf.close();
						// load plugin into AVCore
						this->pluginManager->loadPlugin(pluginPath);
					}
				}
			}
		}
	}
	this->updateMutex.unlock(); // leave critical section.
}

int UpdatePlugin::processCommand(std::string name, std::string args)
{
	if (name == "update")
	{
		this->doUpdate();
	}
	return 0;
}
