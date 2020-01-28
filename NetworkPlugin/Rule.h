#pragma once
#include "ipaddress.h"
#include "PortRange.h"
#include <nlohmann/json.hpp>
#include <vector>
#include <string>

using json = nlohmann::json;
using namespace std;

class Rule {
public:
	Rule(json rule) {
		this->localNetwork = IPNetwork<IPAddress>::parse(rule["local_network"].get<std::string>());
		this->remoteNetwork = IPNetwork<IPAddress>::parse(rule["remote_network"].get<std::string>());
		this->localPorts = PortRange(rule["local_port"].get<std::string>());
		this->remotePorts = PortRange(rule["remote_port"].get<std::string>());
		this->action = parseAction(rule["action"].get<std::string>());
		if (rule.contains("cve")) this->cve = rule["cve"].get<std::string>();
		if (rule.contains("msg")) this->msg = rule["msg"].get<std::string>();

		if (rule.contains("content")) {
			for (json content : rule["content"]) {
				std::pair<std::string, std::string> p(content["t"].get<std::string>(), content["c"].get<std::string>());
				this->contents.push_back(p);
			}
		}
	}

	Rule() {
		this->action = action_t::no_action;
	}

	typedef enum {
		block = 0,
		alert,
		allow,
		no_action
	} action_t;

	action_t makeDecision(
		std::string localAddressStr,
		std::string remoteAddressStr,
		unsigned short localPort,
		unsigned short remotePort,
		char* data,
		unsigned long long dataLength) {

		IPAddress* localAddress = IPAddress::parse(localAddressStr);
		bool localPass = this->localNetwork->contains(*localAddress) &&
			this->localPorts.contains(localPort);

		IPAddress* remoteAddress = IPAddress::parse(remoteAddressStr);
		bool remotePass = this->remoteNetwork->contains(*remoteAddress) &&
			this->remotePorts.contains(remotePort);

		bool contentPass = true;
		if (data != NULL && dataLength != 0) {
			for (std::pair<std::string, std::string> content : this->contents) {
				if (content.first == "string") {
					const char* content_ch = content.second.c_str();
					size_t content_len = content.second.length();
					if (dataLength >= content_len) {
						for (size_t i = 0; i < dataLength - content_len; i++) {
							contentPass = true;
							for (size_t j = 0; j < content_len; j++) {
								if (data[i + j] != content_ch[j]) {
									contentPass = false;
									break;
								}
							}
							if (contentPass) break;
						}
						if (contentPass) break;
					}
				}

				else if (content.first == "bytes") {
					size_t sub_buffer_len = (content.second.length() + 1) / 3;
					char* sub_buffer = (char*)malloc(sub_buffer_len);

					size_t i = 0;
					char* next_token1;
					for (char* pch = strtok_s((char*)content.second.c_str(), " ", &next_token1); 
						pch != NULL; 
						pch = strtok_s(NULL, " ", &next_token1)) {
						sscanf_s(pch, "%hhx", sub_buffer + i++);
					}
					if (dataLength >= sub_buffer_len) {
						for (size_t i = 0; i < dataLength - sub_buffer_len; i++) {
							contentPass = true;
							for (int j = 0; j < sub_buffer_len; j++) {
								if (data[i + j] != sub_buffer[j]) {
									contentPass = false;
									break;
								}
							}
							if (contentPass) break;
						}
					}
				}
				else if (content.first == "decimal") {
					int num = std::stoi(content.second);
					char* content_ch = (char*)&num;
					size_t content_len = sizeof(int);
					if (dataLength >= content_len) {
						for (size_t i = 0; i < dataLength - content_len; i++) {
							contentPass = true;
							for (size_t j = 0; j < content_len; j++) {
								if (data[i + j] != content_ch[j]) {
									contentPass = false;
									break;
								}
							}
							if (contentPass) break;
						}
						if (contentPass) break;
					}
				}
			}
		}

		if (localPass && remotePass && contentPass)
			return this->action;
		else
			return action_t::no_action;
	}

	action_t getAction() {
		return this->action;
	}

	std::string getMsg() {
		return this->msg;
	}

	std::string getCVE() {
		return this->cve;
	}

private:
	action_t parseAction(std::string actionStr) {
		action_t action;
		if (actionStr == "block") action = action_t::block;
		else if (actionStr == "alert") action = action_t::alert;
		else if (actionStr == "allow") action = action_t::allow;
		else action = action_t::block;
		return action;
	}

	IPNetwork <>* localNetwork;
	IPNetwork <>* remoteNetwork;
	PortRange localPorts;
	PortRange remotePorts;
	std::vector<std::pair<std::string, std::string>> contents;
	action_t action;
	std::string cve;
	std::string msg;
};
