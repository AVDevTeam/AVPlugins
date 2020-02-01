#pragma once
#include "Rule.h"
#include <fstream>
#include <json.hpp>
#include <vector>
#include <string>

using namespace std;
using json = nlohmann::json;

class Rules {
public:
	Rules(std::string rulesPath) {
		std::ifstream rulesFile(rulesPath);
		json rulesJson;
		rulesFile >> rulesJson;
		for (json ruleJson : rulesJson["rules"]) {
			Rule* rule = new Rule(ruleJson);
			this->rules.push_back(rule);
		}
	}

	~Rules() {
		for (Rule* rule : rules) {
			delete rule;
		}
	}

	Rule *makeDecision(
		std::string localAddressStr,
		std::string remoteAddressStr,
		unsigned short localPort,
		unsigned short remotePort,
		char *data,
		unsigned long long dataLength) {

		for (Rule *rule : rules) {
			Rule::action_t decision = rule->makeDecision(
				localAddressStr,
				remoteAddressStr,
				localPort,
				remotePort,
				data, 
				dataLength);
			if (decision != Rule::action_t::no_action)
				return rule;
		}
		return &noActionRule;
	}

	int size() {
		return rules.size();
	}

private:
	std::vector<Rule *> rules;
	Rule noActionRule;
};