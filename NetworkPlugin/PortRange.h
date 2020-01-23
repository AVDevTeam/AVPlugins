#pragma once
#include <vector>
#include <string>

using namespace std;
class PortRange {
public:
	PortRange() {}

	PortRange(string rangesStr) {
		vector<string> splitted = split(rangesStr, " ,\t.");
		for (string rangeStr : splitted) {
			unsigned short from = 0, to = USHRT_MAX;
			sscanf_s(rangeStr.c_str(), "%hu-%hu", &from, &to);
			if (from != 0 && to == USHRT_MAX) to = from;
			ranges.push_back({ from, to });
		}
	}

	bool contains(unsigned short port) {
		for (range_t range : ranges) {
			if (port >= range.from && port <= range.to) {
				return true;
			}
		}
		return false;
	}

private:
	typedef struct range_ { unsigned short from;  unsigned short to; } range_t;
	vector<range_t> ranges;

	std::vector<std::string> split(const std::string& s_, std::string delimiter)
	{
		std::string s = s_;
		std::vector<std::string> tokens;
		size_t i;
		do {
			for (i = 0; (i < s.length()) && (delimiter.find(s[i]) != std::string::npos); i++);
			s.erase(0, i);
			if (s.length() == 0) break;
			for (i = 0; (i < s.length()) && (delimiter.find(s[i]) == std::string::npos); i++);
			tokens.push_back(s.substr(0, i));
			s.erase(0, i);
		} while (s.length() != 0);
		return tokens;
	}
};
