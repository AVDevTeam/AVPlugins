#pragma once
#include <vector>
#include <string>

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
