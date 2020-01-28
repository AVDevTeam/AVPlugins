#pragma once
#include <iostream>
#include <Windows.h>
#include <winhttp.h>
#include <wincrypt.h>
#include <nlohmann/json.hpp>
#include <Shlwapi.h>
#include <sstream>
#include <queue>
#include <fstream>
#include <regex>
#include <set>
#include <vector>
#include <stack>
#include "PluginInterface.h"

struct FileInfo {
	std::string md5;
	std::string path;
	float mlScore;
	float cuckooScore;
};

class CloudScanner {
public:
	CloudScanner(std::vector<std::string> scanPath, std::string skipListFile, int scanPeriod, int cuckooCheckPeriod, ILogger *logger);
	BOOL run();
	void stop();
private:
	DWORD   dwThreadIdAnalyse, dwThreadIdCuckoo;
	HANDLE  hThreadAnalyse, hThreadCuckoo;

	BOOL avDown = FALSE;
	std::vector<std::string> scanPath;
	std::string skipListFile;
	std::set<std::string> filesSkip;
	std::queue<FileInfo> cuckooQueue;
	int scanPeriod, cuckooCheckPeriod;
	HANDLE mutex;
	FILETIME lastScanTime = { 0 };
	ILogger *logger;

	static DWORD WINAPI cuckooCheckResult(LPVOID lpParam);
	static DWORD WINAPI scanFiles(LPVOID lpParam);
	BOOL makeDecision(FileInfo* fileinfo);
	BOOL sendJson(std::string& requestJson, std::string& responseJson);
	BOOL sendFileToAnalyse(std::string filePath, FileInfo *info);
	void putFileInfo(FileInfo info);
	FileInfo getFileInfo();
	size_t queueSize();
	BOOL readSkipFileHashes();
	static BOOL hashFile(BYTE* data, DWORD dataLength, std::string *hashStr);
	BOOL addScannedFile(std::string hash);
};