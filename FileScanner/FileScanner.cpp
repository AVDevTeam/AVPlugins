#include "FileScanner.h"
#include "EventsUMInterfaces.h"
#include "KMUMcomm.h"
#include "Utils.h"
#include <vector>
#include <filesystem>
#include <fstream>

AV_EVENT_RETURN_STATUS FileScanner::callback(int callbackId, void* event, void** umMessage)
{	
	if (callbackId == CallbackFileCreate) {
		IEventFSCreate* eventFSCreate = reinterpret_cast<IEventFSCreate*>(event);
		scanFile(eventFSCreate->getFilePath());
	}
	return AV_EVENT_RETURN_STATUS::AvEventStatusAllow;
}

BOOL FileScanner::scanFile(std::string path) {
	try {
		if (path.find("C:\\Users\\user\\Documents") != -1 &&
			path.find("AV") == -1 &&
			path.find(this->rulesPath) == -1 &&
			(path.find(".exe") != -1 || path.find(".dll") != -1)) {

			std::lock_guard<std::mutex> lock(this->scanMutex);
			bool scanResult = (this->yara->analyze(path) && this->yara->getDetectedRules().size() > 0);

			if (scanResult) {
				std::string message = "AVScanFiles | malware detected | path: \'" + path + "\'  rule: " + this->yara->getDetectedRules()[0].getName();
				this->logger->log(message);
				this->messageManager->outAlert(message);
				delete this->yara;
				this->yara = newDetector();
				return TRUE;
			}
		}
	}
	catch (int e) {
		this->logger->log("File scan error");
	}
	return FALSE;
}

void FileScanner::scanFiles() {
	try {
		while (!this->avDown) {
			if (this->scannerInited) {
				WIN32_FIND_DATAA file;
				std::stack<std::string, std::vector<std::string>> fstack(this->scanPath);
				while (!fstack.empty()) {
					std::string dir = fstack.top();
					fstack.pop();
					HANDLE hFile = FindFirstFileA((dir + "\\*").c_str(), &file);
					if (hFile != INVALID_HANDLE_VALUE) {
						do {
							std::string fname = std::string(file.cFileName);
							std::string path = dir + "\\" + fname;
							if (file.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
								if ((fname != ".") && (fname != "..")) {
									fstack.push(path);
								}
							}
							else {
								DWORD binaryType;
								FILETIME lastModified = file.ftLastWriteTime;
								if (CompareFileTime(&lastModified, &this->lastScanTime) >= 0) {
									this->scanFile(path);
								}
							}
						} while (FindNextFileA(hFile, &file));

						FindClose(hFile);
					}
				}
				SYSTEMTIME systemTime;
				GetSystemTime(&systemTime);
				SystemTimeToFileTime(&systemTime, &this->lastScanTime);
			}
			this->waitForScanThread(std::chrono::minutes(this->scanPeriod));
		}
	}
	catch (int e) {
		this->logger->log("AVCloud | scanFiles exception");
	}
}

void FileScanner::addFileToUserVerify(std::string path) {
	std::unique_lock<std::mutex> lock(this->verifyMutex);
	this->filesToVerify.push(path);
	this->verifyNotifier.notify_one();
}

void FileScanner::verifyFiles() {
	std::unique_lock<std::mutex> lock(this->verifyMutex);
	while (!this->avDown) {
		this->verifyNotifier.wait(lock);

		if (this->filesToVerify.empty()) continue;
		std::string path = this->filesToVerify.front();
		this->filesToVerify.pop();

		int res = MessageBoxA(NULL, (std::string("Detected malware. Delete?") + path).c_str(), "Detected malware", MB_YESNO);
		if (res == IDYES) {
			DeleteFileA(path.c_str());
		}
	}
}

void FileScanner::shutdownThreads() {
	{
		std::lock_guard<std::mutex> l(scanSchedulingMutex);
		scanSchedulingLoopStop = true;
		avDown = true;
	}
	schedulingLoopCondition.notify_one();
	scanThread->join();
	delete scanThread;

	if (notifyThread) {
		verifyNotifier.notify_one();
		delete notifyThread;
	}
}

void FileScanner::wakeupScanThead() {
	{
		std::lock_guard<std::mutex> l(scanSchedulingMutex);
		scanSchedulingLoopStop = true;
	}
	schedulingLoopCondition.notify_one();
}

template<class Duration>
bool FileScanner::waitForScanThread(Duration duration) {
	std::unique_lock<std::mutex> l(scanSchedulingMutex);
	schedulingLoopCondition.wait_for(l, duration, [this]() { return scanSchedulingLoopStop; });
	scanSchedulingLoopStop = false;
}


void FileScanner::init(IManager* manager, HMODULE module, IConfig* configManager)
{
	this->module = module;
	this->logger = manager->getLogger();
	this->logger->log("FileScanner");
	this->messageManager = manager->getMessageManager();
	this->configManager = configManager;
	this->scanPath = split(configManager->getStringParam("ScanPaths"), ";");
	this->rulesPath = configManager->getStringParam("RulesPath");
	this->scanPeriod = configManager->getDwordParam("ScanPeriod");

	this->logger->log("AVFileScanner | loading rules");

	this->readRules(rulesPath);
	this->yara = newDetector();

	manager->registerCallback(this, CallbackFileCreate, AvFileCreate, 100);
	
	this->scanThread = new std::thread([this]() { this->scanFiles(); });
	//this->notifyThread = new std::thread([this]() { this->verifyFiles(); });
	
	this->logger->log("AVFileScanner | started");
}

void FileScanner::readRules(std::string rulesPath) {
	for (auto& p : std::filesystem::directory_iterator(rulesPath)) {
		if (p.path().extension().string() != ".yar") continue;
		std::ifstream f(p.path().string());
		std::string rule((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
		rules.push_back(rule);
		f.close();
	}
}

yaracpp::YaraDetector* FileScanner::newDetector() {
	yaracpp::YaraDetector* yara = new yaracpp::YaraDetector();
	for (std::string rule : this->rules) {
		yara->addRules(rule.c_str());
	}
	return yara;
}

void FileScanner::deinit()
{
	shutdownThreads();
	delete yara;
}

FileScanner::~FileScanner()
{
}

int FileScanner::processCommand(std::string name, std::string args)
{
	if (name == "scan") {
		this->wakeupScanThead();
	} 
	return 0;
}

unsigned int FileScanner::getVersion()
{
	return 1;
}

std::string& FileScanner::getName()
{
	return this->name;
}

HMODULE FileScanner::getModule()
{
	return this->module;
}

std::string& FileScanner::getDescription()
{
	return this->description;
}

IConfig* FileScanner::getConfig()
{
	return this->configManager;
}
