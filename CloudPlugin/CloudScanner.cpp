#include "CloudScanner.h"

using json = nlohmann::json;

CloudScanner::CloudScanner(std::vector<std::string> scanPath, std::string skipListFile, int scanPeriod, int cuckooCheckPeriod, ILogger* logger) {
	this->scanPeriod = scanPeriod;
	this->cuckooCheckPeriod = cuckooCheckPeriod;
	this->scanPath = scanPath;
	mutex = CreateMutex(NULL, FALSE, NULL);
	this->readSkipFileHashes();
	this->logger = logger;
}

BOOL CloudScanner::run() {
	this->hThreadAnalyse = CreateThread(NULL, 0, CloudScanner::scanFiles, this, 0, &this->dwThreadIdAnalyse);
	if (this->dwThreadIdAnalyse == NULL) { return FALSE; }
	this->hThreadCuckoo = CreateThread(NULL, 0, CloudScanner::cuckooCheckResult, this, 0, &this->dwThreadIdCuckoo);
	if (this->dwThreadIdCuckoo == NULL) { CloseHandle(this->hThreadAnalyse); return FALSE; }
	return TRUE;
}

void CloudScanner::stop() {
	this->avDown = TRUE;
	WaitForSingleObject(this->hThreadCuckoo, this->scanPeriod);
	WaitForSingleObject(this->hThreadCuckoo, this->cuckooCheckPeriod);
	CloseHandle(hThreadAnalyse);
	CloseHandle(hThreadCuckoo);
}

BOOL CloudScanner::makeDecision(FileInfo *fileinfo) {
	if (fileinfo->mlScore > 0.5 || fileinfo->cuckooScore > 5.0) {
		DeleteFileA(fileinfo->path.c_str());
		return TRUE;
	}
	else if (fileinfo->cuckooScore != -1) {
		this->addScannedFile(fileinfo->md5);
	}
	return FALSE;
}

DWORD WINAPI CloudScanner::cuckooCheckResult(LPVOID lpParam) {
	CloudScanner* fs = (CloudScanner*)lpParam;
	try {
		while (!fs->avDown) {
			size_t queueSize = fs->queueSize();
			for (size_t i = 0; i < queueSize; i++) {
				FileInfo info = fs->getFileInfo();
				json j;
				j["action"] = "cuckoo_check_result";
				j["md5"] = info.md5;
				std::string request = j.dump(), response;

				fs->sendJson(request, response);
				fs->logger->log(std::string("AVCloud | cuckoo result") + response);
				json responseJson = json::parse(response);
				if (responseJson["status"].get<std::string>() == "analysing") {
					fs->putFileInfo(info);
				}
				else {
					info.cuckooScore = std::stof(responseJson["cuckoo_score"].get<std::string>());
					fs->makeDecision(&info);
				}
			}
			Sleep(fs->cuckooCheckPeriod);
		}
	}
	catch (int e) {
		fs->logger->log("AVCloud | cuckooCheckResult exception");
	}
	return 0;
}

DWORD WINAPI CloudScanner::scanFiles(LPVOID lpParam) {
	CloudScanner* fs = (CloudScanner*)lpParam;

	try {
		while (!fs->avDown) {
			WIN32_FIND_DATAA file;

			std::stack<std::string, std::vector<std::string>> fstack(fs->scanPath);
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
							if (/*GetBinaryTypeA(path.c_str(), &binaryType) && */(CompareFileTime(&lastModified, &fs->lastScanTime) >= 0)) {
								FileInfo info;
								if (fs->sendFileToAnalyse(path, &info)) {
									fs->makeDecision(&info);
								}
							}
						}
					} while (FindNextFileA(hFile, &file));

					FindClose(hFile);
				}
			}
			SYSTEMTIME systemTime;
			GetSystemTime(&systemTime);
			SystemTimeToFileTime(&systemTime, &fs->lastScanTime);
			Sleep(fs->scanPeriod);
		}
	} catch (int e) {
		fs->logger->log("AVCloud | scanFiles exception");
	}
	return 0;
}

BOOL CloudScanner::sendJson(std::string& requestJson, std::string& responseJson) {
	DWORD dwSize = 0;
	DWORD dwDownloaded = 0;
	LPSTR pszOutBuffer;
	BOOL  bResults = FALSE;
	HINTERNET  hSession = NULL,
		hConnect = NULL,
		hRequest = NULL;
	hSession = WinHttpOpen(L"WinHTTP Example/1.0",
		WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
		WINHTTP_NO_PROXY_NAME,
		WINHTTP_NO_PROXY_BYPASS, 0);
	if (hSession)
		hConnect = WinHttpConnect(hSession, L"avcuckooserver", 4443, 0);
	if (hConnect)
		hRequest = WinHttpOpenRequest(hConnect, L"POST", NULL,
			NULL, WINHTTP_NO_REFERER,
			WINHTTP_DEFAULT_ACCEPT_TYPES,
			WINHTTP_FLAG_SECURE);
	if (hRequest)
		bResults = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, (LPVOID)requestJson.c_str(), requestJson.length(), requestJson.length(), 0);
	if (bResults)
		bResults = WinHttpReceiveResponse(hRequest, NULL);

	DWORD dwStatusCode = 0;
	DWORD dwStatusCodeSize = sizeof(dwStatusCode);
	WinHttpQueryHeaders(hRequest,
		WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
		WINHTTP_HEADER_NAME_BY_INDEX,
		&dwStatusCode, &dwStatusCodeSize, WINHTTP_NO_HEADER_INDEX);
	bResults = (dwStatusCode == 200);

	std::stringstream ss;
	if (bResults) {
		do {
			dwSize = 0;
			if (WinHttpQueryDataAvailable(hRequest, &dwSize)) {
				pszOutBuffer = new char[dwSize + 1];
				if (!pszOutBuffer) {
					dwSize = 0;
				}
				else {
					pszOutBuffer[dwSize] = 0;
					if (WinHttpReadData(hRequest, (LPVOID)pszOutBuffer, dwSize, &dwDownloaded))
						ss << pszOutBuffer;

					delete[] pszOutBuffer;
				}
			}
		} while (dwSize > 0);
	}
	if (!bResults) {
		this->logger->log("AVCloud | NetworkError");
		return FALSE;
	}
	else {
		responseJson = ss.str();
	}

	// Close any open handles.
	if (hRequest) WinHttpCloseHandle(hRequest);
	if (hConnect) WinHttpCloseHandle(hConnect);
	if (hSession) WinHttpCloseHandle(hSession);

	return TRUE;
}

BOOL CloudScanner::sendFileToAnalyse(std::string filePath, FileInfo *info) {
	HANDLE hFile = CreateFileA(filePath.c_str(),
		GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return FALSE;
	}

	DWORD fileSize, dataRead;
	fileSize = GetFileSize(hFile, NULL);
	BYTE* buffer = new BYTE[fileSize];
	BOOL bResults = ReadFile(hFile, buffer, fileSize, &dataRead, NULL);
	CloseHandle(hFile);

	if ((!bResults) || (dataRead == 0)) {
		return FALSE;
	}

	std::string hashStr;
	if (!CloudScanner::hashFile(buffer, fileSize, &hashStr) ||
		this->filesSkip.find(hashStr) != this->filesSkip.end()) {
		delete buffer;
		return FALSE;
	}

	this->logger->log(std::string("AVCloud | File to scan ") + filePath + " " + hashStr);

	json hashRequestJson;
	hashRequestJson["action"] = "check_md5";
	hashRequestJson["md5"] = hashStr;
	std::string hashRequest = hashRequestJson.dump(), hashResponse;
	if (!sendJson(hashRequest, hashResponse)) {
		this->logger->log("AVCloud | MD5 check send failed");
		return FALSE;
	}
	this->logger->log("AVCloud | MD5 check sent");
	json responseJson = json::parse(hashResponse);

	float cuckooscore = -1, mlscore = -1;
	std::string status = responseJson["status"].get<std::string>();

	this->logger->log("AVCloud | MD5 check status " + status);

	if (status != "not_found") {
		cuckooscore = std::stof(responseJson["cuckoo_score"].get<std::string>());
		mlscore = std::stof(responseJson["ml_score"].get<std::string>());
		*info = { hashStr, filePath, mlscore, cuckooscore };
		if (status == "analysing") {
			this->putFileInfo(*info);
		}
	} else {
		DWORD cchString = 0;
		CryptBinaryToStringA(buffer, dataRead, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCR | CRYPT_STRING_NOCRLF, NULL, &cchString);
		CHAR* szString = new CHAR[cchString];
		bResults = CryptBinaryToStringA(buffer, dataRead, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCR | CRYPT_STRING_NOCRLF, szString, &cchString);

		if (!bResults) {
			return FALSE;
		}

		json fileRequestJson;
		fileRequestJson["action"] = "analyse_file";
		fileRequestJson["payload"] = std::string(szString);
		fileRequestJson["file_name"] = std::string(PathFindFileNameA(filePath.c_str()));
		fileRequestJson["md5"] = hashStr;
		std::string fileRequest = fileRequestJson.dump();
		std::string fileResponse;
		if (sendJson(fileRequest, fileResponse)) {
			json fileResponseJson = json::parse(fileResponse);
			mlscore = std::stof(fileResponseJson["ml_score"].get<std::string>());
			cuckooscore = std::stof(fileResponseJson["cuckoo_score"].get<std::string>());
			*info = { hashStr, filePath, mlscore, cuckooscore };
			if (fileResponseJson["status"].get<std::string>() == "analysing") {
				this->putFileInfo(*info);
			}
		}

		delete buffer;
		delete szString;
	}

	return TRUE;
}

void CloudScanner::putFileInfo(FileInfo info) {
	this->logger->log("AVCloud | putFileInfo ");
	WaitForSingleObject(this->mutex, INFINITE);
	this->cuckooQueue.push(info);
	ReleaseMutex(this->mutex);
}

FileInfo CloudScanner::getFileInfo() {
	FileInfo info;
	WaitForSingleObject(this->mutex, INFINITE);
	if (this->cuckooQueue.empty()) {
		info = { 0 };
	}
	else {
		info = this->cuckooQueue.front();
		this->cuckooQueue.pop();	
	}
	ReleaseMutex(this->mutex);
	return info;
}

size_t CloudScanner::queueSize() {

	WaitForSingleObject(this->mutex, INFINITE);
	size_t size = this->cuckooQueue.size();
	ReleaseMutex(this->mutex);
	return size;
}

BOOL CloudScanner::readSkipFileHashes()
{
	std::ifstream in(this->skipListFile);
	if (!in) { return FALSE; }
	std::string str;
	while (std::getline(in, str)){
		this->filesSkip.insert(str);
	}
	in.close();
	return TRUE;
}

BOOL CloudScanner::hashFile(BYTE *data, DWORD dataLength, std::string *hashStr) {
	HCRYPTPROV hCryptProv = NULL;
	HCRYPTHASH   hHash = NULL;
	BYTE* pbHash = NULL;
	DWORD        dwHashLen;
	DWORD        dwHashLenSize = sizeof(DWORD);
	DWORD        i;

	BOOL result = CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
	if (result)  result = CryptCreateHash(hCryptProv, CALG_MD5, 0, 0, &hHash);
	if (result)  result = CryptHashData(hHash, data, dataLength, NULL);
	if (result)  result = CryptGetHashParam(hHash, HP_HASHSIZE, (BYTE*)&dwHashLen, &dwHashLenSize, 0);
	if (result)  result = (pbHash = (BYTE*)malloc(dwHashLen)) != NULL;
	if (result)  result = CryptGetHashParam(hHash, HP_HASHVAL, pbHash, &dwHashLen, 0);
	if (result) {
		CHAR* hashCStr = new CHAR[dwHashLen * 2 + 1];
		hashCStr[dwHashLen * 2] = 0;
		for (i = 0; i < dwHashLen; i++) {
			sprintf_s(hashCStr + i * 2, (dwHashLen - i) * 2 + 1, "%02x", pbHash[i]);
		}
		*hashStr = std::string(hashCStr);
		delete hashCStr;
	}

	if (hHash) CryptDestroyHash(hHash);
	if (hCryptProv) CryptReleaseContext(hCryptProv, 0);

	return result;
}

BOOL CloudScanner::addScannedFile(std::string hash) {
	std::ofstream f;
	f.open(this->skipListFile, std::ios_base::app);
	f << hash << std::endl;
	f.close();
	this->filesSkip.insert(hash);
	return TRUE;
}
