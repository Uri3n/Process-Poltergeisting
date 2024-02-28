#pragma once
#include <Windows.h>
#include <cstdint>
#include <iostream>
#include <tuple>
#include "Structures.hpp"
#include "defs.hpp"


typedef NTSTATUS(NTAPI* fnNtQueryInformationProcess)(

    _In_ HANDLE ProcessHandle,
    _In_ PROCESSINFOCLASS ProcessInformationClass,
    _Out_writes_bytes_(ProcessInformationLength) PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength,
    _Out_opt_ PULONG ReturnLength

);