#pragma once
#include <cstdint>
#include <Windows.h>
#include <string>
#include <tuple>
#include <iostream>
#include <Psapi.h>
#include "defs.hpp"

std::uint32_t GetCodeRva(byte* RawFileBuffer);
std::wstring GetFakeCommandLineArguments();
std::tuple<HANDLE, std::wstring> CreateTemporaryFile();
HANDLE EnumerateRuntimeBrokerProcess();