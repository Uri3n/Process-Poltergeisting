#pragma once
#include <iostream>
#include <Windows.h>

#define WIN32_ERR(API) std::cerr << "[!] " << #API " Failed With Error: " << GetLastError() << std::endl;
#define NTAPI_ERR(STUB, STATUS) std::cerr << "[!] " << #STUB << " Failed With Status: " << std::hex << STATUS << std::endl;