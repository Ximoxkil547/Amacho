#pragma once
#pragma comment (lib, "Dbghelp.lib")
#pragma comment (lib, "Ws2_32.lib")
#pragma warning(disable : 4996)
#include <iostream>
#include "windows.h"
#include <TlHelp32.h>
#include <minidumpapiset.h>
using namespace std;
class DumpLsass
{

    public:
        bool isElevatedProcess();
        DWORD GetProcessIDByName(const wstring& processName);
        bool setPrivilege();
};

