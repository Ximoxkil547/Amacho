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
typedef struct _ProcessInfo {
	INT PID = NULL;
	PSID SID_OwnerP = NULL;
	PCHAR Domain_User_Name;
	PWCHAR Name_Process;
	size_t Domain_User_Name_Len = 0, Name_Process_Len = 0;
}ProcessInfo, * PProcessInfo;


class tokenImpersonate
{
public:
	PCHAR CombineUserDomainName(PCHAR Domain, PCHAR User);
	void DeallocProcessInfo(PProcessInfo process);
	PProcessInfo GetProcessInfo(PPROCESSENTRY32 processEntry32);
	list<PProcessInfo> EnumerateProcesses();
	bool hasImpersonatePrivilege();
	int ImpersonateTokenAndSpawnNewProcess(int TargetPID, PWCHAR ProcessToLaunch);
	

};

