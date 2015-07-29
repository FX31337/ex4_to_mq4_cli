/*
This file is part of DosBox Injector.

DosBox Injector is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

DosBox Injector is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with DosBox Injector.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "scit.h"


void _scitReleaseAndUnloadModule(HANDLE hProcess, DWORD dwProcessId, LPCSTR lpLibPath, PVOID lpRemoteAddress, DWORD dwFreeMode, void *buffer2free, void *lpDwSectionsProtect, ScitInjectedProcessDescriptor_t ipd) {
	DWORD dwLastError = GetLastError();

	if (lpRemoteAddress) {
		VirtualFreeEx(hProcess, lpRemoteAddress, 0, MEM_RELEASE);
	}

	if (lpDwSectionsProtect) {
		free(lpDwSectionsProtect);
		lpDwSectionsProtect = 0;
	}

	if (hProcess) {
		CloseHandle(hProcess);
	}

	if (buffer2free) {
		free(buffer2free);
		buffer2free = 0;
	}

	scitUninjectModule(ipd);
	_scitFreeDescriptor(ipd);

	SetLastError(dwLastError);
}


ScitInjectedProcessDescriptor_t scitCallInjectedModuleMethod(ScitInjectedProcessDescriptor_t ipd, LPTHREAD_START_ROUTINE lpRemoteFunc, LPVOID lpParameter, DWORD dwParameterLength, BOOL bDebugee) {
	HANDLE hRemoteThread;
	DWORD dwThreadExitCode;
	DWORD dwRemoteFunction = (DWORD) lpRemoteFunc;
	DWORD dwDelta;
	ScitFunctionArguments_t arg;
	LPVOID lpArgRemoteAddress = 0;
	BOOL bInjected;
	DWORD dwSizeWritten;
	HMODULE hKernel32;


	ipd.bOk = FALSE;

	if (!ipd.hInjectedModule || !ipd.hProcess || !lpRemoteFunc) {
		return ipd;
	}

	hKernel32 = GetModuleHandle("KERNEL32.DLL");
	if(!hKernel32) {
		hKernel32 = GetModuleHandle("kernel32.dll");
		if (!hKernel32) {
			return ipd;
		}
	}

	/* use address of currently loaded executable will be the same in remote loaded */
	dwDelta = (DWORD) ipd.hInjectedModule - (DWORD) GetModuleHandle(0);
	dwRemoteFunction += dwDelta;
	lpRemoteFunc = (LPTHREAD_START_ROUTINE) dwRemoteFunction;

	if (lpParameter && dwParameterLength) {
		/* inject parameter using ScitFunctionArguments_t */
		arg.lpArg = VirtualAllocEx(ipd.hProcess, NULL, dwParameterLength, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
		arg.dwArgLength = dwParameterLength;
		arg.dwType = 0;

		if (!arg.lpArg) {
			return ipd;
		}

		lpArgRemoteAddress = VirtualAllocEx(ipd.hProcess, NULL, sizeof(ScitFunctionArguments_t), MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
		if (!lpArgRemoteAddress) {
			VirtualFreeEx(ipd.hProcess, arg.lpArg, 0, MEM_RELEASE);

			return ipd;
		}

		/* write param */
		bInjected = WriteProcessMemory(ipd.hProcess, arg.lpArg, lpParameter, dwParameterLength, &dwSizeWritten);
		if (!bInjected) {
			VirtualFreeEx(ipd.hProcess, arg.lpArg, 0, MEM_RELEASE);
			VirtualFreeEx(ipd.hProcess, lpArgRemoteAddress, 0, MEM_RELEASE);

			return ipd;
		}

		bInjected = WriteProcessMemory(ipd.hProcess, lpArgRemoteAddress, &arg, sizeof(ScitFunctionArguments_t), &dwSizeWritten);
		if (!bInjected) {
			VirtualFreeEx(ipd.hProcess, lpArgRemoteAddress, 0, MEM_RELEASE);

			return ipd;
		}
	}

	hRemoteThread = CreateRemoteThread(ipd.hProcess, NULL, 0, lpRemoteFunc, lpArgRemoteAddress, 0, NULL);
	if (!hRemoteThread) {
		if (lpArgRemoteAddress) {
			VirtualFreeEx(ipd.hProcess, lpArgRemoteAddress, 0, MEM_RELEASE);
		}

		if (arg.lpArg) {
			VirtualFreeEx(ipd.hProcess, arg.lpArg, 0, MEM_RELEASE);
		}

		return ipd;
	}

	dwThreadExitCode = _scitGetExitCodeThread(hRemoteThread, bDebugee);

	CloseHandle(hRemoteThread);

	/* free args */
	if (lpArgRemoteAddress) {
		VirtualFreeEx(ipd.hProcess, lpArgRemoteAddress, 0, MEM_RELEASE);
	}
	if (arg.lpArg) {
		VirtualFreeEx(ipd.hProcess, arg.lpArg, 0, MEM_RELEASE);
	}

	/*printf("%x\n", dwThreadExitCode);*/

	ipd.bOk = TRUE;
	ipd.dwReturnValue = dwThreadExitCode;

	return ipd;
}


int scitUnhookImports_IAT(LPCSTR lpDllName) {
	HMODULE hLocalModule = GetModuleHandle(0);
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS pNtHeader;
	PIMAGE_IMPORT_DESCRIPTOR pImageImportDescriptor;
	DWORD lpInjectedModuleImportOffset;
	char dllName[512];


	if (!hLocalModule) {
		return 0;
	}

	pDosHeader = (PIMAGE_DOS_HEADER) hLocalModule;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		return 0;
	}

	pNtHeader = (PIMAGE_NT_HEADERS) ((DWORD) hLocalModule + pDosHeader->e_lfanew);
	if (pNtHeader->Signature != IMAGE_NT_SIGNATURE) {
		return 0;
	}

	if (
		!pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress ||
		!pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size
	) {
		return 0;
	}

	lpInjectedModuleImportOffset = (DWORD) hLocalModule + pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

	do {
		pImageImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR) lpInjectedModuleImportOffset;
		if (!pImageImportDescriptor->FirstThunk) {
			break;
		}

		/* read imported DLL name */
		memset(dllName, 0, 512);
		memcpy(dllName, (const void*) ((DWORD)hLocalModule + pImageImportDescriptor->Name), 512);

		if (!lstrcmpiA(lpDllName, dllName) != 0) {
			//ok find dll

			break;
		}

//		/* now me must load a DLL itself to get remote function address */
//		hModule = LoadLibrary(dllName);
//		/* hModule holds now a image base, we can use it to get RVA of remote function*/
//
//		lpInjectedModuleImportThunkOffset = (DWORD) imageBuffer + pImageImportDescriptor->FirstThunk;
//		do {
//			pImageThunkData = (PIMAGE_THUNK_DATA) lpInjectedModuleImportThunkOffset;
//			if (!pImageThunkData->u1.Function) {
//				break;
//			}
//
//			/* read imported function name */
//			memset(funcName, 0, 512);
//			memcpy(funcName, imageBuffer + pImageThunkData->u1.Function + sizeof(pImageImportByName->Hint), 512);
//
//			/*
//			 * get address of remote function - experimental - we should get function addreess
//			 * directly from loaded module, not our module - TODO
//			 */
//			dwJmpAddr = (DWORD) GetProcAddress(hModule, funcName);
//
//			/* printf("%x -> %x\n", pImageThunkData->u1.Function, dwJmpAddr); */
//			/* change function address */
//			pImageThunkData->u1.Function = dwJmpAddr;
//
//			lpInjectedModuleImportThunkOffset += sizeof(IMAGE_THUNK_DATA);
//		} while (pImageThunkData->u1.Function);

		lpInjectedModuleImportOffset += sizeof(IMAGE_IMPORT_DESCRIPTOR);
	} while (pImageImportDescriptor->FirstThunk);

	return 0;
}


BOOL _scitInit_dbghelp_dll() {
	HMODULE hModule;


	if (
		_scit_dbghelp_dll_ImageDirectoryEntryToData &&
		_scit_dbghelp_dll_ImageRvaToVa
	) {
		return TRUE;
	}

	hModule = GetModuleHandle("dbghelp.dll");
	if (!hModule) {
		hModule = LoadLibrary("dbghelp.dll");
		if (!hModule) {
			return FALSE;
		}
	}

	_scit_dbghelp_dll_ImageDirectoryEntryToData		= GetProcAddress(hModule, "ImageDirectoryEntryToData");
	_scit_dbghelp_dll_ImageRvaToVa 					= GetProcAddress(hModule, "ImageRvaToVa");

	if (
		!_scit_dbghelp_dll_ImageDirectoryEntryToData ||
		!_scit_dbghelp_dll_ImageRvaToVa
	) {
		return FALSE;
	}

	return TRUE;
}


ScitFunctionEATPointer_t *_scitBuildEATMap(unsigned char *image, BOOL bLoadedAsDLL) {
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS pNtHeader;
	PIMAGE_EXPORT_DIRECTORY pReal_ExportDirectory;
	PDWORD pReal_ExportAddressTable;
	PWORD pReal_ExportOrdinalTable;
	PDWORD pReal_AddressOfNames;
	PDWORD pReal_FunctionName;
	DWORD i, j, dwOrdinal;
	ScitFunctionEATPointer_t *map;
	int mapLen;
	ULONG dirSize;


	pDosHeader = (PIMAGE_DOS_HEADER) image;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		return 0;
	}

	pNtHeader = (PIMAGE_NT_HEADERS) ((DWORD) image + pDosHeader->e_lfanew);
	if (pNtHeader->Signature != IMAGE_NT_SIGNATURE) {
		return 0;
	}

	if (!_scitInit_dbghelp_dll()) {
		return 0;
	}

	pReal_ExportDirectory = (PIMAGE_EXPORT_DIRECTORY) _scit_dbghelp_dll_ImageDirectoryEntryToData(image, bLoadedAsDLL, IMAGE_DIRECTORY_ENTRY_EXPORT, &dirSize);

	if (bLoadedAsDLL) {
		pReal_ExportAddressTable 	= (PDWORD) 	((DWORD)image + pReal_ExportDirectory ->AddressOfFunctions);
		pReal_ExportOrdinalTable 	= (PWORD) 	((DWORD)image + pReal_ExportDirectory->AddressOfNameOrdinals);
		pReal_AddressOfNames 		= (PDWORD) 	((DWORD)image + pReal_ExportDirectory->AddressOfNames);
	}
	else {
		pReal_ExportAddressTable 	= (PDWORD) 	_scit_dbghelp_dll_ImageRvaToVa(pNtHeader, image, pReal_ExportDirectory ->AddressOfFunctions, 0);
		pReal_ExportOrdinalTable 	= (PWORD) 	_scit_dbghelp_dll_ImageRvaToVa(pNtHeader, image, pReal_ExportDirectory ->AddressOfNameOrdinals, 0);
		pReal_AddressOfNames 		= (PDWORD) 	_scit_dbghelp_dll_ImageRvaToVa(pNtHeader, image, pReal_ExportDirectory ->AddressOfNames, 0);
	}

	mapLen = sizeof(ScitFunctionEATPointer_t) * (pReal_ExportDirectory->NumberOfFunctions + 1);
	map = malloc(mapLen);
	if (!map) {
		return 0;
	}

	memset(map, 0, mapLen);

	for (i = 0; i < pReal_ExportDirectory->NumberOfFunctions; i++) {
		pReal_FunctionName = (PDWORD) &"?";
		dwOrdinal = (int) (i + pReal_ExportDirectory->Base);

		for(j=0; j<pReal_ExportDirectory->NumberOfNames; j++) {
			if(pReal_ExportOrdinalTable[j] == i) {
				if (bLoadedAsDLL) {
					pReal_FunctionName = (PDWORD) ((DWORD)image + pReal_AddressOfNames[j]);
				}
				else {
					pReal_FunctionName = (PDWORD) _scit_dbghelp_dll_ImageRvaToVa(pNtHeader, image, pReal_AddressOfNames[j], 0);
				}

				break;
			}
		}

		map[i].dwOrdinal = dwOrdinal;
		map[i].pExportAddress = &pReal_ExportAddressTable[i];
		map[i].pFunctionName = (char*)pReal_FunctionName;
	}

	return map;
}


int scitUnhookExports_EAT(LPCSTR lpDllName) {
	HMODULE hModule = GetModuleHandle(lpDllName);
	char lpModuleFilename[512];
	ScitFunctionEATPointer_t *aEATMemoryMap;
	ScitFunctionEATPointer_t *aEATDiskMap;
	ScitFunctionEATPointer_t funcPointerMemory;
	ScitFunctionEATPointer_t funcPointerDisk;
	FILE *f;
	char *fileMap;
	int i, fileLen;
	char buffer1[33];
	char buffer2[33];


	if (!hModule) {
		return 0;
	}

	//get loaded dll pathname
	memset(lpModuleFilename, 0, sizeof(lpModuleFilename));
	GetModuleFileName(hModule, lpModuleFilename, sizeof(lpModuleFilename));

	//create map of loaded dll from disk
	f = fopen(lpModuleFilename, "rb");
	if (!f) {
		return 0;
	}

	fseek(f, 0, SEEK_END);
	fileLen = ftell(f);
	rewind(f);

	if (!fileLen) {
		fclose(f);
		f = 0;

		return 0;
	}

	fileMap = malloc(fileLen);
	if (!fileMap) {
		fclose(f);
		f = 0;

		return 0;
	}

	fread(fileMap, 1, fileLen, f);

	fclose(f);
	f = 0;

	memset(buffer1, 0, sizeof(buffer1));
	memset(buffer2, 0, sizeof(buffer2));

	//diff EATs
	aEATMemoryMap	= _scitBuildEATMap((unsigned char *) hModule, TRUE);
	aEATDiskMap		= _scitBuildEATMap((unsigned char *) fileMap, FALSE);

	if (aEATDiskMap) {
		i = 0;

		while (aEATDiskMap[i].pFunctionName) {
			funcPointerDisk		= aEATDiskMap[i];
			funcPointerMemory 	= aEATMemoryMap[i];

			if (*funcPointerDisk.pExportAddress != *funcPointerMemory.pExportAddress) {
				MessageBoxA(0, funcPointerDisk.pFunctionName, funcPointerMemory.pFunctionName, 0);
			}

			i++;
		}
	}

	if (aEATMemoryMap) {
		free(aEATMemoryMap);
		aEATMemoryMap = 0;
	}

	if (aEATDiskMap) {
		free(aEATDiskMap);
		aEATDiskMap = 0;
	}

	if (!fileMap) {
		free(fileMap);
		fileMap = 0;
	}

	return 0;
}


void _scitFixImports(HMODULE hInjectedModule, unsigned char *imageBuffer, DWORD dwImageBufferLen) {
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER) imageBuffer;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS) ((DWORD) imageBuffer + pDosHeader->e_lfanew);
	PIMAGE_IMPORT_DESCRIPTOR pImageImportDescriptor;
	PIMAGE_THUNK_DATA pImageThunkData;
	PIMAGE_IMPORT_BY_NAME pImageImportByName;
	IMAGE_IMPORT_BY_NAME imageImportByName;
	DWORD lpInjectedModuleImportOffset;
	DWORD lpInjectedModuleImportThunkOffset;
	char dllName[512], funcName[512];
	HINSTANCE hModule;
	DWORD dwJmpAddr;
	DWORD dwDelta;
	DWORD i;


	if ((DWORD) hInjectedModule == pNtHeader->OptionalHeader.ImageBase) {
		return;
	}

	dwDelta = (DWORD) hInjectedModule - pNtHeader->OptionalHeader.ImageBase;

	for (i = 0; i < pNtHeader->OptionalHeader.SizeOfImage; i++) {
		/*
		 * following two instructions (FF,25) depends on CPU family
		 * FF, 25 means FAR JMP used in win32/x86
		 */
		if (imageBuffer[i] == 0xFF && imageBuffer[i + 1] == 0x25) {
			memcpy(&dwJmpAddr, &imageBuffer[i + 2], sizeof(DWORD));

			if (dwJmpAddr >= pNtHeader->OptionalHeader.ImageBase && dwJmpAddr <= pNtHeader->OptionalHeader.ImageBase + pNtHeader->OptionalHeader.SizeOfImage) {
				/*printf("%x -> %x\n", dwJmpAddr, dwJmpAddr + dwDelta);*/

				dwJmpAddr += dwDelta;
				memcpy(&imageBuffer[i + 2], &dwJmpAddr, sizeof(DWORD));
			}
		}
	}

	lpInjectedModuleImportOffset = (DWORD) imageBuffer + pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

	do {
		pImageImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR) lpInjectedModuleImportOffset;
		if (!pImageImportDescriptor->FirstThunk) {
			break;
		}

		/* read imported DLL name */
		memset(dllName, 0, 512);
		memcpy(dllName, imageBuffer + pImageImportDescriptor->Name, 512);

		/* now me must load a DLL itself to get remote function address */
		hModule = LoadLibrary(dllName);
		/* hModule holds now a image base, we can use it to get RVA of remote function*/

		lpInjectedModuleImportThunkOffset = (DWORD) imageBuffer + pImageImportDescriptor->FirstThunk;
		do {
			pImageThunkData = (PIMAGE_THUNK_DATA) lpInjectedModuleImportThunkOffset;
			if (!pImageThunkData->u1.Function) {
				break;
			}

			/* read imported function name */
			memset(funcName, 0, 512);
//			memcpy(funcName, imageBuffer + pImageThunkData->u1.Function + sizeof(pImageImportByName->Hint), 512);
//			memcpy(funcName, imageBuffer + pImageThunkData->u1.Function, + sizeof(imageImportByName.Hint), 512);
			memcpy(funcName, imageBuffer + pImageThunkData->u1.Function + sizeof(imageImportByName.Hint), 512);

			/*
			 * get address of remote function - experimental - we should get function addreess
			 * directly from loaded module, not our module - TODO
			 */
			dwJmpAddr = (DWORD) GetProcAddress(hModule, funcName);

			/* printf("%x -> %x\n", pImageThunkData->u1.Function, dwJmpAddr); */
			/* change function address */
			pImageThunkData->u1.Function = dwJmpAddr;

			lpInjectedModuleImportThunkOffset += sizeof(IMAGE_THUNK_DATA);
		} while (pImageThunkData->u1.Function);

		lpInjectedModuleImportOffset += sizeof(IMAGE_IMPORT_DESCRIPTOR);
	} while (pImageImportDescriptor->FirstThunk);
}


void _scitFixRelocations(HMODULE hInjectedModule, char *imageBuffer, DWORD dwImageBufferLen) {
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER) imageBuffer;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS) ((DWORD) imageBuffer + pDosHeader->e_lfanew);
	DWORD lpBaseRelocOffset, dwNextReloc;
	PIMAGE_BASE_RELOCATION imageRelocation;
	unsigned char *lpByteArray;
	DWORD dwValue;
	DWORD dwDelta;
	WORD wEntry;
	WORD wAddr;
	WORD wType;
	WORD wRva;
	DWORD i;


	if ((DWORD) hInjectedModule == pNtHeader->OptionalHeader.ImageBase) {
		return;
	}

	dwDelta = (DWORD) hInjectedModule - pNtHeader->OptionalHeader.ImageBase;

	lpBaseRelocOffset = pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;

	dwNextReloc = (DWORD) imageBuffer + lpBaseRelocOffset;

	do {
		imageRelocation = (PIMAGE_BASE_RELOCATION) dwNextReloc;
		if (!imageRelocation->VirtualAddress) {
			break;
		}

		lpByteArray = (unsigned char*) imageRelocation;
		for (i = sizeof(IMAGE_BASE_RELOCATION); i < imageRelocation->SizeOfBlock; i += sizeof(WORD)) {
			memcpy(&wEntry, (const void*) ((DWORD) lpByteArray + i), sizeof(WORD));

			wType = (wEntry & 0xF000) >> 12;
			wAddr = wEntry & 0x0FFF;
			wRva = imageRelocation->VirtualAddress + wAddr;

			if (wType == IMAGE_REL_BASED_HIGHLOW) {
				memcpy(&dwValue, (const void*) ((DWORD) imageBuffer + wRva), sizeof(DWORD));

				if (dwValue - pNtHeader->OptionalHeader.ImageBase <= 0 || dwValue - pNtHeader->OptionalHeader.ImageBase > pNtHeader->OptionalHeader.SizeOfImage)
					continue;

				/* printf("[%x]: %x -> %x\n", (DWORD) hInjectedModule + wRva, dwValue, dwValue + dwDelta); */

				dwValue += dwDelta;

				memcpy((void*) ((DWORD) imageBuffer + wRva), &dwValue, sizeof(DWORD));
			}
		}

		dwNextReloc += imageRelocation->SizeOfBlock;
	} while (imageRelocation->VirtualAddress);
}


ScitInjectedProcessDescriptor_t scitInjectLocalModuleByExeName(LPCSTR lpExeName, BOOL bForce, BOOL bDebugee) {
	DWORD aProcesses[4096], cbNeeded, cProcesses;
	TCHAR szProcessName[MAX_PATH];
	ScitInjectedProcessDescriptor_t ipd;
	TCHAR szLibPath[MAX_PATH];
	DWORD dwProcessId;
	HANDLE hProcess;
	DWORD i;

	ipd.bOk = FALSE;

	GetModuleFileName(0, szLibPath, MAX_PATH);

    if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded)) {
        return ipd;
	}

	cProcesses = cbNeeded / sizeof(DWORD);
    for (i = 0; i < (int) cProcesses; i++) {
        if (aProcesses[i] != 0) {
            dwProcessId = aProcesses[i];

            hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, dwProcessId);
            if (hProcess) {
                GetModuleBaseName(hProcess, 0, szProcessName, sizeof(szProcessName)/sizeof(TCHAR));
                CloseHandle(hProcess);

				if (!strcasecmp(szProcessName, lpExeName)) {
					return scitInjectModule(dwProcessId, szLibPath, bForce, bDebugee);
				}
            }
        }
    }

	return ipd;
}


ScitInjectedProcessDescriptor_t scitInjectLocalModule(DWORD dwProcessId, BOOL bForce, BOOL bDebugee) {
	TCHAR szLibPath[MAX_PATH];


	GetModuleFileName(0, szLibPath, MAX_PATH);
	return scitInjectModule(dwProcessId, szLibPath, bForce, bDebugee);
}


WINBASEAPI DWORD WINAPI _scitRemoteUnhookExports_EAT(void* args) {
	ScitFunctionArguments_t *arg = args;

	if (!arg->lpArg || !arg->dwArgLength) {
		return 0;
	}

	return scitUnhookExports_EAT(arg->lpArg);
}


WINBASEAPI DWORD WINAPI _scitRemoteHookAPI(void* args) {
	ScitFunctionArguments_t *arg;
	ScitFunction_t function;

	arg = args;
	memcpy(&function, arg->lpArg, arg->dwArgLength);

	*function.fpOldHandlerPtr = (FARPROC)scitHookAPI(function.lpDllName, function.lpApiName, function.fpHandler);

	return (DWORD)*function.fpOldHandlerPtr;
}


ScitInjectedProcessDescriptor_t scitRemoteUnhookExports_EAT(ScitInjectedProcessDescriptor_t ipd, LPCSTR lpDllName, BOOL bDebugee) {
	return scitCallInjectedModuleMethod(ipd, (LPTHREAD_START_ROUTINE)_scitRemoteUnhookExports_EAT, (LPVOID) lpDllName, strlen(lpDllName) + 1, bDebugee);
}


ScitInjectedProcessDescriptor_t scitRemoteHookAPI(ScitInjectedProcessDescriptor_t ipd, LPCSTR lpDllName, LPCSTR lpApiName, FARPROC fpHandler, FARPROC *fpOldHandlerPtr, BOOL bDebugee) {
	ScitFunction_t function;


	memset(&function, 0, sizeof(ScitFunction_t));

	//todo - check it, experimental!
	function.fpHandler = (FARPROC) ((DWORD)fpHandler - (DWORD)ipd.hModule + (DWORD)ipd.hInjectedModule);
	function.fpOldHandlerPtr = (FARPROC*) ((DWORD)fpOldHandlerPtr - (DWORD)ipd.hModule + (DWORD)ipd.hInjectedModule);

	strncpy(function.lpDllName, lpDllName, SCIT_DLL_NAME_LEN);
	strncpy(function.lpApiName, lpApiName, SCIT_API_NAME_LEN);

	ipd = scitCallInjectedModuleMethod(ipd, (LPTHREAD_START_ROUTINE)_scitRemoteHookAPI, &function, sizeof(ScitFunction_t), bDebugee);

	*fpOldHandlerPtr = (FARPROC)ipd.dwReturnValue;

	return ipd;
}


DWORD _scitGetExitCodeThread(HANDLE hRemoteThread, BOOL bDebugee) {
	DWORD dwThreadExitCode = -1;
	DEBUG_EVENT de;


	do {
		GetExitCodeThread(hRemoteThread, (LPDWORD)&dwThreadExitCode);

		if (dwThreadExitCode == STILL_ACTIVE && bDebugee) {
			if (!WaitForDebugEvent(&de, INFINITE)) {
				break;
			}
			ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);
		}
	} while (dwThreadExitCode == STILL_ACTIVE);

	return dwThreadExitCode;
}


ScitInjectedProcessDescriptor_t scitInjectModule(DWORD dwProcessId, LPCSTR lpLibPath, BOOL bForce, BOOL bDebugee) {
	ScitInjectedProcessDescriptor_t ipd;
	DWORD dwLibPathSize;
	HMODULE hKernel32;
	HANDLE hProcess = 0;
	LPVOID lpRemoteAddress = 0;
	BOOL bInjected;
	DWORD dwSizeWritten;
	unsigned char *imageBuffer = 0;
	HANDLE hRemoteThread;
	HMODULE hInjectedModule;
	HMODULE hModule;
	BOOL bReaded;
	DWORD dwSizeReaded;
	LPVOID lpHeaderOffset;
	LPVOID lpSectionOffset;
	IMAGE_DOS_HEADER dosHeader;
	IMAGE_NT_HEADERS ntHeader;
	IMAGE_DOS_HEADER dosCurrentHeader;
	IMAGE_NT_HEADERS ntCurrentHeader;
	IMAGE_SECTION_HEADER section;
	MEMORY_BASIC_INFORMATION memoryBasicInformation;
	DWORD dwOldProtect, dwOldProtect_;
	DWORD *lpDwSectionsProtect = 0;
	DWORD i;


	memset(&ipd, 0, sizeof(ScitInjectedProcessDescriptor_t));

	if (!lpLibPath) {
		return ipd;
	}

	if (dwProcessId == SCIT_CURRENT_PROCESS) {
		dwProcessId = GetCurrentProcessId();
	}

	ipd.bOk = 0;
	ipd.hProcess = 0;
	ipd.dwProcessId = dwProcessId;
	ipd.lpLibPath = strdup(lpLibPath);
	ipd.hInjectedModule = 0;
	ipd.hModule = 0;

	if (!ipd.lpLibPath) {
		_scitReleaseAndUnloadModule(hProcess, dwProcessId, lpLibPath, lpRemoteAddress, MEM_RELEASE, imageBuffer, lpDwSectionsProtect, ipd);

		return ipd;
	}

	dwLibPathSize = strlen(lpLibPath);

	hKernel32 = GetModuleHandle("KERNEL32.DLL");
	if(!hKernel32) {
		hKernel32 = GetModuleHandle("kernel32.dll");
		if (!hKernel32) {
			_scitReleaseAndUnloadModule(hProcess, dwProcessId, lpLibPath, lpRemoteAddress, MEM_RELEASE, imageBuffer, lpDwSectionsProtect, ipd);

			return ipd;
		}
	}

	hProcess = OpenProcess(PROCESS_ALL_ACCESS | PROCESS_VM_OPERATION, FALSE, dwProcessId);
	if (!hProcess) {
		_scitReleaseAndUnloadModule(hProcess, dwProcessId, lpLibPath, lpRemoteAddress, MEM_RELEASE, imageBuffer, lpDwSectionsProtect, ipd);

		return ipd;
	}

	/* get image base of current module */
	hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "GetModuleHandleA"), 0, 0, NULL);
	if (!hRemoteThread) {
		_scitReleaseAndUnloadModule(hProcess, dwProcessId, lpLibPath, lpRemoteAddress, MEM_RELEASE, imageBuffer, lpDwSectionsProtect, ipd);

		return ipd;
	}

	hModule = (HMODULE) _scitGetExitCodeThread(hRemoteThread, bDebugee);

	CloseHandle(hRemoteThread);

	/* read DOS and PE headers of current module */
	bReaded = ReadProcessMemory(hProcess, (LPVOID) ((DWORD) hModule), &dosCurrentHeader, sizeof(IMAGE_DOS_HEADER), &dwSizeReaded);
	if (!bReaded) {
		_scitReleaseAndUnloadModule(hProcess, dwProcessId, lpLibPath, lpRemoteAddress, MEM_RELEASE, imageBuffer, lpDwSectionsProtect, ipd);

		return ipd;
	}

	if (dosCurrentHeader.e_magic != IMAGE_DOS_SIGNATURE) {
		_scitReleaseAndUnloadModule(hProcess, dwProcessId, lpLibPath, lpRemoteAddress, MEM_RELEASE, imageBuffer, lpDwSectionsProtect, ipd);

		return ipd;
	}

	/* read PE header */
	lpHeaderOffset = (LPVOID) ((DWORD) hModule + (DWORD) dosCurrentHeader.e_lfanew);
	bReaded = ReadProcessMemory(hProcess, lpHeaderOffset, &ntCurrentHeader, sizeof(IMAGE_NT_HEADERS), &dwSizeReaded);
	if (!bReaded) {
		_scitReleaseAndUnloadModule(hProcess, dwProcessId, lpLibPath, lpRemoteAddress, MEM_RELEASE, imageBuffer, lpDwSectionsProtect, ipd);

		return ipd;
	}

	if (ntCurrentHeader.FileHeader.NumberOfSections <= 0) {
		/* wrong file? */
		_scitReleaseAndUnloadModule(hProcess, dwProcessId, lpLibPath, lpRemoteAddress, MEM_RELEASE, imageBuffer, lpDwSectionsProtect, ipd);

		return ipd;
	}

	lpSectionOffset = (LPVOID) ((DWORD) hModule + (DWORD) dosCurrentHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS));
	for (i = 0; i < ntCurrentHeader.FileHeader.NumberOfSections; i++) {
		bReaded = ReadProcessMemory(hProcess, (LPVOID) ((DWORD) lpSectionOffset + (i * sizeof(IMAGE_SECTION_HEADER))), &section, sizeof(IMAGE_SECTION_HEADER), &dwSizeReaded);
		if (!bReaded) {
			_scitReleaseAndUnloadModule(hProcess, dwProcessId, lpLibPath, lpRemoteAddress, MEM_RELEASE, imageBuffer, lpDwSectionsProtect, ipd);

			return ipd;
		}

		if ((section.Characteristics & IMAGE_SCN_CNT_CODE) && (section.Characteristics & IMAGE_SCN_MEM_WRITE) && !bForce)
		{
			/* strange - code section have write flag, maybe it's packed/compressed
			 * so we can wait until it will be ready for infection
			 */
			_scitReleaseAndUnloadModule(hProcess, dwProcessId, lpLibPath, lpRemoteAddress, MEM_RELEASE, imageBuffer, lpDwSectionsProtect, ipd);

			return ipd;
		}
	}

	/* alloc remote memory */
	lpRemoteAddress = VirtualAllocEx(hProcess, NULL, dwLibPathSize + 1, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
	if (!lpRemoteAddress) {
		_scitReleaseAndUnloadModule(hProcess, dwProcessId, lpLibPath, lpRemoteAddress, MEM_RELEASE, imageBuffer, lpDwSectionsProtect, ipd);

		return ipd;
	}

	bInjected = WriteProcessMemory(hProcess, lpRemoteAddress, (LPVOID)lpLibPath, dwLibPathSize, &dwSizeWritten);
	if (!bInjected) {
		_scitReleaseAndUnloadModule(hProcess, dwProcessId, lpLibPath, lpRemoteAddress, MEM_RELEASE, imageBuffer, lpDwSectionsProtect, ipd);

		return ipd;
	}

	/* check if DLL is already injected... */
	hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "GetModuleHandleA"), lpRemoteAddress, 0, NULL);
	if (!hRemoteThread) {
		_scitReleaseAndUnloadModule(hProcess, dwProcessId, lpLibPath, lpRemoteAddress, MEM_RELEASE, imageBuffer, lpDwSectionsProtect, ipd);

		return ipd;
	}

	hInjectedModule = (HMODULE) _scitGetExitCodeThread(hRemoteThread, bDebugee);

	CloseHandle(hRemoteThread);

	/* DLL already injected? */
	if (hInjectedModule) {
		_scitReleaseAndUnloadModule(hProcess, dwProcessId, lpLibPath, lpRemoteAddress, MEM_RELEASE, imageBuffer, lpDwSectionsProtect, ipd);

		return ipd;
	}

	hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryA"), lpRemoteAddress, 0, NULL);
	if (!hRemoteThread) {
		_scitReleaseAndUnloadModule(hProcess, dwProcessId, lpLibPath, lpRemoteAddress, MEM_RELEASE, imageBuffer, lpDwSectionsProtect, ipd);

		return ipd;
	}

	hInjectedModule = (HMODULE) _scitGetExitCodeThread(hRemoteThread, bDebugee);

	CloseHandle(hRemoteThread);

	/* free module name buffer */
	VirtualFreeEx(hProcess, lpRemoteAddress, 0, MEM_RELEASE);
	lpRemoteAddress = 0;

	/* read DOS header */
	bReaded = ReadProcessMemory(hProcess, (LPVOID) hInjectedModule, &dosHeader, sizeof(IMAGE_DOS_HEADER), &dwSizeReaded);
	if (!bReaded) {
		_scitReleaseAndUnloadModule(hProcess, dwProcessId, lpLibPath, lpRemoteAddress, MEM_RELEASE, imageBuffer, lpDwSectionsProtect, ipd);

		return ipd;
	}

	if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
		_scitReleaseAndUnloadModule(hProcess, dwProcessId, lpLibPath, lpRemoteAddress, MEM_RELEASE, imageBuffer, lpDwSectionsProtect, ipd);

		return ipd;
	}

	/* read PE header */
	lpHeaderOffset = (LPVOID) ((DWORD) hInjectedModule + (DWORD) dosHeader.e_lfanew);
	bReaded = ReadProcessMemory(hProcess, lpHeaderOffset, &ntHeader, sizeof(IMAGE_NT_HEADERS), &dwSizeReaded);
	if (!bReaded) {
		_scitReleaseAndUnloadModule(hProcess, dwProcessId, lpLibPath, lpRemoteAddress, MEM_RELEASE, imageBuffer, lpDwSectionsProtect, ipd);

		return ipd;
	}

	if (ntHeader.OptionalHeader.ImageBase != (DWORD) hInjectedModule) {
		lpDwSectionsProtect = (LPDWORD) malloc(IMAGE_NUMBEROF_DIRECTORY_ENTRIES * sizeof(DWORD));
		if (!lpDwSectionsProtect) {
			_scitReleaseAndUnloadModule(hProcess, dwProcessId, lpLibPath, lpRemoteAddress, MEM_RELEASE, imageBuffer, lpDwSectionsProtect, ipd);

			return ipd;
		}

		/* get memory regions protect information */
		for (i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++) {
			lpDwSectionsProtect[i] = 0;

			if (ntHeader.OptionalHeader.DataDirectory[i].VirtualAddress && ntHeader.OptionalHeader.DataDirectory[i].Size) {
				if (VirtualQueryEx(hProcess, (LPVOID) ((DWORD) hInjectedModule + ntHeader.OptionalHeader.DataDirectory[i].VirtualAddress), &memoryBasicInformation, ntHeader.OptionalHeader.DataDirectory[i].Size)) {
					if (memoryBasicInformation.AllocationProtect) {
						lpDwSectionsProtect[i] = memoryBasicInformation.AllocationProtect;
					}

					/* printf("%x, %d, %x\n", ntHeader.OptionalHeader.DataDirectory[i].VirtualAddress, ntHeader.OptionalHeader.DataDirectory[i].Size, lpDwSectionsProtect[i]); */
				}

			}

			/* printf("%x\n", lpDwSectionsProtect[i]); */
		}

		if (!(imageBuffer = (unsigned char*) malloc(ntHeader.OptionalHeader.SizeOfImage + 1))) {
			_scitReleaseAndUnloadModule(hProcess, dwProcessId, lpLibPath, lpRemoteAddress, MEM_RELEASE, imageBuffer, lpDwSectionsProtect, ipd);

			return ipd;
		}

		/* unlock memory before read/write */
		if (!VirtualProtectEx(hProcess, (LPVOID) hInjectedModule, ntHeader.OptionalHeader.SizeOfImage, PAGE_READWRITE, &dwOldProtect)) {
			_scitReleaseAndUnloadModule(hProcess, dwProcessId, lpLibPath, lpRemoteAddress, MEM_RELEASE, imageBuffer, lpDwSectionsProtect, ipd);

			return ipd;
		}

		bReaded = ReadProcessMemory(hProcess, (LPVOID) hInjectedModule, imageBuffer, ntHeader.OptionalHeader.SizeOfImage, &dwSizeReaded);
		if (!bReaded) {
			_scitReleaseAndUnloadModule(hProcess, dwProcessId, lpLibPath, lpRemoteAddress, MEM_RELEASE, imageBuffer, lpDwSectionsProtect, ipd);

			return ipd;
		}

		_scitFixRelocations(hInjectedModule, (char*)imageBuffer, ntHeader.OptionalHeader.SizeOfImage);

		_scitFixImports(hInjectedModule, imageBuffer, ntHeader.OptionalHeader.SizeOfImage);

		/* write module image back to process */
		bInjected = WriteProcessMemory(hProcess, (LPVOID) hInjectedModule, imageBuffer, ntHeader.OptionalHeader.SizeOfImage, &dwSizeWritten);
		if (!bInjected) {
			_scitReleaseAndUnloadModule(hProcess, dwProcessId, lpLibPath, lpRemoteAddress, MEM_RELEASE, imageBuffer, lpDwSectionsProtect, ipd);

			return ipd;
		}

		/* restore old lock */
		if (!VirtualProtectEx(hProcess, (LPVOID) hInjectedModule, ntHeader.OptionalHeader.SizeOfImage, dwOldProtect, &dwOldProtect_)) {
			_scitReleaseAndUnloadModule(hProcess, dwProcessId, lpLibPath, lpRemoteAddress, MEM_RELEASE, imageBuffer, lpDwSectionsProtect, ipd);

			return ipd;
		}

		/* restore protect for each section */
 		for (i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++) {
			if (ntHeader.OptionalHeader.DataDirectory[i].VirtualAddress && ntHeader.OptionalHeader.DataDirectory[i].Size && lpDwSectionsProtect[i]) {
				if (!VirtualProtectEx(hProcess, (LPVOID) hInjectedModule, ntHeader.OptionalHeader.SizeOfImage, lpDwSectionsProtect[i], &dwOldProtect)) {
					_scitReleaseAndUnloadModule(hProcess, dwProcessId, lpLibPath, lpRemoteAddress, MEM_RELEASE, imageBuffer, lpDwSectionsProtect, ipd);

					return ipd;
				}
			}

			/* printf("%x\n", lpDwSectionsProtect[i]); */
		}

		free(imageBuffer);
		imageBuffer = 0;
	}

	ipd.hProcess = hProcess;
	ipd.hModule = GetModuleHandle(0);
	ipd.hInjectedModule = hInjectedModule;
	ipd.bOk = TRUE;

	return ipd;
}


void _scitFreeDescriptor(ScitInjectedProcessDescriptor_t ipd) {
	if (ipd.lpLibPath) {
		free(ipd.lpLibPath);
	}

	ipd.hProcess = 0;
	ipd.dwProcessId = 0;
	ipd.lpLibPath = 0;
	ipd.hInjectedModule = 0;
}


BOOL scitUninjectModule(ScitInjectedProcessDescriptor_t ipd) {
	HANDLE hRemoteThread;
	LPVOID lpRemoteAddress;
	BOOL bUninjected;
	DWORD dwThreadExitCode;
	DWORD dwSizeWritten;
	DWORD dwSize;
	HMODULE hKernel32;
	HMODULE hModule;


	if (!ipd.lpLibPath || !ipd.hProcess) {
		return FALSE;
	}

	if (ipd.dwProcessId == SCIT_CURRENT_PROCESS)
		ipd.dwProcessId = GetCurrentProcessId();

	dwSize = strlen(ipd.lpLibPath);

	hKernel32 = GetModuleHandle("KERNEL32.DLL");
	if(!hKernel32) {
		hKernel32 = GetModuleHandle("kernel32.dll");
		if (!hKernel32) {
			return FALSE;
		}
	}

	lpRemoteAddress = VirtualAllocEx(ipd.hProcess, NULL, dwSize + 1, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
	if (!lpRemoteAddress) {
		return FALSE;
	}

	bUninjected = WriteProcessMemory(ipd.hProcess, lpRemoteAddress, (LPVOID) ipd.lpLibPath, dwSize, &dwSizeWritten);
	if (!bUninjected) {
		return FALSE;
	}

	/* check if DLL is already injected... */
	hRemoteThread = CreateRemoteThread(ipd.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "GetModuleHandleA"), lpRemoteAddress, 0, NULL);
	if (!hRemoteThread) {
		return FALSE;
	}

	hModule = (HMODULE) _scitGetExitCodeThread(hRemoteThread, FALSE);

	CloseHandle(hRemoteThread);

	/* DLL already injected? */
	if (!hModule) {
		return FALSE;
	}

	hRemoteThread = CreateRemoteThread(ipd.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "GetModuleHandleA"), lpRemoteAddress, 0, NULL);
	if (!hRemoteThread) {
		return FALSE;
	}

	hModule = (HMODULE) _scitGetExitCodeThread(hRemoteThread, FALSE);

	CloseHandle(hRemoteThread);

	if (!hModule) {
		return FALSE;
	}

	hRemoteThread = CreateRemoteThread(ipd.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "FreeLibrary"), hModule, 0, NULL);
	if (!hRemoteThread) {
		return FALSE;
	}

	dwThreadExitCode = _scitGetExitCodeThread(hRemoteThread, FALSE);

	CloseHandle(hRemoteThread);

	if (ipd.hProcess) {
		VirtualFreeEx(ipd.hProcess, lpRemoteAddress, 0, MEM_RELEASE);
		CloseHandle(ipd.hProcess);
	}

	_scitFreeDescriptor(ipd);

	return dwThreadExitCode > 0;
}


int _scitBuildExportedFunctionsMap(HMODULE hDll, ScitApiDescriptor_t *aFunctions, DWORD nFunctions) {
	PIMAGE_DOS_HEADER pImageDosHeader;
	PIMAGE_NT_HEADERS pImageNtHeaders;
	PIMAGE_EXPORT_DIRECTORY pImageExportDirectory;
	ScitApiDescriptor_t func1, func2;
	DWORD nExportedFunctions;
	PVOID pNames;
	DWORD i, n;
	LPSTR lpName;


	if (!hDll || !aFunctions || nFunctions <= 0) {
		return 0;
	}

	pImageDosHeader = (PIMAGE_DOS_HEADER)hDll;
	if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		return 0;
	}

	pImageNtHeaders = (PIMAGE_NT_HEADERS) ((BYTE *)pImageDosHeader + pImageDosHeader->e_lfanew);
	if (pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
		return 0;
	}

	pImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY) ((BYTE *)pImageDosHeader + pImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	pNames = (BYTE *)pImageDosHeader + pImageExportDirectory->AddressOfNames;

	/* build "map" of DLL exported functions (function name -> address) */
	for (i = 0; i < nFunctions; i++) {
		aFunctions[i].lpName = 0;
		aFunctions[i].fAddr = 0;
	}

	nExportedFunctions = 0;
	for (i = 0; i < pImageExportDirectory->NumberOfNames && i < nFunctions; i++) {
		lpName = (LPSTR) ((BYTE *)pImageDosHeader + ((DWORD *)pNames)[i]);
		if (!lpName) {
			continue;
		}
//		aFunctions[i].lpName = _strndup_((LPSTR) ((BYTE *)pImageDosHeader + ((DWORD *)pNames)[i]), 32);
		aFunctions[i].lpName = (LPSTR) ((BYTE *)pImageDosHeader + ((DWORD *)pNames)[i]);
		aFunctions[i].fAddr = GetProcAddress(hDll, aFunctions[i].lpName);

		nExportedFunctions++;
	}

	/* sort by addr */
	n = nExportedFunctions;
	do {
		for (i = 0; i < n - 1; i++) {
			if ((DWORD) aFunctions[i].fAddr > (DWORD) aFunctions[i + 1].fAddr) {
				func1 = aFunctions[i];
				func2 = aFunctions[i + 1];

				aFunctions[i] = func2;
				aFunctions[i + 1] = func1;
			}
		}

		n = n - 1;
	} while (n > 1);

	return nExportedFunctions;
}


/**
 * returned function length can be somewhat different, more than real, due to other function code
 * not described in export table (for example: IsDebuggerPresent real length is 19, but
 * this function will return 173)
 */
int _scitGetExportedFunctionCodeLength(LPCSTR lpApiName, ScitApiDescriptor_t *aFunctions, DWORD nFunctions) {
	DWORD i;


	if (!lpApiName || !aFunctions || nFunctions <= 0) {
		return 0;
	}

	/* todo: fixme: implement better method to get code length */
	for (i = 0; i < nFunctions; i++) {
		/* first - find function entry in sorted array */
		if (!lstrcmpA(aFunctions[i].lpName, lpApiName)) {
			/* get next entry */
			i++;
			if (i < nFunctions) {
				/* calculate function code length by next function */
				return (DWORD)aFunctions[i].fAddr - (DWORD)aFunctions[i - 1].fAddr;
			}

			break;
		}
	}

	return 0;
}


void _scitFix_E8_E9(BYTE *functionCode, DWORD functionCodeLength, DWORD currentApiAddress, LPVOID newApiAddress) {
	INSTRUCTION inst;
	int insLen = 0;
	int insPtr = 0;
	DWORD addr;


	if (!functionCode || functionCodeLength <= 0 || !currentApiAddress || !newApiAddress) {
		return;
	}

	do {
		if (functionCode[insPtr] == 0xE8 || functionCode[insPtr] == 0xE9) {
			/* JMP/CALL - recalculate address */
			memcpy(&addr, &functionCode[insPtr + 1], 4);

			/* calc real original address */
			addr = (DWORD)currentApiAddress + insPtr + addr + 5;

			if ((DWORD)newApiAddress + insPtr >= addr)
				addr = 0 - ((DWORD)newApiAddress + insPtr) - addr - 5;
			else
				addr = 0 - ((DWORD)newApiAddress + insPtr) + addr - 5;

			memcpy(&functionCode[insPtr + 1], &addr, 4);
		}

		insLen = get_instruction(&inst, functionCode + insPtr, MODE_32);
		if (insLen <= 0) {
			break;
		}

		insPtr += insLen;
	} while (insPtr < functionCodeLength && insLen);
}


DWORD _scitUnconditionalAddress2RelativeFromTo(DWORD dwFrom, DWORD dwTo) {
	/*
		0 - (from - desination) - 5
		ex.: 0 - ($6259326B - $02980000) - 5
	*/
	if ((DWORD)dwFrom >= (DWORD)dwTo)
		return 0 - ((DWORD)dwFrom - (DWORD)dwTo) - 5;
	else
		return 0 - ((DWORD)dwFrom + (DWORD)dwTo) - 5;
}


void scitFreeAPICodeBackup(ScitAPICode_t *code) {
	if (!code) {
		return;
	}

	if (code->pOriginalCode) {
		free(code->pOriginalCode);
		code->pOriginalCode = 0;
	}

	free(code);
	code = 0;
}


BOOL scitRestoreAPICode(ScitAPICode_t *pCode, BOOL bFree) {
	DWORD dwOriginalApiProtect;
	DWORD dwTmpOldProtect;


	if (
		!pCode ||
		pCode->dwOriginalCodeLength <= 0 ||
		!pCode->fpOriginalAPIAddress ||
		!pCode->pOriginalCode ||
		!pCode->lpApiName ||
		!pCode->lpDllName
	) {
		return FALSE;
	}

	/* unprotect function memory to get read/write access, also get old protect flags */
	dwOriginalApiProtect = 0;
	if (!VirtualProtect((LPVOID) (DWORD) pCode->fpOriginalAPIAddress, pCode->dwOriginalCodeLength, PAGE_READWRITE, &dwOriginalApiProtect)) {
		return FALSE;
	}

	/* restore original code */
	memcpy(pCode->fpOriginalAPIAddress, pCode->pOriginalCode, pCode->dwOriginalCodeLength);

	/* restore old lock */
	dwTmpOldProtect = 0;
	if (!VirtualProtect((LPVOID) (DWORD)pCode->fpOriginalAPIAddress, pCode->dwOriginalCodeLength, dwOriginalApiProtect, &dwTmpOldProtect)) {
		return FALSE;
	}

	if (bFree) {
		scitFreeAPICodeBackup(pCode);
	}

	return TRUE;
}


WINBASEAPI DWORD WINAPI _scitRemoteBackupAPICode(void* args) {
	ScitFunctionArguments_t *arg;
	ScitFunction_t function;


	arg = args;
	memcpy(&function, arg->lpArg, arg->dwArgLength);

	*function.dwAdditionalDataPtr = (DWORD)scitBackupAPICode(function.lpDllName, function.lpApiName);

	return *function.dwAdditionalDataPtr;
}


ScitInjectedProcessDescriptor_t scitRemoteBackupAPICode(ScitInjectedProcessDescriptor_t ipd, LPCSTR lpDllName, LPCSTR lpApiName, DWORD *dwOriginalCodePtr, BOOL bDebugee) {
	ScitFunction_t function;


	memset(&function, 0, sizeof(ScitFunction_t));

	function.dwAdditionalDataPtr = (DWORD*) ((DWORD)dwOriginalCodePtr - (DWORD)ipd.hModule + (DWORD)ipd.hInjectedModule);

	strncpy(function.lpDllName, lpDllName, SCIT_DLL_NAME_LEN);
	strncpy(function.lpApiName, lpApiName, SCIT_API_NAME_LEN);

	return scitCallInjectedModuleMethod(ipd, (LPTHREAD_START_ROUTINE)_scitRemoteBackupAPICode, &function, sizeof(ScitFunction_t), bDebugee);
}


ScitAPICode_t *scitBackupAPICode(LPCSTR lpDllName, LPCSTR lpApiName) {
	DWORD dwFunctionCodeLength, nFunctions = 0;
	ScitApiDescriptor_t aFunctions[SCIT_MAX_FUNCTIONS];
	ScitAPICode_t *pCode;
	FARPROC fpCurrentApiAddress;
	HMODULE hDll;


	if (!lpDllName || !lpApiName) {
		return 0;
	}

	pCode = malloc(sizeof(ScitAPICode_t));
	if (!pCode) {
		return 0;
	}

	memset(pCode, 0, sizeof(ScitAPICode_t));

	hDll = GetModuleHandleA(lpDllName);
	if (!hDll) {
		hDll = LoadLibraryA(lpDllName);
		if (!hDll) {
			free(pCode);
			return pCode;
		}
	}

	fpCurrentApiAddress = GetProcAddress(hDll, lpApiName);
	if (!fpCurrentApiAddress) {
		free(pCode);
		return pCode;
	}

	nFunctions = _scitBuildExportedFunctionsMap(hDll, aFunctions, SCIT_MAX_FUNCTIONS);
	if (!nFunctions) {
		free(pCode);
		return 0;
	}

	/* get length of function code */
	dwFunctionCodeLength = _scitGetExportedFunctionCodeLength(lpApiName, aFunctions, nFunctions);
	if (!dwFunctionCodeLength) {
		/* unable to determine function code length - exit */
		free(pCode);
		return 0;
	}

	pCode->pOriginalCode = malloc(dwFunctionCodeLength + 1);
	if (!pCode->pOriginalCode) {
		free(pCode);
		return 0;
	}

	pCode->dwOriginalCodeLength = dwFunctionCodeLength;

	memset(pCode->pOriginalCode, 0, dwFunctionCodeLength + 1);
	memcpy(pCode->pOriginalCode, fpCurrentApiAddress, dwFunctionCodeLength);

	strncpy(pCode->lpDllName, lpDllName, sizeof(pCode->lpDllName));
	strncpy(pCode->lpApiName, lpApiName, sizeof(pCode->lpApiName));

	pCode->fpOriginalAPIAddress = fpCurrentApiAddress;

	return pCode;
}


FARPROC scitHookAPI(LPCSTR lpDllName, LPCSTR lpApiName, FARPROC fpHandler) {
	ScitApiDescriptor_t functions[SCIT_MAX_FUNCTIONS];
	FARPROC currentApiAddress;
	DWORD functionCodeLength, nFunctions = 0;
	DWORD dwOriginalApiProtect, dwTmpOldProtect;
	BYTE jmpIns[5];
	HMODULE hDll;
	LPVOID newApiAddress;
	DWORD relativeNewApiAddress;


	if (!lpDllName || !lpApiName || !fpHandler) {
		return 0;
	}

	hDll = GetModuleHandleA(lpDllName);
	if (!hDll) {
		hDll = LoadLibraryA(lpDllName);
		if (!hDll) {
			return 0;
		}
	}

	currentApiAddress = GetProcAddress(hDll, lpApiName);
	if (!currentApiAddress) {
		return 0;
	}
//char buffer[33];
//itoa(currentApiAddress, buffer, 10);
//MessageBoxA(0, buffer, buffer, 0);

	nFunctions = _scitBuildExportedFunctionsMap(hDll, functions, SCIT_MAX_FUNCTIONS);
	if (!nFunctions) {
		return 0;
	}

	/* get length of function code */
	functionCodeLength = _scitGetExportedFunctionCodeLength(lpApiName, functions, nFunctions);
	if (!functionCodeLength) {
		/* unable to determine function code length - exit */
		return 0;
	}

	/* we need at least sizeof(jmpIns) bytes in old api memory area, to put E9 (JMP) XX XX XX XX instruction */
	if (functionCodeLength < 5) {
		/* insufficient memory in old api area - exit */
		return 0;
	}

	/* now we can copy function code to new address and make JMP (0xE9) in old address to our handler
	 * after that - new address will be returned
	 */

	/* allocate space for old function code */
	newApiAddress = VirtualAlloc(0, functionCodeLength, MEM_COMMIT, PAGE_READWRITE);
	if (!newApiAddress) {
		return 0;
	}

	/* copy old function code to new area */
	memcpy(newApiAddress, (void*)(DWORD)currentApiAddress, functionCodeLength);

	/* unprotect function memory to get read/write access, also get old protect flags */
	if (!VirtualProtect((LPVOID) (DWORD) currentApiAddress, 5, PAGE_READWRITE, &dwOriginalApiProtect)) {
		VirtualFree(newApiAddress, 0, MEM_RELEASE);
		return 0;
	}

	/* prepare JMP XX XX XX XX */
	relativeNewApiAddress = _scitUnconditionalAddress2RelativeFromTo((DWORD)currentApiAddress, (DWORD)fpHandler);

//	jmpIns[0] = 0xCC;
	jmpIns[0] = 0xE9;
	memcpy(&jmpIns[1], &relativeNewApiAddress, 4);

	/* finally - copy JMP FAR to old function memory area */
	memcpy((void*)(DWORD)currentApiAddress, jmpIns, 5);

	/* fix adresses used in E8/E9 instructions */
	_scitFix_E8_E9(newApiAddress, functionCodeLength, (DWORD)currentApiAddress, newApiAddress);

	/* set old protect to new function area */
	dwTmpOldProtect = 0;
	if (!VirtualProtect(newApiAddress, functionCodeLength, dwOriginalApiProtect, &dwTmpOldProtect)) {
		VirtualFree(newApiAddress, 0, MEM_RELEASE);
		return 0;
	}

	/* restore old lock */
	dwTmpOldProtect = 0;
	if (!VirtualProtect((LPVOID) (DWORD)currentApiAddress, 5, dwOriginalApiProtect, &dwTmpOldProtect)) {
		VirtualFree(newApiAddress, 0, MEM_RELEASE);
		return 0;
	}

	return (FARPROC)(DWORD)newApiAddress;
}


FARPROC scitUnhookAPI(LPCSTR lpDllName, LPCSTR lpApiName, FARPROC fpNewHandler, FARPROC fpOldHandler) {
	FARPROC fpModuleApiAddress;
	DWORD realNewApiAddress;
	HMODULE hDll;
	BYTE jmpIns[5];
	DWORD dwOriginalApiProtect;
	ScitApiDescriptor_t functions[SCIT_MAX_FUNCTIONS];
	DWORD functionCodeLength, nFunctions = 0;
	DWORD dwTmpOldProtect;


	if (!lpDllName || !lpApiName || !fpNewHandler || !fpOldHandler) {
		return 0;
	}

	hDll = GetModuleHandle(lpDllName);
	if (!hDll) {
		return 0;
	}

	fpModuleApiAddress = GetProcAddress(hDll, lpApiName);
	if (!fpModuleApiAddress) {
		return 0;
	}

	/* check if first instruction is JMP */
	memcpy(jmpIns, (void*)(DWORD)fpModuleApiAddress, 5);
	if (jmpIns[0] != 0xE9) {
		/* not a JMP instruction - not hooked */
		return 0;
	}

	/* read jmp relative address */
	memcpy(&realNewApiAddress, &jmpIns[1], 4);

	/* calculate real jmp address */
	realNewApiAddress = (DWORD)fpModuleApiAddress + realNewApiAddress + 5;
	if (realNewApiAddress != (DWORD)fpNewHandler) {
		/* JMP address does not point to our new handler - not hooked */
		return 0;
	}

	/* build dll exported functions map */
	nFunctions = _scitBuildExportedFunctionsMap(hDll, functions, SCIT_MAX_FUNCTIONS);
	if (!nFunctions) {
		return 0;
	}

	/* get length of function code */
	functionCodeLength = _scitGetExportedFunctionCodeLength(lpApiName, functions, nFunctions);
	if (!functionCodeLength) {
		/* unable to determine function code length - exit */
		return 0;
	}

	/* ok api is probably hooked, unprotect original api memory region */
	if (!VirtualProtect((LPVOID) (DWORD)fpModuleApiAddress, functionCodeLength, PAGE_READWRITE, &dwOriginalApiProtect)) {
		return 0;
	}

	/* restore original api code (also "blot" jmp xx xx xx xx) */
	memcpy((void*)(DWORD)fpModuleApiAddress, (void*)(DWORD)fpOldHandler, functionCodeLength);

	/* fix E8/E9 (jmp/call) addresses */
	_scitFix_E8_E9((BYTE*)(DWORD)fpModuleApiAddress, functionCodeLength, (DWORD)fpOldHandler, (void*)(DWORD)fpModuleApiAddress);

	/* restore old lock */
	dwTmpOldProtect = 0;
	if (!VirtualProtect((LPVOID) (DWORD)fpModuleApiAddress, functionCodeLength, dwOriginalApiProtect, &dwTmpOldProtect)) {
		return 0;
	}

	/* free new api handler memory */
	VirtualFree((LPVOID) realNewApiAddress, 0, MEM_RELEASE);

	return fpModuleApiAddress;
}
