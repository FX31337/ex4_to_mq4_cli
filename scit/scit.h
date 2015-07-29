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

#ifndef _SCIT_H_
#define _SCIT_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <windows.h>
#include <imagehlp.h>
#include <winnt.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <string.h>
#include <stdio.h>

#include "libdasm/libdasm.h"

//#include "udis86.h"

#define SCIT_CURRENT_PROCESS  0
#define SCIT_ALL_PROCESSES   -1

#define SCIT_MAX_FUNCTIONS 4096
#define SCIT_DLL_NAME_LEN 256
#define SCIT_API_NAME_LEN 256

/* hook types for scitHookAPI & scitUnhookAPI */
#define SCIT_HOOK_HOST_IAT 1


typedef struct ScitInjectedProcessDescriptor_s {
	HANDLE hProcess;
	DWORD dwProcessId;
	LPSTR lpLibPath;
	HMODULE hModule;
	HMODULE hInjectedModule;
	BOOL bOk;
	DWORD dwReturnValue;
} ScitInjectedProcessDescriptor_t;


typedef struct ScitFunctionArgument_s {
	LPVOID lpArg;
	DWORD dwArgLength;
	DWORD dwType;  /* not used */
} ScitFunctionArguments_t;


typedef struct ScitApiDescriptor_s {
	LPSTR lpName;
	FARPROC fAddr;
} ScitApiDescriptor_t;


typedef struct ScitFunction_s {
	CHAR lpDllName[256];
	CHAR lpApiName[256];
	FARPROC fpHandler;
	FARPROC *fpOldHandlerPtr;
	DWORD *dwAdditionalDataPtr;
} ScitFunction_t;


typedef struct ScitFunctionEATPointer_s {
	DWORD dwOrdinal;
	PDWORD pExportAddress;
	char *pFunctionName;
} ScitFunctionEATPointer_t;


typedef struct ScitAPICode_s {
	CHAR lpDllName[256];
	CHAR lpApiName[256];
	PVOID *pOriginalCode;
	DWORD dwOriginalCodeLength;
	FARPROC fpOriginalAPIAddress;
} ScitAPICode_t;


FARPROC _scit_dbghelp_dll_ImageDirectoryEntryToData;
FARPROC _scit_dbghelp_dll_ImageRvaToVa;


/* public */
ScitInjectedProcessDescriptor_t scitRemoteHookAPI(ScitInjectedProcessDescriptor_t ipd, LPCSTR lpDllName, LPCSTR lpApiName, FARPROC fpHandler, FARPROC *fpOldHandlerPtr, BOOL bDebugee);
ScitInjectedProcessDescriptor_t scitRemoteUnhookExports_EAT(ScitInjectedProcessDescriptor_t ipd, LPCSTR lpDllName, BOOL bDebugee);
ScitInjectedProcessDescriptor_t scitCallInjectedModuleMethod(ScitInjectedProcessDescriptor_t ipd, LPTHREAD_START_ROUTINE lpRemoteFunc, LPVOID lpParameter, DWORD dwParameterLength, BOOL bDebugee);
ScitInjectedProcessDescriptor_t scitInjectLocalModuleByExeName(LPCSTR lpExeName, BOOL bForce, BOOL bDebugee);
ScitInjectedProcessDescriptor_t scitInjectLocalModule(DWORD dwProcessId, BOOL bForce, BOOL bDebugee);
ScitInjectedProcessDescriptor_t scitInjectModule(DWORD dwProcessId, LPCSTR lpLibPath, BOOL bForce, BOOL bDebugee);
BOOL scitUninjectModule(ScitInjectedProcessDescriptor_t ipd);
FARPROC scitHookAPI(LPCSTR lpDllName, LPCSTR lpApiName, FARPROC fpHandler);
ScitInjectedProcessDescriptor_t scitRemoteBackupAPICode(ScitInjectedProcessDescriptor_t ipd, LPCSTR lpDllName, LPCSTR lpApiName, DWORD *dwOriginalCodePtr, BOOL bDebugee);
ScitAPICode_t *scitBackupAPICode(LPCSTR lpDllName, LPCSTR lpApiName);
BOOL scitRestoreAPICode(ScitAPICode_t *pCode, BOOL bFree);
void scitFreeAPICodeBackup(ScitAPICode_t *code);
FARPROC scitUnhookAPI(LPCSTR lpDllName, LPCSTR lpApiName, FARPROC fpNewHandler, FARPROC fpOldHandler);
int scitUnhookExports_EAT(LPCSTR lpDllName);
int scitUnhookImports_IAT(LPCSTR lpDllName);


/* protected */
BOOL _scitInit_dbghelp_dll();
ScitFunctionEATPointer_t *_scitBuildEATMap(unsigned char *image, BOOL bLoadedAsDLL);
WINBASEAPI DWORD WINAPI _scitRemoteHookAPI(void* args);
DWORD _scitGetExitCodeThread(HANDLE hRemoteThread, BOOL bDebugee);
void _scitReleaseAndUnloadModule(HANDLE hProcess, DWORD dwProcessId, LPCSTR lpLibPath, PVOID lpRemoteAddress, DWORD dwFreeMode, void *buffer2free, void *lpDwSectionsProtect, ScitInjectedProcessDescriptor_t ipd);
void _scitFixImports(HMODULE hInjectedModule, unsigned char *imageBuffer, DWORD dwImageBufferLen);
void _scitFixRelocations(HMODULE hInjectedModule, char *imageBuffer, DWORD dwImageBufferLen);
void _scitFreeDescriptor(ScitInjectedProcessDescriptor_t ipd);
char *_strndup_(const char *s, size_t n);
int _scitBuildExportedFunctionsMap(HMODULE hDll, ScitApiDescriptor_t *aFunctions, DWORD nFunctions);
int _scitGetExportedFunctionCodeLength(LPCSTR lpApiName, ScitApiDescriptor_t *aFunctions, DWORD nFunctions);
void _scitFix_E8_E9(BYTE *functionCode, DWORD functionCodeLength, DWORD currentApiAddress, LPVOID newApiAddress);
DWORD _scitUnconditionalAddress2RelativeFromTo(DWORD dwFrom, DWORD dwTo);

#ifdef __cplusplus
}
#endif

#endif  /* _SCIT_H_ */
