#define _WIN32_WINNT 0x0501

#include <windows.h>
#include <shlobj.h>
#include <objbase.h>
#include <objidl.h>
#include <olectlid.h>
#include <tchar.h>
#include <wchar.h>

#include "scit/scit.h"

#define null NULL
#define true 1
#define false 0

#define APP_NAME "ex4_to_mq4_auto"

//L"D:\\prj\\cl workspace\\ex4_to_mq4_auto\\Debug\\Foo.ex4"

#define WND_NAME "EX4-TO-MQ4 Decompiler (https://purebeam.biz)"
#define EXE_NAME "ex4_to_mq4_demo.exe"

//#define WND_NAME "NotePAD"
//#define EXE_NAME "notepad.exe"

typedef UINT WINAPI DragQueryFileW_t(HDROP,UINT,LPWSTR,UINT);

DragQueryFileW_t *oldDragQueryFileW;
wchar_t tmpWcBuff[1024];


HWND WINAPI _FindWindow(LPCTSTR lpClassName, LPCTSTR lpWindowName)
{
	HWND hWnd;


	hWnd = FindWindow(lpClassName, null);
	if (hWnd) {
		return hWnd;
	}
	hWnd = FindWindow(null, lpWindowName);
	if (hWnd) {
		return hWnd;
	}
	return 0;
}


/*
 * http://msdn.microsoft.com/en-us/library/windows/desktop/bb776408(v=vs.85).aspx
 */
UINT WINAPI myDragQueryFileW(HDROP hDrop, UINT iFile, LPWSTR lpszFile, UINT cch) {
    if (iFile == -1) {
        return 1;
    }

    if ((int)hDrop == 123 && iFile == 0) {
        wcsncpy(lpszFile, tmpWcBuff, cch);
        return wcslen(tmpWcBuff);
    }

    return oldDragQueryFileW(hDrop, iFile, lpszFile, cch);
}


int main(int argc, char **argv)
{
    ScitInjectedProcessDescriptor_t ipd;
	PROCESS_INFORMATION pi;
	STARTUPINFO si;
	HWND hWnd = 0;
    char tmpBuff[1024];
    DWORD dwTargetTmpWcBuff;
    SIZE_T stWritten;
    int i;


	if (argc <= 1) {
        memset(tmpBuff, 0, sizeof(tmpBuff));
        snprintf(tmpBuff, sizeof(tmpBuff), "Usage: %s <ex4 file> [...]", argv[0]);
		MessageBox(0, tmpBuff, APP_NAME, 0);
		return 1;
	}

	hWnd = _FindWindow(WND_NAME, WND_NAME);
	if (!hWnd) {
		memset(&si, 0, sizeof(si));
		memset(&pi, 0, sizeof(pi));

		if (!CreateProcess(EXE_NAME, null, null, null, false, 0, null, null, &si, &pi)) {
            memset(tmpBuff, 0, sizeof(tmpBuff));
            snprintf(tmpBuff, sizeof(tmpBuff), "Unable to run %s", EXE_NAME);
			MessageBox(0, tmpBuff, APP_NAME, 0);
			return 1;
		}

		do {
			if (!hWnd) {
				hWnd = _FindWindow(WND_NAME, WND_NAME);
				if (hWnd) {
					break;
				}
			}
		} while (WaitForSingleObject(pi.hProcess, 0));
	}

    ipd = scitInjectLocalModule(pi.dwProcessId, TRUE, FALSE);
    if (ipd.bOk) {
        ipd = scitRemoteHookAPI(ipd, "shell32.dll", "DragQueryFileW", (FARPROC)myDragQueryFileW, (FARPROC*)&oldDragQueryFileW, FALSE);
    }

    //calculate tmpWcBuff in remote process
    dwTargetTmpWcBuff = (DWORD)tmpWcBuff - (DWORD)ipd.hModule + (DWORD)ipd.hInjectedModule;

    for (i = 1; i < argc; i++) {
        //get fullpath of target file
        memset(tmpBuff, 0, sizeof(tmpBuff));
        GetFullPathName(argv[i], sizeof(tmpBuff), tmpBuff, null);

        //copy to local buffer as unicode string
        mbstowcs(tmpWcBuff, tmpBuff, 1024);

        //write file pathname to remote process and send WM_DROPFILES message
        WriteProcessMemory(pi.hProcess, (LPVOID)dwTargetTmpWcBuff, tmpWcBuff, sizeof(tmpWcBuff), &stWritten);
        SendMessage(hWnd, WM_DROPFILES, 123, 0);
    }

	//wait until process terminate
//	do {
//	} while (WaitForSingleObject(pi.hProcess, 1));

    TerminateProcess(pi.hProcess, 0);

	return 0;
}
