#define _WIN32_WINNT 0x0501
#include <iostream>
#include <sstream>
#include <windows.h>
#include <shlobj.h>
#include <objbase.h>
#include <objidl.h>
#include <olectlid.h>
#include <tchar.h>
#include <wchar.h>

using namespace std;

#define APP_NAME "ex4_to_mq4_auto"

//#define WND_NAME "EX4-TO-MQ4 Decompiler (https://purebeam.biz)"
//#define EXE_NAME "ex4_to_mq4_demo.exe"

#define WND_NAME "NotePAD"
#define EXE_NAME "notepad.exe"


#define null NULL

//http://dl3d.free.fr/phpBB2/viewtopic.php?t=1491&sid=045c9eb99fa395bfccd79fead4a5a6cd
/*
if (HGLOBAL hGlobal = GlobalAlloc(GHND, sizeof(DROPFILES) + _tcslen(filename) + 2))
 {
   DROPFILES *df = static_cast<DROPFILES>(GlobalLock(hGlobal));
   df->pFiles = sizeof(DROPFILES);
   df->fWide = TRUE;
   _tcscpy(reinterpret_cast<TCHAR>(df + 1), filename);
   GlobalUnlock(hGlobal);
   Interface12 *ip = GetCOREInterface12();
   if (!ip || !PostMessage(ip->GetMAXHWnd(), WM_DROPFILES, (WPARAM)hGlobal, 0))
    GlobalFree(hGlobal);
 }
*/
HGLOBAL getHDROP(wchar_t* filePath) {
	SIZE_T dropFilesSize = sizeof(DROPFILES) + (sizeof(WCHAR) * (wcslen(filePath) + 2));
    HGLOBAL memObj = GlobalAlloc(GHND | GMEM_SHARE, dropFilesSize);
    if (!memObj)
        return 0;

    DROPFILES* dropFiles = (DROPFILES*) GlobalLock(memObj);
    dropFiles->pFiles = sizeof(DROPFILES);
    dropFiles->fWide = TRUE;
    wcscpy((LPWSTR)(dropFiles + 1), filePath);
    GlobalUnlock(memObj);

    return memObj;
}


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


int main(int argc, char **argv)
{
	PROCESS_INFORMATION pi;
	STARTUPINFO si;
	stringstream ss;
	HWND hWnd = 0;
	HDROP hDrop;


	if (argc <= 1) {
		ss << "Usage: " << argv[0] << " <ex4 file> [...]";
		MessageBox(0, ss.str().c_str(), APP_NAME, 0);
		return 1;
	}

	hWnd = _FindWindow(WND_NAME, WND_NAME);
	if (!hWnd) {
		memset(&si, 0, sizeof(si));
		memset(&pi, 0, sizeof(pi));

		if (!CreateProcess(EXE_NAME, null, null, null, false, 0, null, null, &si, &pi)) {
			MessageBox(0, "Unable to run ex4_to_mq4_demo.exe", APP_NAME, 0);
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

	hDrop = (HDROP)getHDROP(L"D:\\prj\\cl workspace\\ex4_to_mq4_auto\\Debug\\Foo.ex4");
	SendMessage(hWnd, WM_DROPFILES, (WPARAM)hDrop, 0);
//	PostMessage(hWnd, WM_DROPFILES, (WPARAM)hDrop, 0);
//	GlobalFree(hWnd);
	return 0;
}
