// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "stdafx.h"
#include "easyhook.h"
#include "DriverShared.h"

EXTERN_C BOOL APIENTRY EasyHookLib_DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved);

BOOL InstallHook()
{
	TCHAR		szCurrentProcessName[MAX_PATH] = { 0 };
	GetModuleFileName(NULL, szCurrentProcessName, _countof(szCurrentProcessName));
	return TRUE;
}

BOOL UnInstallHook()
{
	return TRUE;
}

DWORD WINAPI HookThreadProc(LPVOID lpParamter)
{
	InstallHook();
	return 0;
}

void StartHookThread()
{
	DWORD dwThreadID = 0;
	HANDLE hThread = CreateThread(NULL, 0, HookThreadProc, NULL, 0, &dwThreadID);
	CloseHandle(hThread);
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	EasyHookLib_DllMain(hModule, ul_reason_for_call, lpReserved);
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		{
			OutputDebugString(_T("测试名单DLL： DLL_PROCESS_ATTACH"));
		}
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		{
			OutputDebugString(_T("测试名单DLL： DLL_PROCESS_DETACH"));
		}
		break;
	}
	return TRUE;
}

