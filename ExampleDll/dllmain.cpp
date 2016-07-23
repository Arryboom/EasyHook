// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "stdafx.h"
#include "easyhook.h"
#include "DriverShared.h"

EASYHOOK_BOOL_EXPORT EasyHookDllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved);

// NtCreateFile 的函数指针
typedef NTSTATUS(NTAPI* pfnNTCREATEFILE) (
	OUT PHANDLE             FileHandle,
	IN ACCESS_MASK          DesiredAccess,
	IN POBJECT_ATTRIBUTES   ObjectAttributes,
	OUT PVOID               IoStatusBlock,
	IN PLARGE_INTEGER       AllocationSize OPTIONAL,
	IN ULONG                FileAttributes,
	IN ULONG                ShareAccess,
	IN ULONG                CreateDisposition,
	IN ULONG                CreateOptions,
	IN PVOID                EaBuffer OPTIONAL,
	IN ULONG                EaLength
	);

// 全局变量
pfnNTCREATEFILE			pfnNtCreateFile = (pfnNTCREATEFILE)GetProcAddress(GetModuleHandle(_T("ntdll.dll")), "NtCreateFile");
TRACED_HOOK_HANDLE      hHookNtCreateFile = new HOOK_TRACE_INFO();
ULONG                   HookNtCreateFile_ACLEntries[1] = { 0 };

NTSTATUS NTAPI NtCreateFileHook(OUT PHANDLE FileHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PLARGE_INTEGER AllocationSize OPTIONAL,
	IN ULONG FileAttributes,
	IN ULONG ShareAccess,
	IN ULONG CreateDisposition,
	IN ULONG CreateOptions,
	IN PVOID EaBuffer OPTIONAL,
	IN ULONG EaLength)
{
	// 打印被打开的文件名参数
	if (CreateDisposition == FILE_CREATE &&
		ShareAccess & (FILE_SHARE_READ | FILE_SHARE_WRITE))
	{
		CString csOutput;
		csOutput.Format(_T("ObjectName = %s, FileAttributes = 0x%08X, ShareAccess = 0x%08X, CreateDisposition  = 0x%08X, CreateOptions = 0x%08X\n"),
			ObjectAttributes->ObjectName->Buffer,
			FileAttributes,
			ShareAccess,
			CreateDisposition,
			CreateOptions);
		OutputDebugString(csOutput);
	}
	// 调用系统原有的 NtCreateFile
	return pfnNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes,
		IoStatusBlock, AllocationSize, FileAttributes, ShareAccess,
		CreateDisposition, CreateOptions, EaBuffer, EaLength);
}

BOOL InstallHook()
{
	NTSTATUS	status;
	TCHAR		szCurrentProcessName[MAX_PATH] = { 0 };

	GetModuleFileName(NULL, szCurrentProcessName, _countof(szCurrentProcessName));
	OutputDebugString(szCurrentProcessName);

	// 开始 Hook NtCreateFile 函数，使其跳转到自己的 NtCreateFileHook 函数中
	status = LhInstallHook(pfnNtCreateFile, NtCreateFileHook, NULL, hHookNtCreateFile);
	if (!SUCCEEDED(status))
	{
		OutputDebugString(_T("LhInstallHook failed..\n"));
		return FALSE;
	}

	// 开始 Hook，如果不调用这句，Hook 是不生效的
	status = LhSetExclusiveACL(HookNtCreateFile_ACLEntries, 1, hHookNtCreateFile);
	if (!SUCCEEDED(status))
	{
		OutputDebugString(_T("LhSetInclusiveACL failed..\n"));
		return FALSE;
	}

	OutputDebugString(_T("InstallHook success...\n"));

	return TRUE;
}

BOOL UnInstallHook()
{
	LhUninstallAllHooks();

	if (NULL != hHookNtCreateFile)
	{
		LhUninstallHook(hHookNtCreateFile);
		delete hHookNtCreateFile;
		hHookNtCreateFile = NULL;
	}

	LhWaitForPendingRemovals();

	OutputDebugString(_T("UninstallHook success...\n"));

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
	// 调用 EasyHook 的入口处理函数
	EasyHookDllMain(hModule, ul_reason_for_call, lpReserved);
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		// 调用 InstallHook 的线程
		StartHookThread();
		OutputDebugString(_T("DLL_PROCESS_ATTACH\n"));
	}
	break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
	{
		// 调用 UnInstallHook 的线程
		UnInstallHook();
		OutputDebugString(_T("DLL_PROCESS_DETACH\n"));
	}
	break;
	}
	return TRUE;
}

