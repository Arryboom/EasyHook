// dllmain.cpp : ���� DLL Ӧ�ó������ڵ㡣
#include "stdafx.h"
#include "easyhook.h"
#include "DriverShared.h"

EASYHOOK_BOOL_EXPORT EasyHookDllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved);

// NtCreateFile �ĺ���ָ��
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

// ȫ�ֱ���
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
	// ��ӡ���򿪵��ļ�������
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
	// ����ϵͳԭ�е� NtCreateFile
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

	// ��ʼ Hook NtCreateFile ������ʹ����ת���Լ��� NtCreateFileHook ������
	status = LhInstallHook(pfnNtCreateFile, NtCreateFileHook, NULL, hHookNtCreateFile);
	if (!SUCCEEDED(status))
	{
		OutputDebugString(_T("LhInstallHook failed..\n"));
		return FALSE;
	}

	// ��ʼ Hook�������������䣬Hook �ǲ���Ч��
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
	// ���� EasyHook ����ڴ�����
	EasyHookDllMain(hModule, ul_reason_for_call, lpReserved);
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		// ���� InstallHook ���߳�
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
		// ���� UnInstallHook ���߳�
		UnInstallHook();
		OutputDebugString(_T("DLL_PROCESS_DETACH\n"));
	}
	break;
	}
	return TRUE;
}

