// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "stdafx.h"
#include "easyhook.h"
#include "DriverShared.h"
#include "NtStructDef.h"

EASYHOOK_BOOL_EXPORT EasyHookDllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved);

// NtCreateFile 的函数指针
typedef NTSTATUS (NTAPI* pfnNTCREATEFILE) (
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

typedef NTSTATUS (NTAPI* pfnNTCREATEUSERPROCESS) (
	OUT PHANDLE ProcessHandle,
	OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK ProcessDesiredAccess,
	IN ACCESS_MASK ThreadDesiredAccess,
	IN POBJECT_ATTRIBUTES ProcessObjectAttributes OPTIONAL,
	IN POBJECT_ATTRIBUTES ThreadObjectAttributes OPTIONAL,
	IN ULONG CreateProcessFlags,
	IN ULONG CreateThreadFlags,
	IN PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
	IN PVOID Parameter,
	IN PNT_PROC_THREAD_ATTRIBUTE_LIST AttributeList
);

// 全局变量
pfnNTCREATEFILE			pfnNtCreateFile = NULL;
pfnNTCREATEUSERPROCESS	pfnNtCreateUserProcess = NULL;
TRACED_HOOK_HANDLE      hHookNtCreateFile = new HOOK_TRACE_INFO();
TRACED_HOOK_HANDLE      hHookNtCreateUserProcess = new HOOK_TRACE_INFO();
ULONG                   HookNtCreateFile_ACLEntries[1] = { 0 };
ULONG                   HookNtCreateUserProcess_ACLEntries[1] = { 0 };

TCHAR					szCurrentProcessName[MAX_PATH] = { 0 };
DWORD					dwCurrentProcessId;

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
	NTSTATUS ntStatus;

	// 调用系统原有的 NtCreateFile
	ntStatus = pfnNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes,
		IoStatusBlock, AllocationSize, FileAttributes, ShareAccess,
		CreateDisposition, CreateOptions, EaBuffer, EaLength);

	if (CreateDisposition >= FILE_CREATE)
	{
		CString csOutput;
		CString csFileName = _T("");

		// 处理 cmd.exe 下创建文件路径为空的问题
		if (NULL != ObjectAttributes->RootDirectory)
		{
			TCHAR szCurrentDirectory[MAX_PATH];
			GetCurrentDirectory(MAX_PATH, szCurrentDirectory);
			csFileName += szCurrentDirectory;
			csFileName += _T("\\");
		}

		csFileName += ObjectAttributes->ObjectName->Buffer;

		switch (IoStatusBlock->Information)
		{
		case FILE_CREATED:
		{
			csOutput.Format(_T("%s:%ld 创建文件 %s"), szCurrentProcessName, dwCurrentProcessId, csFileName);
			OutputDebugString(csOutput);
		}
			break;
		case FILE_OVERWRITTEN:
		{
			csOutput.Format(_T("%s:%ld 修改文件 %s"), szCurrentProcessName, dwCurrentProcessId, csFileName);
			OutputDebugString(csOutput);
		}
			break;
		}
	}

	/*csOutput.Format(_T("IoStatusBlock = 0x%08X, ObjectName = %s, FileAttributes = 0x%08X, ShareAccess = 0x%08X, CreateDisposition  = 0x%08X, CreateOptions = 0x%08X\n"),
		IoStatusBlock->Information,
		ObjectAttributes->ObjectName->Buffer,
		FileAttributes,
		ShareAccess,
		CreateDisposition,
		CreateOptions);
	OutputDebugString(csOutput);*/
	return ntStatus;
}

NTSTATUS NTAPI NtCreateUserProcessHook(
	OUT PHANDLE ProcessHandle,
	OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK ProcessDesiredAccess,
	IN ACCESS_MASK ThreadDesiredAccess,
	IN POBJECT_ATTRIBUTES ProcessObjectAttributes OPTIONAL,
	IN POBJECT_ATTRIBUTES ThreadObjectAttributes OPTIONAL,
	IN ULONG CreateProcessFlags,
	IN ULONG CreateThreadFlags,
	IN PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
	IN PVOID Parameter,
	IN PNT_PROC_THREAD_ATTRIBUTE_LIST AttributeList
)
{
	NTSTATUS ntStatus;

	// 调用系统的 NtCreateUserProcess
	ntStatus = pfnNtCreateUserProcess(ProcessHandle, ThreadHandle, ProcessDesiredAccess,
		ThreadDesiredAccess, ProcessObjectAttributes, ThreadObjectAttributes,
		CreateProcessFlags, CreateThreadFlags, ProcessParameters,
		Parameter, AttributeList);

	// 获取进程PID
	DWORD dwProcessId = GetProcessId(*ProcessHandle);

	CString csOutput;
	
	csOutput.Format(_T("%s:%ld 创建进程 %s:%ld, 参数：%s"), 
		szCurrentProcessName, dwCurrentProcessId, 
		ProcessParameters->ImagePathName.Buffer, dwProcessId, 
		ProcessParameters->CommandLine.Buffer);
	OutputDebugString(csOutput);

	return ntStatus;
}

BOOL InstallHook()
{
	NTSTATUS ntStatus;

	GetModuleFileName(NULL, szCurrentProcessName, _countof(szCurrentProcessName));
	dwCurrentProcessId = GetCurrentProcessId();

	if (NULL != pfnNtCreateFile)
	{
		// 开始 Hook NtCreateFile 函数，使其跳转到自己的 NtCreateFileHook 函数中
		ntStatus = LhInstallHook(pfnNtCreateFile, NtCreateFileHook, NULL, hHookNtCreateFile);
		if (!SUCCEEDED(ntStatus))
		{
			OutputDebugString(_T("LhInstallHook failed..\n"));
			return FALSE;
		}

		// 开始 Hook，如果不调用这句，Hook 是不生效的
		ntStatus = LhSetExclusiveACL(HookNtCreateFile_ACLEntries, 1, hHookNtCreateFile);
		if (!SUCCEEDED(ntStatus))
		{
			OutputDebugString(_T("LhSetInclusiveACL failed..\n"));
			return FALSE;
		}
	}
	else
	{
		OutputDebugString(_T("Get pfnNtCreateFile function address is NULL."));
	}
	
	if (NULL != pfnNtCreateUserProcess)
	{
		// 开始 Hook NtCreateUserProcess 函数
		ntStatus = LhInstallHook(pfnNtCreateUserProcess, NtCreateUserProcessHook, NULL, hHookNtCreateUserProcess);
		if (!SUCCEEDED(ntStatus))
		{
			OutputDebugString(_T("LhInstallHook failed..\n"));
			return FALSE;
		}

		// 开始 Hook，如果不调用这句，Hook 是不生效的
		ntStatus = LhSetExclusiveACL(HookNtCreateUserProcess_ACLEntries, 1, hHookNtCreateUserProcess);
		if (!SUCCEEDED(ntStatus))
		{
			OutputDebugString(_T("LhSetInclusiveACL failed..\n"));
			return FALSE;
		}
	}
	else
	{
		OutputDebugString(_T("Get pfnNtCreateUserProcess function address is NULL."));
	}

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

	if (NULL != hHookNtCreateUserProcess)
	{
		LhUninstallHook(hHookNtCreateUserProcess);
		delete hHookNtCreateUserProcess;
		hHookNtCreateUserProcess = NULL;
	}

	LhWaitForPendingRemovals();

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

	// 获取要 Hook 的函数原地址
	pfnNtCreateFile = (pfnNTCREATEFILE)GetProcAddress(GetModuleHandle(_T("ntdll.dll")), "NtCreateFile");
	pfnNtCreateUserProcess = (pfnNTCREATEUSERPROCESS)GetProcAddress(GetModuleHandle(_T("ntdll.dll")), "NtCreateUserProcess");

	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		StartHookThread();
	}
	break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
	{
		UnInstallHook();
	}
	break;
	}
	return TRUE;
}

