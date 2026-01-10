// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include <windows.h>
#include <string>
#include <cstdio>
#include "detours/detours.h"
#pragma comment(lib, "detours//detours_x86.lib")
// 原函数指针
static BOOL(WINAPI* Real_ReadProcessMemory)(
	HANDLE hProcess,
	LPCVOID lpBaseAddress,
	LPVOID lpBuffer,
	SIZE_T nSize,
	SIZE_T* lpNumberOfBytesRead) = ReadProcessMemory;

static BOOL(WINAPI* Real_WriteProcessMemory)(
	HANDLE hProcess,
	LPVOID lpBaseAddress,
	LPCVOID lpBuffer,
	SIZE_T nSize,
	SIZE_T* lpNumberOfBytesWritten) = WriteProcessMemory;

// 命名管道句柄（每个线程独立，避免竞争）
static thread_local HANDLE g_hPipe = INVALID_HANDLE_VALUE;

// 发送日志到主程序
void SendLogToGui(const char* log) {
	if (g_hPipe == INVALID_HANDLE_VALUE) {
		// 尝试连接命名管道（首次调用时）
		g_hPipe = CreateFileA(
			"\\\\.\\pipe\\RWMHookPipe",   // 管道名
			GENERIC_WRITE,
			0, nullptr,
			OPEN_EXISTING,
			0, nullptr
		);
		if (g_hPipe == INVALID_HANDLE_VALUE) {
			return; // 主程序未运行，忽略
		}
	}

	DWORD written;
	WriteFile(g_hPipe, log, (DWORD)strlen(log), &written, nullptr);
}


// Hook 函数：ReadProcessMemory
BOOL WINAPI Mine_ReadProcessMemory(
	HANDLE hProcess,
	LPCVOID lpBaseAddress,
	LPVOID lpBuffer,
	SIZE_T nSize,
	SIZE_T* lpNumberOfBytesRead)
{
	char buffer[512];
	DWORD pid = GetProcessId(hProcess);
	snprintf(buffer, sizeof(buffer),
		"[READ] PID=%u | Base=0x%p | Buf=0x%p | Size=0x%zX (%zu)\n",
		pid, lpBaseAddress, lpBuffer, nSize, nSize);

	SendLogToGui(buffer);

	// 调用原始函数
	BOOL result = Real_ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);

	if (!result) {
		snprintf(buffer, sizeof(buffer), "  -> FAILED! Error=%u\n", GetLastError());
		SendLogToGui(buffer);
	}
	else if (lpNumberOfBytesRead) {
		snprintf(buffer, sizeof(buffer), "  -> OK, read %zu bytes\n", *lpNumberOfBytesRead);
		SendLogToGui(buffer);
	}

	return result;
}

// Hook 函数：WriteProcessMemory
BOOL WINAPI Mine_WriteProcessMemory(
	HANDLE hProcess,
	LPVOID lpBaseAddress,
	LPCVOID lpBuffer,
	SIZE_T nSize,
	SIZE_T* lpNumberOfBytesWritten)
{
	char buffer[512];
	DWORD pid = GetProcessId(hProcess);
	snprintf(buffer, sizeof(buffer),
		"[WRITE] PID=%u | Base=0x%p | Buf=0x%p | Size=0x%zX (%zu)\n",
		pid, lpBaseAddress, lpBuffer, nSize, nSize);

	SendLogToGui(buffer);

	BOOL result = Real_WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);

	if (!result) {
		snprintf(buffer, sizeof(buffer), "  -> FAILED! Error=%u\n", GetLastError());
		SendLogToGui(buffer);
	}
	else if (lpNumberOfBytesWritten) {
		snprintf(buffer, sizeof(buffer), "  -> OK, wrote %zu bytes\n", *lpNumberOfBytesWritten);
		SendLogToGui(buffer);
	}

	return result;
}

// 安装 Hook
void InstallHooks() {

	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach(&(PVOID&)Real_ReadProcessMemory, Mine_ReadProcessMemory);
	DetourAttach(&(PVOID&)Real_WriteProcessMemory, Mine_WriteProcessMemory);
	DetourTransactionCommit();
}

// 卸载 Hook
void UninstallHooks() {
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourDetach(&(PVOID&)Real_ReadProcessMemory, Mine_ReadProcessMemory);
	DetourDetach(&(PVOID&)Real_WriteProcessMemory, Mine_WriteProcessMemory);
	DetourTransactionCommit();


	if (g_hPipe != INVALID_HANDLE_VALUE) {
		CloseHandle(g_hPipe);
		g_hPipe = INVALID_HANDLE_VALUE;
	}
}


BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		DisableThreadLibraryCalls(hModule);
		InstallHooks();
		break;
	case DLL_PROCESS_DETACH:
		UninstallHooks();
		break;
	}
	return TRUE;
}

