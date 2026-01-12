// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include <windows.h>
#include <string>
#include <cstdio>
#include <atomic>
#include "detours/detours.h"
#include "JSON/CJsonObject.hpp"

#pragma comment(lib, "detours//detours_x86.lib")


#define MAIN_WINDOW_TITLE L"ProcessGuardian_Window_Unique_2026"

#define LOG_COPYDATA_ID 0x1234

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

// 原子标志：是否启用 Hook
static std::atomic<bool> g_bHooksEnabled{ false };

std::string PtrToString(LPCVOID ptr) {
	char buf[32] = { 0 };
#ifdef _WIN64
	_snprintf_s(buf, sizeof(buf), "0x%016llX", (unsigned long long)ptr);
#else
	_snprintf_s(buf, sizeof(buf), "0x%08X", (unsigned int)(uintptr_t)ptr);
#endif
	return std::string(buf);
}

// 将字节转为十六进制字符串，支持大块数据（带换行和截断）
void BytesToHexFull(const void* data, size_t len, char* out, size_t outSize) {
	if (!data || len == 0 || outSize < 1) {
		*out = '\0';
		return;
	}

	const unsigned char* bytes = (const unsigned char*)data;
	char* p = out;
	char* end = out + outSize - 1; // 留1字节给'\0'

	for (size_t i = 0; i < len && p < end; ++i) {
		int written = sprintf_s(p, end - p, "%02X ", bytes[i]);
		if (written <= 0) break;
		p += written;
	}

	if (p > out) {
		// 去掉最后一个空格
		*(p - 1) = '\0';
	}
	else {
		*out = '\0';
	}
}


void SendLogToGui(const char* jsonMessage) {
	if (!jsonMessage) return;

	HWND hWnd = FindWindowW(NULL, MAIN_WINDOW_TITLE);
	if (!hWnd) return;

	size_t len = strlen(jsonMessage) + 1;
	if (len > 65535) return; // WM_COPYDATA 最大 64KB - 1

	COPYDATASTRUCT cds = { 0 };
	cds.dwData = LOG_COPYDATA_ID;
	cds.cbData = static_cast<DWORD>(len);
	cds.lpData = const_cast<char*>(jsonMessage); // 安全：SendMessageW 是同步的

	SendMessageW(hWnd, WM_COPYDATA, 0, reinterpret_cast<LPARAM>(&cds));
}

// 构建 RPM/WPM 的 JSON 日志
std::string BuildJsonLog(
	bool isRead,
	DWORD pid,
	LPCVOID baseAddr,
	SIZE_T requestSize,
	SIZE_T actualSize,
	BOOL success,
	DWORD error,
	const void* data,
	SIZE_T dataSize)
{
	neb::CJsonObject json;
	json.Add("type", isRead ? "ReadProcessMemory" : "WriteProcessMemory");
	json.Add("pid", (int)pid);
	json.Add("address", PtrToString(baseAddr));
	json.Add("request_size", (int)requestSize);
	json.Add("actual_size", (int)actualSize);
	json.Add("success", success != FALSE);

	if (!success) {
		json.Add("error_code", (int)error);
	}

	// 限制 data dump 大小
	if (data && dataSize > 0) {
		SIZE_T dumpSize = dataSize;
		std::string hexStr;
		hexStr.reserve(dumpSize * 3);

		const unsigned char* bytes = static_cast<const unsigned char*>(data);
		for (SIZE_T i = 0; i < dumpSize; ++i) {
			char byteStr[4];
			_snprintf_s(byteStr, sizeof(byteStr), "%02X ", bytes[i]);
			hexStr += byteStr;
		}
		if (!hexStr.empty()) {
			hexStr.pop_back(); // 移除末尾空格
		}
		json.Add("data", hexStr);

		if (dumpSize < dataSize) {
			json.Add("data_truncated", true);
		}
	}

	return json.ToString();
}



// Hook: ReadProcessMemory
BOOL WINAPI Mine_ReadProcessMemory(
	HANDLE hProcess,
	LPCVOID lpBaseAddress,
	LPVOID lpBuffer,
	SIZE_T nSize,
	SIZE_T* lpNumberOfBytesRead)
{
	DWORD pid = GetProcessId(hProcess);
	BOOL result = Real_ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
	SIZE_T actualRead = lpNumberOfBytesRead ? *lpNumberOfBytesRead : (result ? nSize : 0);
	DWORD error = result ? 0 : GetLastError();

	auto jsonBuf = BuildJsonLog(
		true,
		pid,
		lpBaseAddress,
		nSize,
		actualRead,
		result,
		error,
		result ? lpBuffer : nullptr,
		actualRead
	);

	SendLogToGui(jsonBuf.c_str());
	return result;
}

// Hook: WriteProcessMemory
BOOL WINAPI Mine_WriteProcessMemory(
	HANDLE hProcess,
	LPVOID lpBaseAddress,
	LPCVOID lpBuffer,
	SIZE_T nSize,
	SIZE_T* lpNumberOfBytesWritten)
{
	DWORD pid = GetProcessId(hProcess);
	BOOL result = Real_WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
	SIZE_T actualWritten = lpNumberOfBytesWritten ? *lpNumberOfBytesWritten : (result ? nSize : 0);
	DWORD error = result ? 0 : GetLastError();

	auto jsonBuf = BuildJsonLog(
		false,
		pid,
		lpBaseAddress,
		nSize,
		actualWritten,
		result,
		error,
		lpBuffer,
		nSize
	);

	SendLogToGui(jsonBuf.c_str());
	return result;
}

void InstallHooks() {
	if (DetourTransactionBegin() != NO_ERROR) return;
	DetourUpdateThread(GetCurrentThread());
	DetourAttach(&(PVOID&)Real_ReadProcessMemory, Mine_ReadProcessMemory);
	DetourAttach(&(PVOID&)Real_WriteProcessMemory, Mine_WriteProcessMemory);
	DetourTransactionCommit();
}

void UninstallHooks() {
	if (DetourTransactionBegin() != NO_ERROR) return;
	DetourUpdateThread(GetCurrentThread());
	DetourDetach(&(PVOID&)Real_ReadProcessMemory, Mine_ReadProcessMemory);
	DetourDetach(&(PVOID&)Real_WriteProcessMemory, Mine_WriteProcessMemory);
	DetourTransactionCommit();
}

extern "C" __declspec(dllexport) void EnableHooks() {
	if (g_bHooksEnabled.exchange(true)) return; // 已启用
	InstallHooks();
}

extern "C" __declspec(dllexport) void DisableHooks() {
	if (!g_bHooksEnabled.exchange(false)) return; // 未启用
	UninstallHooks();
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
	switch (ul_reason_for_call) {
	case DLL_PROCESS_ATTACH:
		DisableThreadLibraryCalls(hModule);
		break;
	case DLL_PROCESS_DETACH:
		// 即使未启用，也尝试卸载（防御性）
		if (g_bHooksEnabled.load()) {
			UninstallHooks();
		}
		break;
	}
	return TRUE;
}