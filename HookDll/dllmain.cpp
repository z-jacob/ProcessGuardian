// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include <windows.h>
#include <string>
#include <cstdio>
#include "detours/detours.h"
#include <mutex>
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

// 全局配置：最大打印字节数（避免日志爆炸）
static const SIZE_T g_maxDumpSize = 256; // 可设为 1024、4096 等

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

	// 1. 查找主程序窗口
	HWND hWnd = FindWindowW(NULL, MAIN_WINDOW_TITLE);
	if (!hWnd) {
		// 主程序未运行，静默丢弃
		return;
	}

	// 2. 准备 COPYDATASTRUCT
	size_t len = strlen(jsonMessage) + 1; // 包含 '\0'
	if (len > 65536) return; // 防止过大（WM_COPYDATA 有大小限制）

	COPYDATASTRUCT cds = { 0 };
	cds.dwData = LOG_COPYDATA_ID;
	cds.cbData = (DWORD)len;
	cds.lpData = (void*)jsonMessage;

	// 3. 发送（同步，会等待主程序处理完）
	SendMessageW(hWnd, WM_COPYDATA, (WPARAM)nullptr, (LPARAM)&cds);
}

// 安全地将字符串追加到缓冲区（带长度检查）
void AppendString(char*& p, char* end, const char* str) {
	size_t len = strlen(str);
	if (p + len >= end) return;
	memcpy(p, str, len);
	p += len;
}

// 构建 RPM/WPM 的 JSON 日志
void BuildJsonLog(
	bool isRead,
	DWORD pid,
	LPCVOID baseAddr,
	SIZE_T requestSize,
	SIZE_T actualSize,
	BOOL success,
	DWORD error,
	const void* data,
	SIZE_T dataSize,
	char* outBuffer,
	size_t bufferSize)
{
	char* p = outBuffer;
	char* end = outBuffer + bufferSize - 1;

	AppendString(p, end, "{");

	// type
	AppendString(p, end, isRead ? "\"type\":\"READ\"" : "\"type\":\"WRITE\"");
	AppendString(p, end, ",\"pid\":");
	char temp[32];
	_snprintf_s(temp, sizeof(temp), "%u", pid);
	AppendString(p, end, temp);

	// 注意：sprintf 地址需用 %p，但要转成字符串
	char addrStr[32];
	_snprintf_s(addrStr, sizeof(addrStr), "0x%p", baseAddr);
	// 替换上面的占位符
	// 更简单：直接拼
	AppendString(p, end, ",\"address\":\"");
	AppendString(p, end, addrStr);
	AppendString(p, end, "\"");

	// sizes
	_snprintf_s(temp, sizeof(temp), ",\"request_size\":%zu", requestSize);
	AppendString(p, end, temp);
	_snprintf_s(temp, sizeof(temp), ",\"actual_size\":%zu", actualSize);
	AppendString(p, end, temp);

	// result
	AppendString(p, end, ",\"success\":");
	AppendString(p, end, success ? "true" : "false");
	if (!success) {
		_snprintf_s(temp, sizeof(temp), ",\"error\":%u", error);
		AppendString(p, end, temp);
	}

	// data (hex string, no quotes needed in hex, but wrap in "")
	if (data && dataSize > 0) {
		AppendString(p, end, ",\"data\":\"");
		// 转 hex
		const unsigned char* bytes = (const unsigned char*)data;
		for (SIZE_T i = 0; i < dataSize && p + 4 < end; ++i) {
			_snprintf_s(temp, sizeof(temp), "%02X ", bytes[i]);
			AppendString(p, end, temp);
		}
		// 去掉末尾空格
		if (p > outBuffer && *(p - 1) == ' ') {
			*(p - 1) = '"';
		}
		else {
			AppendString(p, end, "\"");
		}
	}

	AppendString(p, end, "}\n");
	*p = '\0';
}


// Hook 函数：ReadProcessMemory
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

	char jsonBuf[4096];
	// 最多 dump 64 字节（避免 JSON 过大）
	SIZE_T dumpSize = min(actualRead, (SIZE_T)64);

	BuildJsonLog(
		true, // isRead
		pid,
		lpBaseAddress,
		nSize,
		actualRead,
		result,
		error,
		result ? lpBuffer : nullptr,
		dumpSize,
		jsonBuf,
		sizeof(jsonBuf)
	);

	SendLogToGui(jsonBuf);
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
	DWORD pid = GetProcessId(hProcess);
	SIZE_T actualWritten = 0;
	BOOL result = Real_WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);

	if (result && lpNumberOfBytesWritten) {
		actualWritten = *lpNumberOfBytesWritten;
	}
	DWORD error = result ? 0 : GetLastError();

	char jsonBuf[4096];
	SIZE_T dumpSize = min(nSize, (SIZE_T)64); // 写入前数据已知

	BuildJsonLog(
		false, // isRead
		pid,
		lpBaseAddress,
		nSize,
		actualWritten,
		result,
		error,
		lpBuffer,
		dumpSize,
		jsonBuf,
		sizeof(jsonBuf)
	);

	SendLogToGui(jsonBuf);
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
}

// 👇 新增：全局标志，控制是否记录日志（可选）
static volatile bool g_bHooksEnabled = false;

// 👇 导出函数：启用 Hook（实际是重新安装）
extern "C" __declspec(dllexport) void EnableHooks()
{
	if (g_bHooksEnabled) return;
	g_bHooksEnabled = true;
	InstallHooks();
}

// 👇 导出函数：禁用 Hook（卸载）
extern "C" __declspec(dllexport) void DisableHooks()
{
	if (!g_bHooksEnabled) return;

	g_bHooksEnabled = false;
	UninstallHooks();
}


BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call) {
	case DLL_PROCESS_ATTACH:
		DisableThreadLibraryCalls(hModule);
		break;
	case DLL_PROCESS_DETACH:
		UninstallHooks();
		break;
	case DLL_THREAD_DETACH:
		break;
	}
	return TRUE;
}

