
// ProcessGuardianDlg.cpp: 实现文件
//

#include "pch.h"
#include "framework.h"
#include "ProcessGuardian.h"
#include "ProcessGuardianDlg.h"
#include "afxdialogex.h"
#include <TlHelp32.h>
#include <cstring>

#ifdef _DEBUG
#define new DEBUG_NEW
#endif
#include <string>
#include "JSON/CJsonObject.hpp"

// ProcessGuardianDlg.h

#define MAIN_WINDOW_TITLE _T("ProcessGuardian_Window_Unique_2026")

#define LOG_COPYDATA_ID 0x1234

#define HOOK_DLL_NAME L"HookDll.dll"

// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialog
{
public:
	CAboutDlg();

	// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

	// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialog(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialog)
END_MESSAGE_MAP()


// CProcessGuardianDlg 对话框



CProcessGuardianDlg::CProcessGuardianDlg(CWnd* pParent /*=nullptr*/)
	: CDialog(IDD_PROCESSGUARDIAN_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CProcessGuardianDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_PROC_COMBO, m_ComboProcess);
	DDX_Control(pDX, IDC_LIST_LOG, m_ListLog);
	DDX_Control(pDX, IDC_INJECT_BTN, m_ButtonInject);
	DDX_Control(pDX, IDC_EDIT_LOG, m_EditLog);
}

BEGIN_MESSAGE_MAP(CProcessGuardianDlg, CDialog)
	ON_WM_COPYDATA()
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_INJECT_BTN, &CProcessGuardianDlg::OnBnClickedInjectBtn)
	ON_BN_CLICKED(IDC_REFRESH_PROCESS_BTN, &CProcessGuardianDlg::OnBnClickedRefreshProcessBtn)
	ON_BN_CLICKED(IDC_HOOK_BTN, &CProcessGuardianDlg::OnBnClickedHookBtn)
	ON_BN_CLICKED(IDC_UNHOOK_BTN, &CProcessGuardianDlg::OnBnClickedUnhookBtn)
END_MESSAGE_MAP()


// CProcessGuardianDlg 消息处理程序

BOOL CProcessGuardianDlg::OnInitDialog()
{
	CDialog::OnInitDialog();


	// 立即设置唯一窗口标题（必须在 FindWindow 前）
	SetWindowText(MAIN_WINDOW_TITLE); // 定义为宏或常量


	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码



	m_ListLog.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

	// 插入列（新增“序号”列）
	m_ListLog.InsertColumn(0, _T("序号"), LVCFMT_RIGHT, 80);   // 新增
	m_ListLog.InsertColumn(1, _T("类型"), LVCFMT_LEFT, 80);
	m_ListLog.InsertColumn(2, _T("PID"), LVCFMT_RIGHT, 80);
	m_ListLog.InsertColumn(3, _T("地址"), LVCFMT_LEFT, 180);
	m_ListLog.InsertColumn(4, _T("请求大小"), LVCFMT_RIGHT, 120);
	m_ListLog.InsertColumn(5, _T("实际大小"), LVCFMT_RIGHT, 120);
	m_ListLog.InsertColumn(6, _T("状态"), LVCFMT_LEFT, 80);
	m_ListLog.InsertColumn(7, _T("数据 (Hex)"), LVCFMT_LEFT, 500);


	// 获取 DLL 路径（假设 hook.dll 在 exe 同目录）
	TCHAR szPath[MAX_PATH];
	GetModuleFileName(NULL, szPath, MAX_PATH);
	PathRemoveFileSpec(szPath);
	PathAppend(szPath, HOOK_DLL_NAME);
	m_strDllPath = szPath;

	m_hLocalDll = LoadLibrary(szPath);
	if (!m_hLocalDll) {
		AfxMessageBox(_T("无法加载 HookDll.dll！请确保它在程序目录下。"));
		// 可选：ExitProcess(1);
	}

	// 填充进程列表
	PopulateProcessList();


	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CProcessGuardianDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialog::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CProcessGuardianDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialog::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CProcessGuardianDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

void CProcessGuardianDlg::PopulateProcessList()
{
	m_ComboProcess.ResetContent();

	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 pe = { sizeof(pe) };
	if (Process32First(hSnap, &pe)) {
		do {
			int idx = m_ComboProcess.AddString(pe.szExeFile);
			m_ComboProcess.SetItemData(idx, pe.th32ProcessID);
		} while (Process32Next(hSnap, &pe));
	}
	CloseHandle(hSnap);
}

void CProcessGuardianDlg::ParseAndAddLogToList(const CString& jsonStr)
{
	try {
		std::string utf8 = CT2A(jsonStr, CP_UTF8);
		neb::CJsonObject json;

		if (!json.Parse(utf8))	return;


		//{"type":"READ","pid":27004,"address":"0x004A18CC","request_size":4,"actual_size":4,"success":true,"data":"F0 5D 14 96"}
		
		std::string type;
		json.Get("type", type);

		int pid;
		json.Get("pid", pid);


		std::string address;
		json.Get("address", address);

		int request_size;
		json.Get("request_size", request_size);

		int actual_size;
		json.Get("actual_size", actual_size);

		bool success;
		json.Get("success", success);


		std::string data;
		json.Get("data", data);

	
		auto status = success ? _T("成功") : _T("失败");
		int idx = m_ListLog.GetItemCount();

		// 设置第 0 列：序号
		m_ListLog.InsertItem(idx, CString(std::to_string(idx).c_str()));
		m_ListLog.SetItemText(idx, 1, CString(type.c_str()));
		m_ListLog.SetItemText(idx, 2, CString(std::to_string(pid).c_str()));
		m_ListLog.SetItemText(idx, 3, CString(address.c_str()));
		m_ListLog.SetItemText(idx, 4, CString(std::to_string(request_size).c_str()));
		m_ListLog.SetItemText(idx, 5, CString(std::to_string(actual_size).c_str()));
		m_ListLog.SetItemText(idx, 6, status);
		m_ListLog.SetItemText(idx, 7, CString(data.c_str()));
		//m_ListLog.EnsureVisible(idx, FALSE);
	}
	catch (const std::exception& e) {
		OutputDebugStringA(("JSON parse error: " + std::string(e.what()) + "\n").c_str());
	}
}

// GetRemoteModuleHandle - 获取远程进程中指定模块的基址（HMODULE）
// 参数：
//   dwProcessId: 目标进程 PID
//   szModuleName: 要查找的模块名（如 L"kernel32.dll" 或 L"MyHook.dll"）
// 返回值：
//   成功：模块基址（HMODULE）
//   失败：nullptr
HMODULE GetRemoteModuleHandle(DWORD dwProcessId, const wchar_t* szModuleName)
{
	if (!szModuleName) return nullptr;

	HMODULE hModule = nullptr;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, dwProcessId);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		return nullptr;
	}

	MODULEENTRY32W me = { 0 };
	me.dwSize = sizeof(me);

	if (Module32FirstW(hSnapshot, &me)) {
		do {
			// 比较模块名（不区分大小写）
			if (_wcsicmp(me.szModule, szModuleName) == 0) {
				hModule = me.hModule;
				break;
			}
		} while (Module32NextW(hSnapshot, &me));
	}

	CloseHandle(hSnapshot);
	return hModule;
}


void CProcessGuardianDlg::ToggleHookInProcess(DWORD pid, bool enable)
{
	HANDLE hProcess = OpenProcess(
		PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION,
		FALSE, pid
	);
	if (!hProcess) {
		AfxMessageBox(_T("无法打开目标进程！"));
		return;
	}

	// 获取远程 DLL 模块句柄
	HMODULE hRemoteDll = GetRemoteModuleHandle(pid, HOOK_DLL_NAME);
	if (!hRemoteDll) {
		AfxMessageBox(_T("目标进程未加载 MyHook.dll！请先注入。"));
		CloseHandle(hProcess);
		return;
	}

	// 获取远程函数地址
	const char* funcName = enable ? "EnableHooks" : "DisableHooks";
	FARPROC pFunc = GetRemoteProcAddress(hRemoteDll, funcName);
	if (!pFunc) {
		AfxMessageBox(_T("找不到导出函数！"));
		CloseHandle(hProcess);
		return;
	}

	// 创建远程线程调用
	HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0,
		(LPTHREAD_START_ROUTINE)pFunc, nullptr, 0, nullptr);

	if (hThread) {
		WaitForSingleObject(hThread, 2000); // 等待最多2秒
		CloseHandle(hThread);
	}

	CloseHandle(hProcess);
	AfxMessageBox(enable ? _T("Hook成功！") : _T("UnHook成功！"));
}

FARPROC CProcessGuardianDlg::GetRemoteProcAddress(HMODULE hRemoteMod, const char* funcName)
{
	if (!m_hLocalDll) {
		return nullptr; // 主程序未加载本地 DLL
	}

	// ✅ 使用 m_hLocalDll，而不是 GetModuleHandle!
	FARPROC pLocalFunc = GetProcAddress(m_hLocalDll, funcName);
	if (!pLocalFunc) {
		return nullptr; // 函数名拼写错误或未导出
	}

	// 计算 RVA（相对虚拟地址）
	ptrdiff_t rva = (BYTE*)pLocalFunc - (BYTE*)m_hLocalDll;

	// 远程地址 = 远程基址 + RVA
	return (FARPROC)((BYTE*)hRemoteMod + rva);
}

bool InjectDLL(DWORD pid, const CString& dllPath) {
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (!hProcess) return false;

	void* pRemote = VirtualAllocEx(hProcess, NULL, (dllPath.GetLength() + 1) * sizeof(TCHAR),
		MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	WriteProcessMemory(hProcess, pRemote, (LPCTSTR)dllPath, (dllPath.GetLength() + 1) * sizeof(TCHAR), NULL);

	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
		(LPTHREAD_START_ROUTINE)(GetProcAddress(GetModuleHandle(_T("kernel32.dll")), "LoadLibraryW")),
		pRemote, 0, NULL);

	if (hThread) {
		WaitForSingleObject(hThread, INFINITE);
		CloseHandle(hThread);
	}

	VirtualFreeEx(hProcess, pRemote, 0, MEM_RELEASE);
	CloseHandle(hProcess);
	return true;
}

void CProcessGuardianDlg::OnBnClickedInjectBtn()
{
	int idx = m_ComboProcess.GetCurSel();
	if (idx == CB_ERR) return;

	auto pid = m_ComboProcess.GetItemData(idx);

	InjectDLL(pid, m_strDllPath);
}

void CProcessGuardianDlg::OnBnClickedRefreshProcessBtn()
{
	// 填充进程列表
	PopulateProcessList();
}

BOOL CProcessGuardianDlg::OnCopyData(CWnd* pWnd, COPYDATASTRUCT* pCopyDataStruct)
{
	if (!pCopyDataStruct) return FALSE;

	// 我们约定：dwData = 0x1234 表示日志消息
	if (pCopyDataStruct->dwData == LOG_COPYDATA_ID && pCopyDataStruct->cbData > 0) {
		// 数据是 UTF-8 JSON 字符串（推荐）
		const char* pszJson = (const char*)pCopyDataStruct->lpData;
		if (pszJson) {
			// 转为 CString（自动处理 ANSI/Unicode）
			CString strJson = CA2T(pszJson, CP_UTF8);
			ParseAndAddLogToList(strJson); // 复用你已有的解析函数
		}
	}
	return TRUE; // 表示已处理
}

void CProcessGuardianDlg::OnBnClickedHookBtn()
{
	int idx = m_ComboProcess.GetCurSel();
	if (idx == CB_ERR) return;

	auto pid = m_ComboProcess.GetItemData(idx);

	ToggleHookInProcess(pid,true);
}

void CProcessGuardianDlg::OnBnClickedUnhookBtn()
{
	int idx = m_ComboProcess.GetCurSel();
	if (idx == CB_ERR) return;

	auto pid = m_ComboProcess.GetItemData(idx);

	ToggleHookInProcess(pid, false);
}
