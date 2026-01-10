
// ProcessGuardianDlg.cpp: 实现文件
//

#include "pch.h"
#include "framework.h"
#include "ProcessGuardian.h"
#include "ProcessGuardianDlg.h"
#include "afxdialogex.h"
#include <TlHelp32.h>

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


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
	DDX_Control(pDX, IDC_LOG_EDIT, m_EditLog);
}

BEGIN_MESSAGE_MAP(CProcessGuardianDlg, CDialog)
	ON_MESSAGE(WM_USER + 1, &OnLogMessage)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_INJECT_BTN, &CProcessGuardianDlg::OnBnClickedInjectBtn)
END_MESSAGE_MAP()


// CProcessGuardianDlg 消息处理程序

BOOL CProcessGuardianDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

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


	// 获取 DLL 路径（假设 hook.dll 在 exe 同目录）
	TCHAR szPath[MAX_PATH];
	GetModuleFileName(NULL, szPath, MAX_PATH);
	PathRemoveFileSpec(szPath);
	PathAppend(szPath, _T("HookDll.dll"));
	m_strDllPath = szPath;

	// 启动日志监听线程
	m_hStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	m_pLogThread = AfxBeginThread(LogListenerProc, this);

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

LRESULT CProcessGuardianDlg::OnLogMessage(WPARAM wParam, LPARAM lParam)
{
	CString* pStr = (CString*)lParam;
	m_EditLog.ReplaceSel(*pStr + "\r\n");
	m_EditLog.LineScroll(m_EditLog.GetLineCount());
	delete pStr; // 注意：我们在 PostMessage 时 new 了字符串
	return 0;
}

UINT CProcessGuardianDlg::LogListenerProc(LPVOID pParam)
{
	CProcessGuardianDlg* pThis = (CProcessGuardianDlg*)pParam;

	while (WaitForSingleObject(pThis->m_hStopEvent, 0) != WAIT_OBJECT_0) {
		HANDLE hPipe = CreateNamedPipe(
			_T("\\\\.\\pipe\\RWMHookPipe"),
			PIPE_ACCESS_INBOUND,
			PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
			1, 1024, 1024, 0, NULL
		);

		if (hPipe == INVALID_HANDLE_VALUE) {
			Sleep(500);
			continue;
		}

		// 等待客户端连接
		if (!ConnectNamedPipe(hPipe, NULL)) {
			if (GetLastError() != ERROR_PIPE_CONNECTED) {
				CloseHandle(hPipe);
				Sleep(500);
				continue;
			}
		}

		// 客户端已连接，持续读取直到断开
		char buffer[1024];
		DWORD bytesRead;
		while (ReadFile(hPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL)) {
			if (bytesRead == 0) break; // 客户端正常关闭

			buffer[bytesRead] = '\0';
			CStringA msgA(buffer);
			CString* pMsg = new CString(msgA);
			pThis->PostMessage(WM_USER + 1, 0, (LPARAM)pMsg);
		}

		// 客户端断开（可能因进程退出、DLL 卸载等）
		CloseHandle(hPipe);
		// 自动进入下一轮循环，等待新连接
	}

	return 0;
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
