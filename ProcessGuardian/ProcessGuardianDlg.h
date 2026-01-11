
// ProcessGuardianDlg.h: 头文件
//

#pragma once


// CProcessGuardianDlg 对话框
class CProcessGuardianDlg : public CDialog
{
// 构造
public:
	CProcessGuardianDlg(CWnd* pParent = nullptr);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_PROCESSGUARDIAN_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()

protected:
	CString m_strDllPath;
	HMODULE m_hLocalDll; // 成员变量
	void PopulateProcessList();
	void ParseAndAddLogToList(const CString& jsonStr);
	void ToggleHookInProcess(DWORD pid, bool enable);
	FARPROC GetRemoteProcAddress(HMODULE hRemoteMod, const char* funcName);
public:
	afx_msg void OnBnClickedInjectBtn();
	CComboBox m_ComboProcess;
	CListCtrl m_ListLog;
	CButton m_ButtonInject;

	afx_msg void OnBnClickedRefreshProcessBtn();

	afx_msg BOOL OnCopyData(CWnd* pWnd, COPYDATASTRUCT* pCopyDataStruct);
	afx_msg void OnBnClickedHookBtn();
	afx_msg void OnBnClickedUnhookBtn();
	afx_msg void OnBnClickedListClearBtn();
};
