
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
	CWinThread* m_pLogThread;
	HANDLE m_hStopEvent;
	CString m_strDllPath;
	void PopulateProcessList();
	LRESULT OnLogMessage(WPARAM wParam, LPARAM lParam);
public:
	static UINT LogListenerProc(LPVOID pParam);
	afx_msg void OnBnClickedInjectBtn();
	CComboBox m_ComboProcess;
	CEdit m_EditLog;
};
