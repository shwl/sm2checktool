
// SM2CheckToolDlg.h : 头文件
//

#pragma once
#include "afxwin.h"
#include <string>


// CSM2CheckToolDlg 对话框
class CSM2CheckToolDlg : public CDialogEx
{
// 构造
public:
	CSM2CheckToolDlg(CWnd* pParent = NULL);	// 标准构造函数

// 对话框数据
	enum { IDD = IDD_SM2CHECKTOOL_DIALOG };

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

	void ShowMessage(CString name, LONG errorCode, CString msg = L"", int flag = 0 );
	std::string GetEditString(const CEdit& et, bool isHex, const std::string& logName);
	void SetEditString(CEdit& et, const std::string& text, const std::string& logName);
	LONG GetSymMod();
public:
	afx_msg void OnBnClickedButtonGenKey();
	afx_msg void OnBnClickedButtonSign();
	afx_msg void OnBnClickedButtonVerify();
	afx_msg void OnBnClickedButtonSm3();
	CEdit m_PubKeyXEdit;
	CEdit m_PubKeyYEdit;
	CEdit m_PriKeyEdit;
	CEdit m_SrcEdit;
	CEdit m_SM3ResEdit;
	CEdit m_SM3ZResEdit;
	CEdit m_SignResR;
	CEdit m_SignResS;
	CEdit m_VerifyRes;
	CEdit m_UserIDEdit;
	CEdit m_ResultEdit;
	afx_msg void OnBnClickedButtonSm4Encrypt();
	afx_msg void OnBnClickedButtonSm4Decrypt();
	CEdit m_SymKeyEdit;
	CEdit m_SymIVEdit;
	CEdit m_EncryptResEdit;
	CEdit m_DecryptResEdit;
	CComboBox m_CryptModCob;
};
