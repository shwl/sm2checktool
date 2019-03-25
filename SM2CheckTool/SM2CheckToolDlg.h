
// SM2CheckToolDlg.h : ͷ�ļ�
//

#pragma once
#include "afxwin.h"
#include <string>


// CSM2CheckToolDlg �Ի���
class CSM2CheckToolDlg : public CDialogEx
{
// ����
public:
	CSM2CheckToolDlg(CWnd* pParent = NULL);	// ��׼���캯��

// �Ի�������
	enum { IDD = IDD_SM2CHECKTOOL_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV ֧��


// ʵ��
protected:
	HICON m_hIcon;

	// ���ɵ���Ϣӳ�亯��
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
