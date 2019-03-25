
// SM2CheckToolDlg.cpp : ʵ���ļ�
//

#include "stdafx.h"
#include <string>
#include "SM2CheckTool.h"
#include "SM2CheckToolDlg.h"
#include "afxdialogex.h"
#include "TG_SM2Api.h"
#pragma comment(lib, "TG_SM2Api.lib");

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

using namespace std;

#define SM2_KEY_LEN		32
#define KEY_OFF_SET		(ECC_MAX_MODULUS_BITS_LEN / 8 - SM2_KEY_LEN)

std::string ESP_CharToHex(const BYTE* data, int len)
{
	std::string hexStr;
	char szbuf[4] = { 0 };
	for (unsigned int i = 0; i < len; ++i)
	{
		sprintf_s(szbuf, 4, "%02x", (unsigned char)data[i]);
		hexStr.append(szbuf, 2);
	}

	return hexStr;
}

std::string ESP_CharToHex(const std::string& str)
{
	return ESP_CharToHex((const BYTE*)str.c_str(), str.length());
}

std::string ESP_HexToChar(const std::string& str)
{
	std::string retStr;
	int n = 0;
	int m = 0;
	for (unsigned int i = 0; i < str.length(); i++)
	{
		if (str[i] >= 'A' && str[i] <= 'F') {
			m = str[i] - 'A' + 10;
		}
		else if (str[i] >= 'a' && str[i] <= 'f') {
			m = str[i] - 'a' + 10;
		}
		else {
			m = str[i] - '0';
		}

		if (i % 2 == 0) {
			n = m * 16;
		}
		else {
			n += m;
			retStr.append(1, (char)n);
		}
	}

	return retStr;
}

void StrToPubKey(const std::string& strX, const std::string& strY,
	ECCPUBLICKEYBLOB& ecc_pub_st)
{
	memcpy(ecc_pub_st.XCoordinate + KEY_OFF_SET, strX.c_str(), SM2_KEY_LEN);
	memcpy(ecc_pub_st.YCoordinate + KEY_OFF_SET, strY.c_str(), SM2_KEY_LEN);
	ecc_pub_st.BitLen = ECC_MAX_MODULUS_BITS_LEN / 2;
}

void StrToPriKey(const std::string& strPriKey, ECCPRIVATEKEYBLOB &eccPriKeyBlob)
{
	memcpy(eccPriKeyBlob.PrivateKey + KEY_OFF_SET, strPriKey.c_str(), SM2_KEY_LEN);
	eccPriKeyBlob.BitLen = ECC_MAX_MODULUS_BITS_LEN / 2;
}

void StrToSignarure(const std::string& strR, const std::string& strS, ECCSIGNATUREBLOB& signature)
{
	memcpy(signature.r + KEY_OFF_SET, strR.c_str(), SM2_KEY_LEN);
	memcpy(signature.s + KEY_OFF_SET, strS.c_str(), SM2_KEY_LEN);
}

// ����Ӧ�ó��򡰹��ڡ��˵���� CAboutDlg �Ի���

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// �Ի�������
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

// ʵ��
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CSM2CheckToolDlg �Ի���



CSM2CheckToolDlg::CSM2CheckToolDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(CSM2CheckToolDlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CSM2CheckToolDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_EDIT_PUBKEY_X, m_PubKeyXEdit);
	DDX_Control(pDX, IDC_EDIT_PUBKEY_Y, m_PubKeyYEdit);
	DDX_Control(pDX, IDC_EDIT_PRIKEY, m_PriKeyEdit);
	DDX_Control(pDX, IDC_EDIT_SRC, m_SrcEdit);
	DDX_Control(pDX, IDC_EDIT_SM3, m_SM3ResEdit);
	DDX_Control(pDX, IDC_EDIT_SM3_Z, m_SM3ZResEdit);
	DDX_Control(pDX, IDC_EDIT_SIGNRES_R, m_SignResR);
	DDX_Control(pDX, IDC_EDIT_SIGNRES_S, m_SignResS);
	DDX_Control(pDX, IDC_EDIT_VERIFYRES, m_VerifyRes);
	DDX_Control(pDX, IDC_EDIT_USER_ID, m_UserIDEdit);
	DDX_Control(pDX, IDC_EDIT_RESULT, m_ResultEdit);
}

BEGIN_MESSAGE_MAP(CSM2CheckToolDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON_GEN_KEY, &CSM2CheckToolDlg::OnBnClickedButtonGenKey)
	ON_BN_CLICKED(IDC_BUTTON_SIGN, &CSM2CheckToolDlg::OnBnClickedButtonSign)
	ON_BN_CLICKED(IDC_BUTTON_VERIFY, &CSM2CheckToolDlg::OnBnClickedButtonVerify)
	ON_BN_CLICKED(IDC_BUTTON_SM3, &CSM2CheckToolDlg::OnBnClickedButtonSm3)
END_MESSAGE_MAP()


// CSM2CheckToolDlg ��Ϣ�������

BOOL CSM2CheckToolDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// ��������...���˵�����ӵ�ϵͳ�˵��С�

	// IDM_ABOUTBOX ������ϵͳ���Χ�ڡ�
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
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

	// ���ô˶Ի����ͼ�ꡣ  ��Ӧ�ó��������ڲ��ǶԻ���ʱ����ܽ��Զ�
	//  ִ�д˲���
	SetIcon(m_hIcon, TRUE);			// ���ô�ͼ��
	SetIcon(m_hIcon, FALSE);		// ����Сͼ��

	// TODO:  �ڴ���Ӷ���ĳ�ʼ������;
	m_SrcEdit.SetWindowTextW(L"1234567812345678");
	m_UserIDEdit.SetWindowTextW(L"1234567812345678");
	
	return TRUE;  // ���ǽ��������õ��ؼ������򷵻� TRUE
}

void CSM2CheckToolDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// �����Ի��������С����ť������Ҫ����Ĵ���
//  �����Ƹ�ͼ�ꡣ  ����ʹ���ĵ�/��ͼģ�͵� MFC Ӧ�ó���
//  �⽫�ɿ���Զ���ɡ�

void CSM2CheckToolDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // ���ڻ��Ƶ��豸������

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// ʹͼ���ڹ����������о���
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// ����ͼ��
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//���û��϶���С������ʱϵͳ���ô˺���ȡ�ù��
//��ʾ��
HCURSOR CSM2CheckToolDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


void CSM2CheckToolDlg::OnBnClickedButtonGenKey()
{
	// TODO:  �ڴ���ӿؼ�֪ͨ����������;
	ECCPRIVATEKEYBLOB priKey = {};
	ECCPUBLICKEYBLOB pubKey = {};
	ULONG ulRes = TG_GenECCKeyPair(0, &priKey, &pubKey);
	if (0 == ulRes)
	{
		string strTmp = ESP_CharToHex(priKey.PrivateKey + KEY_OFF_SET, SM2_KEY_LEN);
		m_PriKeyEdit.SetWindowTextW(CString(strTmp.c_str()));

		strTmp = ESP_CharToHex(pubKey.XCoordinate + KEY_OFF_SET, SM2_KEY_LEN);
		m_PubKeyXEdit.SetWindowTextW(CString(strTmp.c_str()));

		strTmp = ESP_CharToHex(pubKey.YCoordinate + KEY_OFF_SET, SM2_KEY_LEN);
		m_PubKeyYEdit.SetWindowTextW(CString(strTmp.c_str()));
	}
	ShowMessage(L"TG_GenECCKeyPair", ulRes);
}

void CSM2CheckToolDlg::OnBnClickedButtonSign()
{
	// TODO:  �ڴ���ӿؼ�֪ͨ����������;
	string strDigest = GetEditString(m_SM3ZResEdit, true);
	if (0 == strDigest.length()){
		OnBnClickedButtonSm3();
	}
	strDigest = GetEditString(m_SM3ZResEdit, true);
	if (0 < strDigest.length())
	{
		ECCPRIVATEKEYBLOB eccPriKeyBlob = {};
		ECCSIGNATUREBLOB signature = {};
		string strPriKey = GetEditString(m_PriKeyEdit, true);
		StrToPriKey(strPriKey, eccPriKeyBlob);
		ULONG ulRes = TG_ECCSign(&eccPriKeyBlob, (BYTE*)strDigest.c_str(), strDigest.length(), &signature);
		ShowMessage(L"TG_ECCSign", ulRes);
		if (0 == ulRes)
		{
			string strTmp = ESP_CharToHex(signature.r + KEY_OFF_SET, SM2_KEY_LEN);
			m_SignResR.SetWindowTextW(CString(strTmp.c_str()));

			strTmp = ESP_CharToHex(signature.s + KEY_OFF_SET, SM2_KEY_LEN);
			m_SignResS.SetWindowTextW(CString(strTmp.c_str()));
		}
	}
	else{
		ShowMessage(L"Digest is empty", -1);
	}
}

void CSM2CheckToolDlg::OnBnClickedButtonVerify()
{
	// TODO:  �ڴ���ӿؼ�֪ͨ����������;
	string strDigest = GetEditString(m_SM3ZResEdit, true);
	if (0 == strDigest.length()){
		OnBnClickedButtonSm3();
	}
	strDigest = GetEditString(m_SM3ZResEdit, true);
	if (0 < strDigest.length())
	{
		ECCPUBLICKEYBLOB pubKey = {};
		ECCSIGNATUREBLOB signature = {};
		string strX = GetEditString(m_PubKeyXEdit, true);
		string strY = GetEditString(m_PubKeyYEdit, true);
		StrToPubKey(strX, strY, pubKey);
		string strR = GetEditString(m_SignResR, true);
		string strS = GetEditString(m_SignResS, true);
		StrToSignarure(strR, strS, signature);
		ULONG ulRes = TG_ECCVerify(&pubKey, (BYTE*)strDigest.c_str(), strDigest.length(), &signature);
		CString res;
		res.Format(L"%d", ulRes);
		m_VerifyRes.SetWindowTextW(res);
		ShowMessage(L"TG_ECCVerify", ulRes);
	}
	else{
		ShowMessage(L"Digest is empty", -1);
	}
}

void CSM2CheckToolDlg::OnBnClickedButtonSm3()
{
	//TODO:  �ڴ���ӿؼ�֪ͨ����������;
	BOOL isHasZ = FALSE;
	for (int i = 0; i < 2; ++i)
	{
		if (1 == i){
			isHasZ = TRUE;
		}
		HANDLE hHash = NULL;
		ULONG ulRes = 0;
		if (isHasZ)
		{
			ECCPUBLICKEYBLOB pubKey = {};
			string strX = GetEditString(m_PubKeyXEdit, true);
			string strY = GetEditString(m_PubKeyYEdit, true);
			StrToPubKey(strX, strY, pubKey);
			string userID = GetEditString(m_UserIDEdit, false);
			ulRes = TG_DigestInit(SGD_SM3, &pubKey,
				(BYTE*)userID.c_str(), userID.length(), &hHash);
		}
		else{
			ulRes = TG_DigestInit(SGD_SM3, NULL, NULL, 0, &hHash);
		}
		ShowMessage(L"TG_DigestInit", ulRes);
		if (0 == ulRes)
		{
			string srcData = GetEditString(m_SrcEdit, false);
			BYTE szDigest[ECC_MAX_MODULUS_BITS_LEN] = {};
			ULONG ulDigestLen = _countof(szDigest);
			ulRes = TG_Digest(hHash, (BYTE*)srcData.c_str(), srcData.length(),
				szDigest, &ulDigestLen);
			ShowMessage(L"TG_Digest", ulRes);
			if (0 == ulRes)
			{
				string strTmp = ESP_CharToHex(szDigest, ulDigestLen);
				if (isHasZ){
					m_SM3ZResEdit.SetWindowTextW(CString(strTmp.c_str()));
				}
				else{
					m_SM3ResEdit.SetWindowTextW(CString(strTmp.c_str()));
				}
			}
			TG_CloseHandle(hHash, 0);
		}
	}
}

void CSM2CheckToolDlg::ShowMessage(CString name, LONG errorCode,
	CString msg /* = L"" */, int flag /* = 0 */ )
{
	if (flag == 1){
		m_ResultEdit.Clear();
	}
	CString strMsg;
	if (-1 == errorCode)
		strMsg = name + L"\r\n";
	else if (0 == errorCode)
		strMsg.Format(L"%s�ɹ�:%s\r\n", name, msg);
	else
		strMsg.Format(L"%sʧ��:%d	%x\r\n", name, errorCode, errorCode);

	int nLen = m_ResultEdit.GetWindowTextLength();
	m_ResultEdit.SetSel(nLen, nLen);
	m_ResultEdit.ReplaceSel(strMsg);
}

std::string CSM2CheckToolDlg::GetEditString(const CEdit& et, bool isHex)
{
	std::string strRes;
	CString cstr;
	et.GetWindowTextW(cstr);
	strRes = CT2A(cstr.GetBuffer());
	if (isHex){
		strRes = ESP_HexToChar(strRes);
	}
	return strRes;
}