
// SM2CheckToolDlg.cpp : 实现文件
//

#include "stdafx.h"
#include <string>
#include "SM2CheckTool.h"
#include "SM2CheckToolDlg.h"
#include "afxdialogex.h"
#include "TG_SM2Api.h"
#pragma comment(lib, "TG_SM2Api.lib");
#include "spdlog/log.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

using namespace std;

#define SM2_KEY_LEN		32
#define KEY_OFF_SET		(ECC_MAX_MODULUS_BITS_LEN / 8 - SM2_KEY_LEN)
#define SM4_KEY_LEN		16
#define SM4_IV_LEN		16

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

void StrToSignarure(const std::string& strR, const std::string& strS,
	ECCSIGNATUREBLOB& signature)
{
	memcpy(signature.r + KEY_OFF_SET, strR.c_str(), SM2_KEY_LEN);
	memcpy(signature.s + KEY_OFF_SET, strS.c_str(), SM2_KEY_LEN);
}

// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
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


// CSM2CheckToolDlg 对话框



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
	DDX_Control(pDX, IDC_EDIT_SYM_KEY, m_SymKeyEdit);
	DDX_Control(pDX, IDC_EDIT_SYM_IV, m_SymIVEdit);
	DDX_Control(pDX, IDC_EDIT_ENCRYPT_RES, m_EncryptResEdit);
	DDX_Control(pDX, IDC_EDIT_DECRYPT_RES, m_DecryptResEdit);
	DDX_Control(pDX, IDC_COMBO_ENCRYPT_MOD, m_CryptModCob);
	DDX_Control(pDX, IDC_EDIT_ENCRYPT_PUBKEY, m_PubKeyEncEdit);
	DDX_Control(pDX, IDC_EDIT_DECRYPT_PRIKEY, m_PriKeyDecEdit);
}

BEGIN_MESSAGE_MAP(CSM2CheckToolDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON_GEN_KEY, &CSM2CheckToolDlg::OnBnClickedButtonGenKey)
	ON_BN_CLICKED(IDC_BUTTON_SIGN, &CSM2CheckToolDlg::OnBnClickedButtonSign)
	ON_BN_CLICKED(IDC_BUTTON_VERIFY, &CSM2CheckToolDlg::OnBnClickedButtonVerify)
	ON_BN_CLICKED(IDC_BUTTON_SM3, &CSM2CheckToolDlg::OnBnClickedButtonSm3)
	ON_BN_CLICKED(IDC_BUTTON_SM4_ENCRYPT, &CSM2CheckToolDlg::OnBnClickedButtonSm4Encrypt)
	ON_BN_CLICKED(IDC_BUTTON_SM4_DECRYPT, &CSM2CheckToolDlg::OnBnClickedButtonSm4Decrypt)
	ON_BN_CLICKED(IDC_BUTTON_PUBKEY_ENC, &CSM2CheckToolDlg::OnBnClickedButtonPubkeyEnc)
	ON_BN_CLICKED(IDC_BUTTON_PRIKEY_DEC, &CSM2CheckToolDlg::OnBnClickedButtonPrikeyDec)
END_MESSAGE_MAP()


// CSM2CheckToolDlg 消息处理程序

BOOL CSM2CheckToolDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
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

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO:  在此添加额外的初始化代码;
	string key = "31323334353637383132333435363738";
	SetEditString(m_SrcEdit, key, "Init_Src");
	SetEditString(m_UserIDEdit, key, "Init_UserID");
	SetEditString(m_SymKeyEdit, key, "Init_SymKey");
	SetEditString(m_SymIVEdit, key, "Init_SymIV");
	wchar_t* symMod[] = {L"SGD_SM4_ECB", L"SGD_SM4_CBC", L"SGD_SM4_CFB", L"SGD_SM4_OFB"};
	const int size = _countof(symMod);
	for (int i = 0; i < size; ++i)
	{
		m_CryptModCob.InsertString(i, symMod[i]);
	}
	m_CryptModCob.SetCurSel(0);
	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
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

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CSM2CheckToolDlg::OnPaint()
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
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CSM2CheckToolDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


void CSM2CheckToolDlg::ShowMessage(CString name, LONG errorCode /* = -1 */,
	CString msg /* = L"" */, int flag /* = 0 */ )
{
	if (flag == 1){
		m_ResultEdit.Clear();
	}
	CString strMsg;
	if (-1 == errorCode)
	{
		LOGW_ERROR(name.GetBuffer());
		strMsg = name + L"\r\n";
	}
	else if (0 == errorCode)
		strMsg.Format(L"%s成功:%s\r\n", name, msg);
	else
		strMsg.Format(L"%s失败:%d	%x\r\n", name, errorCode, errorCode);

	int nLen = m_ResultEdit.GetWindowTextLength();
	m_ResultEdit.SetSel(nLen, nLen);
	m_ResultEdit.ReplaceSel(strMsg);
}

std::string CSM2CheckToolDlg::GetEditString(const CEdit& et,
	bool isHex, const std::string& logName)
{
	std::string strRes;
	CString cstr;
	et.GetWindowTextW(cstr);
	strRes = CT2A(cstr.GetBuffer());
	LOG_ERROR("%s:%s isHex:%d", logName.c_str(), strRes.c_str(), isHex);
	if (isHex){
		strRes = ESP_HexToChar(strRes);
	}
	return strRes;
}

void CSM2CheckToolDlg::SetEditString(CEdit& et,
	const std::string& text, const std::string& logName)
{
	CString cstr = CString(text.c_str());
	et.SetWindowTextW(cstr);
	LOG_ERROR("%s:%s", logName.c_str(), text.c_str());
}

LONG CSM2CheckToolDlg::GetSymMod(BLOCKCIPHERPARAM& blolparam)
{
	LONG lCryptMod = SGD_SM4_ECB;
	int nIndex = m_CryptModCob.GetCurSel();
	switch (nIndex)
	{
	case 1:
		lCryptMod = SGD_SM4_CBC;
		break;
	case 2:
		lCryptMod = SGD_SM4_CFB;
		blolparam.FeedBitLen = 128;
		break;
	case 3:
		lCryptMod = SGD_SM4_OFB;
		break;
	default:
		break;
	}
	blolparam.PaddingType = 1;
	blolparam.IVLen = SM4_IV_LEN;
	if (lCryptMod != SGD_SM4_ECB)
	{
		string symIV = GetEditString(m_SymIVEdit, true, "SymIV");
		if (symIV.length() != SM4_IV_LEN)
		{
			ShowMessage(L"初始化向量长度必需是", SM4_IV_LEN);
			return -1;
		}
		memcpy(blolparam.IV, symIV.c_str(), blolparam.IVLen);
	}
	return lCryptMod;
}

void CSM2CheckToolDlg::GetPubKey(ECCPUBLICKEYBLOB& pubKey,
	const std::string& logName)
{
	string strX = GetEditString(m_PubKeyXEdit, true, logName + "PubKeyX");
	string strY = GetEditString(m_PubKeyYEdit, true, logName + "PubKeyY");
	StrToPubKey(strX, strY, pubKey);
}

void CSM2CheckToolDlg::GetPriKey(ECCPRIVATEKEYBLOB& priKey,
	const std::string& logName)
{
	string strPriKey = GetEditString(m_PriKeyEdit, true, logName + "PriKey");
	StrToPriKey(strPriKey, priKey);
}

void CSM2CheckToolDlg::ShowCipherText(PECCCIPHERBLOB pCipherText, const std::string& logName)
{
	CString msg = CString(logName.c_str());
	string strTmp = ESP_CharToHex(pCipherText->XCoordinate + KEY_OFF_SET, SM2_KEY_LEN);
	ShowMessage(msg + CString("XCoordinate:") + CString(strTmp.c_str()));
	strTmp = ESP_CharToHex(pCipherText->YCoordinate + KEY_OFF_SET, SM2_KEY_LEN);
	ShowMessage(msg + CString("YCoordinate:") + CString(strTmp.c_str()));
	strTmp = ESP_CharToHex(pCipherText->HASH, _countof(pCipherText->HASH));
	ShowMessage(msg + CString("HASH:") + CString(strTmp.c_str()));
	ShowMessage(msg + CString("CipherLen:") + CString(to_string(pCipherText->CipherLen).c_str()));
	strTmp = ESP_CharToHex(pCipherText->Cipher, pCipherText->CipherLen);
	ShowMessage(msg + CString("Cipher:") + CString(strTmp.c_str()));
}

void CSM2CheckToolDlg::OnBnClickedButtonGenKey()
{
	// TODO:  在此添加控件通知处理程序代码;
	ECCPRIVATEKEYBLOB priKey = {};
	ECCPUBLICKEYBLOB pubKey = {};
	ULONG ulRes = TG_GenECCKeyPair(0, &priKey, &pubKey);
	if (0 == ulRes)
	{
		string strTmp = ESP_CharToHex(priKey.PrivateKey + KEY_OFF_SET, SM2_KEY_LEN);
		SetEditString(m_PriKeyEdit, strTmp, "GenKey_PriKey");

		strTmp = ESP_CharToHex(pubKey.XCoordinate + KEY_OFF_SET, SM2_KEY_LEN);
		SetEditString(m_PubKeyXEdit, strTmp, "GenKey_PubKeyX");

		strTmp = ESP_CharToHex(pubKey.YCoordinate + KEY_OFF_SET, SM2_KEY_LEN);
		SetEditString(m_PubKeyYEdit, strTmp, "GenKey_PubKeyY");
	}
	ShowMessage(L"TG_GenECCKeyPair", ulRes);
}

void CSM2CheckToolDlg::OnBnClickedButtonSign()
{
	// TODO:  在此添加控件通知处理程序代码;
	string strDigest = GetEditString(m_SM3ZResEdit, true, "Sign_SM3Z");
	if (0 == strDigest.length()){
		OnBnClickedButtonSm3();
	}
	strDigest = GetEditString(m_SM3ZResEdit, true, "Sign_SM3Z");
	if (0 < strDigest.length())
	{
		ECCPRIVATEKEYBLOB priKey = {};
		GetPriKey(priKey, "Sign_");
		ECCSIGNATUREBLOB signature = {};
		ULONG ulRes = TG_ECCSign(&priKey,
			(BYTE*)strDigest.c_str(), strDigest.length(), &signature);
		ShowMessage(L"TG_ECCSign", ulRes);
		if (0 == ulRes)
		{
			string strTmp = ESP_CharToHex(signature.r + KEY_OFF_SET, SM2_KEY_LEN);
			SetEditString(m_SignResR, strTmp, "Sign_R");

			strTmp = ESP_CharToHex(signature.s + KEY_OFF_SET, SM2_KEY_LEN);
			SetEditString(m_SignResS, strTmp, "Sign_S");
		}
	}
	else{
		ShowMessage(L"Digest is empty");
	}
}

void CSM2CheckToolDlg::OnBnClickedButtonVerify()
{
	// TODO:  在此添加控件通知处理程序代码;
	string strDigest = GetEditString(m_SM3ZResEdit, true, "Verify_SM3Z");
	if (0 == strDigest.length()){
		OnBnClickedButtonSm3();
	}
	strDigest = GetEditString(m_SM3ZResEdit, true, "Verify_SM3Z");
	if (0 < strDigest.length())
	{
		ECCPUBLICKEYBLOB pubKey = {};
		GetPubKey(pubKey, "Verify_");
		ECCSIGNATUREBLOB signature = {};
		string strR = GetEditString(m_SignResR, true, "Verify_SignValueR");
		string strS = GetEditString(m_SignResS, true, "Verify_SignValueS");
		StrToSignarure(strR, strS, signature);
		ULONG ulRes = TG_ECCVerify(&pubKey,
			(BYTE*)strDigest.c_str(), strDigest.length(), &signature);
		ShowMessage(L"TG_ECCVerify", ulRes);
		SetEditString(m_VerifyRes, std::to_string(ulRes), "Verify_Res");
	}
	else{
		ShowMessage(L"Digest is empty");
	}
}

void CSM2CheckToolDlg::OnBnClickedButtonSm3()
{
	//TODO:  在此添加控件通知处理程序代码;
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
			GetPubKey(pubKey, "SM3_");
			string userID = GetEditString(m_UserIDEdit, true, "SM3_UserID");
			ulRes = TG_DigestInit(SGD_SM3, &pubKey,
				(BYTE*)userID.c_str(), userID.length(), &hHash);
		}
		else{
			ulRes = TG_DigestInit(SGD_SM3, NULL, NULL, 0, &hHash);
		}
		ShowMessage(L"TG_DigestInit", ulRes);
		if (0 == ulRes)
		{
			string srcData = GetEditString(m_SrcEdit, true, "SM3_Src");
			BYTE szDigest[ECC_MAX_MODULUS_BITS_LEN] = {};
			ULONG ulDigestLen = _countof(szDigest);
			ulRes = TG_Digest(hHash, (BYTE*)srcData.c_str(), srcData.length(),
				szDigest, &ulDigestLen);
			ShowMessage(L"TG_Digest", ulRes);
			if (0 == ulRes)
			{
				string strTmp = ESP_CharToHex(szDigest, ulDigestLen);
				if (isHasZ){
					SetEditString(m_SM3ZResEdit, strTmp, "SM3_SM3Z");
				}
				else{
					SetEditString(m_SM3ResEdit, strTmp, "SM3_SM3");
				}
			}
			TG_CloseHandle(hHash, 0);
		}
	}
}

void CSM2CheckToolDlg::OnBnClickedButtonSm4Encrypt()
{
	// TODO:  在此添加控件通知处理程序代码;
	string symKey = GetEditString(m_SymKeyEdit, true, "SM4Encrypt_SymKey");
	if (symKey.length() != SM4_KEY_LEN)
	{
		ShowMessage(L"密钥长度必需是", SM2_KEY_LEN);
		return;
	}
	BLOCKCIPHERPARAM blolparam = { 0 };
	ULONG ulAlgID = GetSymMod(blolparam);
	if (-1 == ulAlgID){
		return;
	}
	HANDLE hKey = NULL;
	LONG lRes = TG_SetSymmKey((BYTE*)symKey.c_str(), ulAlgID, &hKey);
	ShowMessage(L"TG_SetSymmKey", lRes);
	if (0 == lRes)
	{
		lRes = TG_EncryptInit(hKey, blolparam);
		ShowMessage(L"TG_EncryptInit", lRes);
		if (0 == lRes)
		{
			string src = GetEditString(m_SrcEdit, true, "SM4Encrypt_Src");
			ULONG ulLen = src.length() + 128;
			BYTE* pData = new BYTE[ulLen];
			lRes = TG_Encrypt(hKey, (BYTE*)src.c_str(), src.length(), pData, &ulLen);
			if (0 == lRes)
			{
				string strTmp = ESP_CharToHex(pData, ulLen);
				SetEditString(m_EncryptResEdit, strTmp, "SM4Encrypt_Res");
			}
			delete[] pData;
			ShowMessage(L"TG_Encrypt", lRes);
		}
		TG_CloseHandle(hKey, 0);
	}
}

void CSM2CheckToolDlg::OnBnClickedButtonSm4Decrypt()
{
	// TODO:  在此添加控件通知处理程序代码;
	string symKey = GetEditString(m_SymKeyEdit, true, "SM4Decrypt_SymKey");
	if (symKey.length() != SM4_KEY_LEN)
	{
		ShowMessage(L"密钥长度必需是", SM2_KEY_LEN);
		return;
	}
	BLOCKCIPHERPARAM blolparam = { 0 };
	ULONG ulAlgID = GetSymMod(blolparam);
	if (-1 == ulAlgID){
		return;
	}
	HANDLE hKey = NULL;
	LONG lRes = TG_SetSymmKey((BYTE*)symKey.c_str(), ulAlgID, &hKey);
	ShowMessage(L"TG_SetSymmKey", lRes);
	if (0 == lRes)
	{
		lRes = TG_DecryptInit(hKey, blolparam);
		ShowMessage(L"TG_DecryptInit", lRes);
		if (0 == lRes)
		{
			string encryptRes = GetEditString(m_EncryptResEdit, true, "SM4Decrypt_EncRes");
			ULONG ulLen = encryptRes.length() + 128;
			BYTE* pData = new BYTE[ulLen];
			lRes = TG_Decrypt(hKey,
				(BYTE*)encryptRes.c_str(), encryptRes.length(), pData, &ulLen);
			if (0 == lRes)
			{
				string strTmp = ESP_CharToHex(pData, ulLen);
				SetEditString(m_DecryptResEdit, strTmp, "SM4Decrypt_Res");
			}
			delete[] pData;
			ShowMessage(L"TG_Decrypt", lRes);
		}
		TG_CloseHandle(hKey, 0);
	}
}

void CSM2CheckToolDlg::OnBnClickedButtonPubkeyEnc()
{
	// TODO:  在此添加控件通知处理程序代码;
	ECCPUBLICKEYBLOB pubKey = {};
	GetPubKey(pubKey, "PubkeyEnc_");
	string src = GetEditString(m_SrcEdit, true, "PubkeyEnc_Src");
	int cipherLen = sizeof(ECCCIPHERBLOB) + src.length() + SM2_KEY_LEN;
	PECCCIPHERBLOB pCipherText = (PECCCIPHERBLOB)malloc(cipherLen);
	memset(pCipherText, 0, cipherLen);
	LONG lRes = TG_ECCPubKeyEncrypt(&pubKey, (BYTE*)src.c_str(), src.length(), pCipherText);
	if (0 == lRes)
	{
		ShowCipherText(pCipherText, "PubkeyEnc_");
		cipherLen = sizeof(ECCCIPHERBLOB)+pCipherText->CipherLen;
		string strTmp = ESP_CharToHex((BYTE*)pCipherText, cipherLen);
		SetEditString(m_PubKeyEncEdit, strTmp, "PubkeyEnc_Res");
	}
	free(pCipherText);
	ShowMessage(L"TG_ECCPubKeyEncrypt", lRes);
}

void CSM2CheckToolDlg::OnBnClickedButtonPrikeyDec()
{
	// TODO:  在此添加控件通知处理程序代码;
	ECCPRIVATEKEYBLOB priKey = {};
	GetPriKey(priKey, "PrikeyDec_");
	string cipherText = GetEditString(m_PubKeyEncEdit, true, "PrikeyDec_PubKeyEncRes");
	PECCCIPHERBLOB pCipherText = (PECCCIPHERBLOB)cipherText.c_str();
	ShowCipherText(pCipherText, "PrikeyDec_");
	ULONG ulLen = pCipherText->CipherLen;
	BYTE* pData = new BYTE[ulLen];
	LONG lRes = TG_ECCPriKeyDecrypt(&priKey, pCipherText, pData, &ulLen);
	if (0 == lRes)
	{
		string strTmp = ESP_CharToHex((BYTE*)pData, ulLen);
		SetEditString(m_PriKeyDecEdit, strTmp, "PrikeyDec_Res");
	}
	ShowMessage(L"TG_ECCPriKeyDecrypt", lRes);
}
