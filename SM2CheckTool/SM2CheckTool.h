
// SM2CheckTool.h : PROJECT_NAME Ӧ�ó������ͷ�ļ�
//

#pragma once

#ifndef __AFXWIN_H__
	#error "�ڰ������ļ�֮ǰ������stdafx.h�������� PCH �ļ�"
#endif

#include "resource.h"		// ������


// CSM2CheckToolApp: 
// �йش����ʵ�֣������ SM2CheckTool.cpp
//

class CSM2CheckToolApp : public CWinApp
{
public:
	CSM2CheckToolApp();

// ��д
public:
	virtual BOOL InitInstance();

// ʵ��

	DECLARE_MESSAGE_MAP()
};

extern CSM2CheckToolApp theApp;