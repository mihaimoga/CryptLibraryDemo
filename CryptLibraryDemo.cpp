/* Copyright (C) 2014-2025 Stefan-Mihai MOGA
This file is part of CryptLibraryDemo application developed by Stefan-Mihai MOGA.

CryptLibraryDemo is free software: you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the Open
Source Initiative, either version 3 of the License, or any later version.

CryptLibraryDemo is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with
CryptLibraryDemo. If not, see <http://www.opensource.org/licenses/gpl-3.0.html>*/

// CryptLibraryDemo.cpp : Defines the class behaviors for the application.
//

#include "stdafx.h"
#include "CryptLibraryDemo.h"
#include "CryptLibraryDemoDlg.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

///////////////////////////////////////////////////////////////////////////////
// CCryptLibraryDemoApp
///////////////////////////////////////////////////////////////////////////////

BEGIN_MESSAGE_MAP(CCryptLibraryDemoApp, CWinAppEx)
	ON_COMMAND(ID_HELP, &CWinApp::OnHelp)
END_MESSAGE_MAP()

///////////////////////////////////////////////////////////////////////////////
// CCryptLibraryDemoApp construction
///////////////////////////////////////////////////////////////////////////////

CCryptLibraryDemoApp::CCryptLibraryDemoApp()
{
	EnableHtmlHelp();

	// TODO: add construction code here,
	// Place all significant initialization in InitInstance
}


// The one and only CCryptLibraryDemoApp object

CCryptLibraryDemoApp theApp;

///////////////////////////////////////////////////////////////////////////////
// CCryptLibraryDemoApp initialization
///////////////////////////////////////////////////////////////////////////////

BOOL CCryptLibraryDemoApp::InitInstance()
{
	// InitCommonControlsEx() is required on Windows XP if an application
	// manifest specifies use of ComCtl32.dll version 6 or later to enable
	// visual styles.  Otherwise, any window creation will fail.
	INITCOMMONCONTROLSEX InitCtrls;
	InitCtrls.dwSize = sizeof(InitCtrls);
	// Set this to include all the common control classes you want to use
	// in your application.
	InitCtrls.dwICC = ICC_WIN95_CLASSES;
	InitCommonControlsEx(&InitCtrls);

	CWinAppEx::InitInstance();

	AfxEnableControlContainer();

	// Standard initialization
	// If you are not using these features and wish to reduce the size
	// of your final executable, you should remove from the following
	// the specific initialization routines you do not need
	// Change the registry key under which our settings are stored
	// TODO: You should modify this string to be something appropriate
	// such as the name of your company or organization
	SetRegistryKey(_T("MihaiMoga"));

	CCryptLibraryDemoDlg dlgCryptLibraryDemo;
	m_pMainWnd = &dlgCryptLibraryDemo;
	INT_PTR nResponse = dlgCryptLibraryDemo.DoModal();
	if (nResponse == IDOK)
	{
		// TODO: Place code here to handle when the dialog is
		//  dismissed with OK
	}
	else if (nResponse == IDCANCEL)
	{
		// TODO: Place code here to handle when the dialog is
		//  dismissed with Cancel
	}

	// Since the dialog has been closed, return FALSE so that we exit the
	//  application, rather than start the application's message pump.
	return FALSE;
}
