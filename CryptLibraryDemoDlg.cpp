/* This file is part of CryptLibraryDemo application developed by Stefan-Mihai MOGA.

CryptLibraryDemo is free software: you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the Open
Source Initiative, either version 3 of the License, or any later version.

CryptLibraryDemo is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with
CryptLibraryDemo. If not, see <http://www.opensource.org/licenses/gpl-3.0.html>*/

// CryptLibraryDemoDlg.cpp : implementation file
//

#include "stdafx.h"
#include "CryptLibraryDemo.h"
#include "CryptLibraryDemoDlg.h"
#include "CryptographyExt.h"

#include "VersionInfo.h"
#include "HLinkCtrl.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

///////////////////////////////////////////////////////////////////////////////
// CAboutDlg dialog used for App About
///////////////////////////////////////////////////////////////////////////////

class CAboutDlg : public CDialog
{
public:
	CAboutDlg();

// Dialog Data
	enum { IDD = IDD_ABOUTBOX };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

// Implementation
public:
	virtual BOOL OnInitDialog();
	afx_msg void OnDestroy();

protected:
	CStatic m_ctrlVersion;
	CEdit m_ctrlWarning;
	CVersionInfo m_pVersionInfo;
	CHLinkCtrl m_ctrlWebsite;
	CHLinkCtrl m_ctrlEmail;

	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialog(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_VERSION, m_ctrlVersion);
	DDX_Control(pDX, IDC_WARNING, m_ctrlWarning);
	DDX_Control(pDX, IDC_WEBSITE, m_ctrlWebsite);
	DDX_Control(pDX, IDC_EMAIL, m_ctrlEmail);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialog)
	ON_WM_DESTROY()
END_MESSAGE_MAP()

BOOL CAboutDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	TCHAR lpszDrive[_MAX_DRIVE];
	TCHAR lpszDirectory[_MAX_DIR];
	TCHAR lpszFilename[_MAX_FNAME];
	TCHAR lpszExtension[_MAX_EXT];
	TCHAR lpszFullPath[_MAX_PATH];

	VERIFY(0 == _tsplitpath_s(AfxGetApp()->m_pszHelpFilePath, lpszDrive, _MAX_DRIVE, lpszDirectory, _MAX_DIR, lpszFilename, _MAX_FNAME, lpszExtension, _MAX_EXT));
	VERIFY(0 == _tmakepath_s(lpszFullPath, _MAX_PATH, lpszDrive, lpszDirectory, lpszFilename, _T(".exe")));

	if (m_pVersionInfo.Load(lpszFullPath))
	{
		CString strName = m_pVersionInfo.GetProductName().c_str();
		CString strVersion = m_pVersionInfo.GetProductVersionAsString().c_str();
		strVersion.Replace(_T(" "), _T(""));
		strVersion.Replace(_T(","), _T("."));
		const int nFirst = strVersion.Find(_T('.'));
		const int nSecond = strVersion.Find(_T('.'), nFirst + 1);
		strVersion.Truncate(nSecond);
#if _WIN32 || _WIN64
#if _WIN64
		m_ctrlVersion.SetWindowText(strName + _T(" version ") + strVersion + _T(" (64-bit)"));
#else
		m_ctrlVersion.SetWindowText(strName + _T(" version ") + strVersion + _T(" (32-bit)"));
#endif
#endif
	}

	m_ctrlWarning.SetWindowText(_T("This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version. This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details. You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>."));

	m_ctrlWebsite.SetHyperLink(_T("https://www.moga.doctor/"));
	m_ctrlEmail.SetHyperLink(_T("mailto:stefan-mihai@moga.doctor"));

	return TRUE;  // return TRUE unless you set the focus to a control
	// EXCEPTION: OCX Property Pages should return FALSE
}

void CAboutDlg::OnDestroy()
{
	CDialog::OnDestroy();
}

///////////////////////////////////////////////////////////////////////////////
// CCryptLibraryDemoDlg dialog
///////////////////////////////////////////////////////////////////////////////

CCryptLibraryDemoDlg::CCryptLibraryDemoDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CCryptLibraryDemoDlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CCryptLibraryDemoDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_FILENAME, m_editFilename);
	DDX_Control(pDX, IDC_CHECKSUM, m_editChecksum);
	DDX_Control(pDX, IDC_INPUTNAME, m_editInputName);
	DDX_Control(pDX, IDC_OUTPUTNAME, m_editOutputName);
	DDX_Control(pDX, IDC_COMPUTE, m_btnCompute);
	DDX_Control(pDX, IDC_ENCRYPT, m_btnEncrypt);
	DDX_Control(pDX, IDC_DECRYPT, m_btnDecrypt);
}

BEGIN_MESSAGE_MAP(CCryptLibraryDemoDlg, CDialog)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	//}}AFX_MSG_MAP
	ON_BN_CLICKED(IDC_SELECT, &CCryptLibraryDemoDlg::OnBnClickedSelect)
	ON_BN_CLICKED(IDC_COMPUTE, &CCryptLibraryDemoDlg::OnBnClickedCompute)
	ON_BN_CLICKED(IDC_INPUTFILE, &CCryptLibraryDemoDlg::OnBnClickedInputfile)
	ON_BN_CLICKED(IDC_OUTPUTFILE, &CCryptLibraryDemoDlg::OnBnClickedOutputfile)
	ON_BN_CLICKED(IDC_ENCRYPT, &CCryptLibraryDemoDlg::OnBnClickedEncrypt)
	ON_BN_CLICKED(IDC_DECRYPT, &CCryptLibraryDemoDlg::OnBnClickedDecrypt)
END_MESSAGE_MAP()

///////////////////////////////////////////////////////////////////////////////
// CCryptLibraryDemoDlg message handlers
///////////////////////////////////////////////////////////////////////////////

BOOL CCryptLibraryDemoDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// Add "About..." menu item to system menu.

	// IDM_ABOUTBOX must be in the system command range.
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
		pSysMenu->AppendMenu(MF_SEPARATOR);
		pSysMenu->AppendMenu(MF_STRING, IDM_TWITTER, _T("Twitter"));
		pSysMenu->AppendMenu(MF_STRING, IDM_LINKEDIN, _T("LinkedIn"));
		pSysMenu->AppendMenu(MF_STRING, IDM_FACEBOOK, _T("Facebook"));
		pSysMenu->AppendMenu(MF_STRING, IDM_INSTAGRAM, _T("Instagram"));
		pSysMenu->AppendMenu(MF_SEPARATOR);
		pSysMenu->AppendMenu(MF_STRING, IDM_ISSUES, _T("Issues"));
		pSysMenu->AppendMenu(MF_STRING, IDM_DISCUSSIONS, _T("Discussions"));
		pSysMenu->AppendMenu(MF_STRING, IDM_WIKI, _T("Wiki"));
	}

	// Set the icon for this dialog.  The framework does this automatically
	//  when the application's main window is not a dialog
	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon

	CRect rectCryptLibraryDemo;
	GetClientRect(&rectCryptLibraryDemo);
	TRACE(_T("[CCryptLibraryDemoDlg] Width = %d, Height = %d\n"),
		rectCryptLibraryDemo.Width(), rectCryptLibraryDemo.Height());

	m_btnCompute.EnableWindow(FALSE);
	m_btnEncrypt.EnableWindow(FALSE);
	m_btnDecrypt.EnableWindow(FALSE);

	return TRUE;  // return TRUE  unless you set the focus to a control
}

void CCryptLibraryDemoDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		if (nID == IDM_TWITTER)
		{
			::ShellExecute(GetSafeHwnd(), _T("open"), _T("https://twitter.com/stefanmihaimoga"), nullptr, nullptr, SW_SHOW);
		}
		else
		{
			if (nID == IDM_LINKEDIN)
			{
				::ShellExecute(GetSafeHwnd(), _T("open"), _T("https://www.linkedin.com/in/stefanmihaimoga/"), nullptr, nullptr, SW_SHOW);
			}
			else
			{
				if (nID == IDM_FACEBOOK)
				{
					::ShellExecute(GetSafeHwnd(), _T("open"), _T("https://www.facebook.com/stefanmihaimoga"), nullptr, nullptr, SW_SHOW);
				}
				else
				{
					if (nID == IDM_INSTAGRAM)
					{
						::ShellExecute(GetSafeHwnd(), _T("open"), _T("https://www.instagram.com/stefanmihaimoga/"), nullptr, nullptr, SW_SHOW);
					}
					else
					{
						if (nID == IDM_ISSUES)
						{
							::ShellExecute(GetSafeHwnd(), _T("open"), _T("https://github.com/mihaimoga/CryptLibraryDemo/issues"), nullptr, nullptr, SW_SHOW);
						}
						else
						{
							if (nID == IDM_DISCUSSIONS)
							{
								::ShellExecute(GetSafeHwnd(), _T("open"), _T("https://github.com/mihaimoga/CryptLibraryDemo/discussions"), nullptr, nullptr, SW_SHOW);
							}
							else
							{
								if (nID == IDM_WIKI)
								{
									::ShellExecute(GetSafeHwnd(), _T("open"), _T("https://github.com/mihaimoga/CryptLibraryDemo/wiki"), nullptr, nullptr, SW_SHOW);
								}
								else
								{
									CDialog::OnSysCommand(nID, lParam);
								}
							}
						}
					}

				}
			}
		}
	}
}

// If you add a minimize button to your dialog, you will need the code below
//  to draw the icon.  For MFC applications using the document/view model,
//  this is automatically done for you by the framework.

void CCryptLibraryDemoDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // device context for painting

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// Center icon in client rectangle
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// Draw the icon
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialog::OnPaint();
	}
}

// The system calls this function to obtain the cursor to display while the user drags
//  the minimized window.
HCURSOR CCryptLibraryDemoDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

void CCryptLibraryDemoDlg::OnBnClickedSelect()
{
	DWORD dwFlags = OFN_DONTADDTORECENT | OFN_ENABLESIZING | OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_LONGNAMES;
	LPCTSTR lpszFilter = _T("All files (*.*)|*.*\0");
	CFileDialog pFileDialog(TRUE, NULL, NULL, dwFlags, lpszFilter, this);
	if (pFileDialog.DoModal() == IDOK)
	{
		m_strFilename = pFileDialog.GetPathName();
		m_editFilename.SetWindowText(m_strFilename);
		m_btnCompute.EnableWindow(!m_strFilename.IsEmpty());
	}
}

void CCryptLibraryDemoDlg::OnBnClickedCompute()
{
	CString strResult;
	if (!m_strFilename.IsEmpty())
	{
		if (GetChecksumFile(CALG_MD5, strResult, m_strFilename))
		{
			m_editChecksum.SetWindowText(strResult);
			MessageBox(_T("MD5 checksum of selected file is ready!"), _T("Crypt Library Demo"), MB_OK);
		}
	}
}

void CCryptLibraryDemoDlg::OnBnClickedInputfile()
{
	DWORD dwFlags = OFN_DONTADDTORECENT | OFN_ENABLESIZING | OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_LONGNAMES;
	LPCTSTR lpszFilter = _T("All files (*.*)|*.*\0");
	CFileDialog pFileDialog(TRUE, NULL, NULL, dwFlags, lpszFilter, this);
	if (pFileDialog.DoModal() == IDOK)
	{
		m_strInputName = pFileDialog.GetPathName();
		m_editInputName.SetWindowText(m_strInputName);
		m_btnEncrypt.EnableWindow(!m_strInputName.IsEmpty() && !m_strOutputName.IsEmpty());
		m_btnDecrypt.EnableWindow(!m_strInputName.IsEmpty() && !m_strOutputName.IsEmpty());
	}
}

void CCryptLibraryDemoDlg::OnBnClickedOutputfile()
{
	DWORD dwFlags = OFN_DONTADDTORECENT | OFN_ENABLESIZING | OFN_EXPLORER | OFN_HIDEREADONLY | OFN_LONGNAMES;
	LPCTSTR lpszFilter = _T("All files (*.*)|*.*\0");
	CFileDialog pFileDialog(FALSE, NULL, NULL, dwFlags, lpszFilter, this);
	if (pFileDialog.DoModal() == IDOK)
	{
		m_strOutputName = pFileDialog.GetPathName();
		m_editOutputName.SetWindowText(m_strOutputName);
		m_btnEncrypt.EnableWindow(!m_strInputName.IsEmpty() && !m_strOutputName.IsEmpty());
		m_btnDecrypt.EnableWindow(!m_strInputName.IsEmpty() && !m_strOutputName.IsEmpty());
	}
}

void CCryptLibraryDemoDlg::OnBnClickedEncrypt()
{
	CString strSecretKey = GetComputerID();
	LPBYTE lpszSecretKey = (LPBYTE)(LPCTSTR)strSecretKey;
	DWORD dwSecretKey = (strSecretKey.GetLength() + 1) * sizeof(TCHAR);
	if (!m_strInputName.IsEmpty() && !m_strOutputName.IsEmpty())
	{
		if (EncryptFile(CALG_RC4, m_strOutputName, m_strInputName, lpszSecretKey, dwSecretKey))
		{
			MessageBox(_T("The file have been successfully encrypted!"), _T("Crypt Library Demo"), MB_OK);
		}
	}
}

void CCryptLibraryDemoDlg::OnBnClickedDecrypt()
{
	CString strSecretKey = GetComputerID();
	LPBYTE lpszSecretKey = (LPBYTE)(LPCTSTR)strSecretKey;
	DWORD dwSecretKey = (strSecretKey.GetLength() + 1) * sizeof(TCHAR);
	if (!m_strInputName.IsEmpty() && !m_strOutputName.IsEmpty())
	{
		if (EncryptFile(CALG_RC4, m_strOutputName, m_strInputName, lpszSecretKey, dwSecretKey))
		{
			MessageBox(_T("The file have been successfully decrypted!"), _T("Crypt Library Demo"), MB_OK);
		}
	}
}
