/* Copyright (C) 2014-2026 Stefan-Mihai MOGA
This file is part of CryptLibraryDemo application developed by Stefan-Mihai MOGA.

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

/**
 * @brief Internal dialog class that displays the application's About box.
 *
 * Shows the product name, version string, licence text, and hyperlinks
 * to the author's website and e-mail address.
 */
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

/**
 * @brief Constructs the CAboutDlg dialog.
 */
CAboutDlg::CAboutDlg() : CDialog(CAboutDlg::IDD)
{
}

/**
 * @brief Performs dialog data exchange for the About box controls.
 * @param pDX Pointer to the CDataExchange object used for DDX/DDV.
 */
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

/**
 * @brief Retrieves the full path of the currently executing module.
 *
 * Calls ::GetModuleFileName() with a dynamically growing buffer until the
 * path fits, then returns it as a CString.
 *
 * @param pdwLastError Optional output parameter that receives the last Win32
 *                     error code. Set to ERROR_SUCCESS on success.
 * @return The full file-system path of the executable, or an empty CString
 *         if the call fails.
 */
CString GetModuleFileName(_Inout_opt_ DWORD* pdwLastError = nullptr)
{
	CString strModuleFileName;
	DWORD dwSize{ _MAX_PATH };   // start with MAX_PATH and double on overflow
	while (true)
	{
		// Allocate a raw buffer of the current candidate size
		TCHAR* pszModuleFileName{ strModuleFileName.GetBuffer(dwSize) };
		const DWORD dwResult{ ::GetModuleFileName(nullptr, pszModuleFileName, dwSize) };
		if (dwResult == 0)
		{
			// API failed entirely – capture the error code and return empty
			if (pdwLastError != nullptr)
				*pdwLastError = GetLastError();
			strModuleFileName.ReleaseBuffer(0);
			return CString{};
		}
		else if (dwResult < dwSize)
		{
			// Path fits within the buffer – commit the exact character count
			if (pdwLastError != nullptr)
				*pdwLastError = ERROR_SUCCESS;
			strModuleFileName.ReleaseBuffer(dwResult);
			return strModuleFileName;
		}
		else if (dwResult == dwSize)
		{
			// Buffer was too small – discard contents and try again with double the size
			strModuleFileName.ReleaseBuffer(0);
			dwSize *= 2;
		}
	}
}

/**
 * @brief Initialises the About dialog: populates version, licence, and link controls.
 * @return TRUE to let the framework set input focus to the first control.
 */
BOOL CAboutDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// Obtain the full path of the running executable to read its VERSIONINFO resource
	CString strFullPath{ GetModuleFileName() };
	if (strFullPath.IsEmpty())
#pragma warning(suppress: 26487)
		return FALSE;

	if (m_pVersionInfo.Load(strFullPath.GetString()))
	{
		CString strName = m_pVersionInfo.GetProductName().c_str();
		CString strVersion = m_pVersionInfo.GetProductVersionAsString().c_str();
		// Normalise the raw version string: remove spaces and replace commas with dots
		strVersion.Replace(_T(" "), _T(""));
		strVersion.Replace(_T(","), _T("."));
		// Keep only the first two version components (Major.Minor)
		const int nFirst = strVersion.Find(_T('.'));               // position of first dot
		const int nSecond = strVersion.Find(_T('.'), nFirst + 1);  // position of second dot
		strVersion.Truncate(nSecond);
		// Pad a single-digit minor version with a leading zero (e.g. "1.9" -> "1.09")
		if (nSecond == (nFirst + 2))
			strVersion.Insert(nFirst + 1, _T("0"));
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

/**
 * @brief Handles WM_DESTROY for the About dialog; delegates to the base class.
 */
void CAboutDlg::OnDestroy()
{
	CDialog::OnDestroy();
}

///////////////////////////////////////////////////////////////////////////////
// CCryptLibraryDemoDlg dialog
///////////////////////////////////////////////////////////////////////////////

/**
 * @brief Constructs the main application dialog and loads the application icon.
 * @param pParent Optional pointer to the parent window. Defaults to NULL.
 */
CCryptLibraryDemoDlg::CCryptLibraryDemoDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CCryptLibraryDemoDlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

/**
 * @brief Binds dialog controls to their corresponding member variables via DDX/DDV.
 * @param pDX Pointer to the CDataExchange object used for DDX/DDV.
 */
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

/**
 * @brief Initialises the main dialog: sets up the system menu, icons, and
 *        disables buttons that require a file selection before use.
 * @return TRUE to let the framework set input focus to the first control.
 */
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

	// Log the initial dialog dimensions for debugging layout issues
	CRect rectCryptLibraryDemo;
	GetClientRect(&rectCryptLibraryDemo);
	TRACE(_T("[CCryptLibraryDemoDlg] Width = %d, Height = %d\n"),
		rectCryptLibraryDemo.Width(), rectCryptLibraryDemo.Height());

	// Disable action buttons until the user selects the required files
	m_btnCompute.EnableWindow(FALSE);  // requires a file for checksum
	m_btnEncrypt.EnableWindow(FALSE);  // requires both input and output files
	m_btnDecrypt.EnableWindow(FALSE);  // requires both input and output files

	return TRUE;  // return TRUE  unless you set the focus to a control
}

/**
 * @brief Handles WM_SYSCOMMAND messages.
 *
 * Intercepts the About box command and social-media / repository link commands
 * added to the system menu in OnInitDialog(). All other commands are forwarded
 * to the base class.
 *
 * @param nID    The system command identifier.
 * @param lParam Additional message-specific data.
 */
void CCryptLibraryDemoDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	// Mask the lower four bits as required by the Windows SDK documentation
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		// Show the About dialog modally
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		// Dispatch social-media / repository link commands added to the system menu
		if (nID == IDM_TWITTER)
		{
			::ShellExecute(GetSafeHwnd(), _T("open"), _T("https://x.com/stefanmihaimoga"), nullptr, nullptr, SW_SHOW);
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
									// Unknown command – let the framework handle it (e.g. SC_MINIMIZE)
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

/**
 * @brief Handles WM_PAINT.
 *
 * When the window is iconic, manually centres and draws the application icon
 * inside the client rectangle. For normal window states the base-class
 * implementation is called.
 */
void CCryptLibraryDemoDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // device context for painting

		// Erase the icon background before drawing
		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// Center icon in client rectangle
		int cxIcon = GetSystemMetrics(SM_CXICON);  // standard icon width in pixels
		int cyIcon = GetSystemMetrics(SM_CYICON);  // standard icon height in pixels
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;  // horizontal centre offset
		int y = (rect.Height() - cyIcon + 1) / 2; // vertical centre offset

		// Draw the icon
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialog::OnPaint();
	}
}

/**
 * @brief Returns the cursor to display while the user drags the minimized window.
 * @return The application icon handle cast to an HCURSOR.
 */
HCURSOR CCryptLibraryDemoDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

/**
 * @brief Handles the "Select" button click.
 *
 * Opens a file-open dialog so the user can choose a file whose MD5 checksum
 * will be computed. Enables the Compute button when a valid path is selected.
 */
void CCryptLibraryDemoDlg::OnBnClickedSelect()
{
	// OFN_FILEMUSTEXIST ensures the user cannot type a non-existent path
	DWORD dwFlags = OFN_DONTADDTORECENT | OFN_ENABLESIZING | OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_LONGNAMES;
	LPCTSTR lpszFilter = _T("All files (*.*)|*.*\0");
	CFileDialog pFileDialog(TRUE, NULL, NULL, dwFlags, lpszFilter, this);
	if (pFileDialog.DoModal() == IDOK)
	{
		// Store the selected path and reflect it in the edit control
		m_strFilename = pFileDialog.GetPathName();
		m_editFilename.SetWindowText(m_strFilename);
		// Enable the Compute button only when a valid path has been captured
		m_btnCompute.EnableWindow(!m_strFilename.IsEmpty());
	}
}

/**
 * @brief Handles the "Compute" button click.
 *
 * Calculates the MD5 checksum of the previously selected file using
 * GetChecksumFile() and displays the result in the checksum edit control.
 */
void CCryptLibraryDemoDlg::OnBnClickedCompute()
{
	CString strResult;
	if (!m_strFilename.IsEmpty())
	{
		// Compute the MD5 digest of the selected file via the CryptoAPI wrapper
		if (GetChecksumFile(CALG_MD5, strResult, m_strFilename))
		{
			// Display the hex-encoded checksum string in the read-only edit control
			m_editChecksum.SetWindowText(strResult);
			MessageBox(_T("MD5 checksum of selected file is ready!"), _T("Crypt Library Demo"), MB_OK);
		}
	}
}

/**
 * @brief Handles the "Input File" button click.
 *
 * Opens a file-open dialog so the user can specify the source file for
 * encryption or decryption. Enables Encrypt/Decrypt buttons when both
 * input and output paths are set.
 */
void CCryptLibraryDemoDlg::OnBnClickedInputfile()
{
	// Open an existing file as the encryption/decryption source
	DWORD dwFlags = OFN_DONTADDTORECENT | OFN_ENABLESIZING | OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_LONGNAMES;
	LPCTSTR lpszFilter = _T("All files (*.*)|*.*\0");
	CFileDialog pFileDialog(TRUE, NULL, NULL, dwFlags, lpszFilter, this);
	if (pFileDialog.DoModal() == IDOK)
	{
		// Store the source path and update the corresponding edit control
		m_strInputName = pFileDialog.GetPathName();
		m_editInputName.SetWindowText(m_strInputName);
		// Both input and output paths must be set before encryption/decryption is allowed
		m_btnEncrypt.EnableWindow(!m_strInputName.IsEmpty() && !m_strOutputName.IsEmpty());
		m_btnDecrypt.EnableWindow(!m_strInputName.IsEmpty() && !m_strOutputName.IsEmpty());
	}
}

/**
 * @brief Handles the "Output File" button click.
 *
 * Opens a file-save dialog so the user can specify the destination file for
 * encryption or decryption. Enables Encrypt/Decrypt buttons when both
 * input and output paths are set.
 */
void CCryptLibraryDemoDlg::OnBnClickedOutputfile()
{
	// Save dialog (FALSE) – the output file does not need to exist yet;
	// OFN_HIDEREADONLY removes the read-only checkbox from the dialog
	DWORD dwFlags = OFN_DONTADDTORECENT | OFN_ENABLESIZING | OFN_EXPLORER | OFN_HIDEREADONLY | OFN_LONGNAMES;
	LPCTSTR lpszFilter = _T("All files (*.*)|*.*\0");
	CFileDialog pFileDialog(FALSE, NULL, NULL, dwFlags, lpszFilter, this);
	if (pFileDialog.DoModal() == IDOK)
	{
		// Store the destination path and update the corresponding edit control
		m_strOutputName = pFileDialog.GetPathName();
		m_editOutputName.SetWindowText(m_strOutputName);
		// Both input and output paths must be set before encryption/decryption is allowed
		m_btnEncrypt.EnableWindow(!m_strInputName.IsEmpty() && !m_strOutputName.IsEmpty());
		m_btnDecrypt.EnableWindow(!m_strInputName.IsEmpty() && !m_strOutputName.IsEmpty());
	}
}

/**
 * @brief Handles the "Encrypt" button click.
 *
 * Retrieves the machine-specific secret key via GetComputerID() and uses
 * EncryptFile() with the RC4 algorithm to encrypt the input file,
 * writing the result to the output file.
 */
void CCryptLibraryDemoDlg::OnBnClickedEncrypt()
{
	// Derive a machine-specific secret key from the computer's unique identifier
	CString strSecretKey = GetComputerID();
	LPBYTE lpszSecretKey = (LPBYTE)(LPCTSTR)strSecretKey;  // raw byte pointer into the key string
	DWORD dwSecretKey = (strSecretKey.GetLength() + 1) * sizeof(TCHAR);  // key length in bytes, including null terminator
	if (!m_strInputName.IsEmpty() && !m_strOutputName.IsEmpty())
	{
		// Encrypt the input file with RC4 and write the ciphertext to the output file
		if (EncryptFile(CALG_RC4, m_strOutputName, m_strInputName, lpszSecretKey, dwSecretKey))
		{
			MessageBox(_T("The file have been successfully encrypted!"), _T("Crypt Library Demo"), MB_OK);
		}
	}
}

/**
 * @brief Handles the "Decrypt" button click.
 *
 * Retrieves the machine-specific secret key via GetComputerID() and uses
 * EncryptFile() with the RC4 algorithm to decrypt the input file,
 * writing the result to the output file.
 */
void CCryptLibraryDemoDlg::OnBnClickedDecrypt()
{
	// Use the same machine-specific key that was used during encryption
	CString strSecretKey = GetComputerID();
	LPBYTE lpszSecretKey = (LPBYTE)(LPCTSTR)strSecretKey;  // raw byte pointer into the key string
	DWORD dwSecretKey = (strSecretKey.GetLength() + 1) * sizeof(TCHAR);  // key length in bytes, including null terminator
	if (!m_strInputName.IsEmpty() && !m_strOutputName.IsEmpty())
	{
		// RC4 is symmetric: applying EncryptFile again with the same key reverses the encryption
		if (EncryptFile(CALG_RC4, m_strOutputName, m_strInputName, lpszSecretKey, dwSecretKey))
		{
			MessageBox(_T("The file have been successfully decrypted!"), _T("Crypt Library Demo"), MB_OK);
		}
	}
}
