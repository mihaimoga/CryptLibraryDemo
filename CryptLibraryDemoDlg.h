/* This file is part of CryptLibraryDemo application developed by Stefan-Mihai MOGA.

CryptLibraryDemo is free software: you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the Open
Source Initiative, either version 3 of the License, or any later version.

CryptLibraryDemo is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with
CryptLibraryDemo. If not, see <http://www.opensource.org/licenses/gpl-3.0.html>*/

// CryptLibraryDemoDlg.h : header file
//

#pragma once
#include "afxwin.h"

///////////////////////////////////////////////////////////////////////////////
// CCryptLibraryDemoDlg dialog
///////////////////////////////////////////////////////////////////////////////

class CCryptLibraryDemoDlg : public CDialog
{
// Construction
public:
	CCryptLibraryDemoDlg(CWnd* pParent = NULL);	// standard constructor

// Dialog Data
	enum { IDD = IDD_CRYPTLIBRARYDEMO_DIALOG };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV support

// Implementation
public:
	// Generated message map functions
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
public:
	afx_msg void OnBnClickedSelect();
	afx_msg void OnBnClickedCompute();
	afx_msg void OnBnClickedInputfile();
	afx_msg void OnBnClickedOutputfile();
	afx_msg void OnBnClickedEncrypt();
	afx_msg void OnBnClickedDecrypt();

protected:
	HICON m_hIcon;
	CButton m_btnCompute;
	CButton m_btnEncrypt;
	CButton m_btnDecrypt;
	CEdit m_editFilename;
	CEdit m_editChecksum;
	CEdit m_editInputName;
	CEdit m_editOutputName;
	CString m_strFilename;
	CString m_strChecksum;
	CString m_strInputName;
	CString m_strOutputName;

	DECLARE_MESSAGE_MAP()
};
