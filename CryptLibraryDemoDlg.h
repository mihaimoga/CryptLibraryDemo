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

// CryptLibraryDemoDlg.h : header file
//

#pragma once
#include "afxwin.h"

///////////////////////////////////////////////////////////////////////////////
// CCryptLibraryDemoDlg dialog
///////////////////////////////////////////////////////////////////////////////

/**
 * @brief Main dialog class for the CryptLibraryDemo application.
 *
 * Provides a UI for computing MD5 checksums of files and for
 * encrypting / decrypting files using the RC4 algorithm via the
 * Windows CryptoAPI wrapper.
 */
class CCryptLibraryDemoDlg : public CDialog
{
// Construction
public:
	/**
	 * @brief Constructs the main dialog.
	 * @param pParent Optional pointer to the parent window. Defaults to NULL.
	 */
	CCryptLibraryDemoDlg(CWnd* pParent = NULL);	// standard constructor

// Dialog Data
	enum { IDD = IDD_CRYPTLIBRARYDEMO_DIALOG };

protected:
	/**
	 * @brief Performs dialog data exchange and validation.
	 * @param pDX Pointer to the CDataExchange object used for DDX/DDV.
	 */
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV support

// Implementation
public:
	// Generated message map functions
	/**
	 * @brief Called by the framework when the dialog is initialized.
	 * @return TRUE to set focus to the first control, FALSE if focus was set manually.
	 */
	virtual BOOL OnInitDialog();

	/**
	 * @brief Handles WM_SYSCOMMAND messages, dispatching About box and social-media links.
	 * @param nID  The system command identifier.
	 * @param lParam Additional message-specific data.
	 */
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);

	/**
	 * @brief Handles WM_PAINT; draws the application icon when the window is minimized.
	 */
	afx_msg void OnPaint();

	/**
	 * @brief Returns the cursor to display while the user drags the minimized window.
	 * @return Handle to the application icon cast as a cursor.
	 */
	afx_msg HCURSOR OnQueryDragIcon();

public:
	/**
	 * @brief Handles the "Select" button click; opens a file picker for checksum input.
	 */
	afx_msg void OnBnClickedSelect();

	/**
	 * @brief Handles the "Compute" button click; calculates and displays the MD5 checksum.
	 */
	afx_msg void OnBnClickedCompute();

	/**
	 * @brief Handles the "Input File" button click; opens a file picker for the encryption source.
	 */
	afx_msg void OnBnClickedInputfile();

	/**
	 * @brief Handles the "Output File" button click; opens a file picker for the encryption destination.
	 */
	afx_msg void OnBnClickedOutputfile();

	/**
	 * @brief Handles the "Encrypt" button click; encrypts the input file to the output file.
	 */
	afx_msg void OnBnClickedEncrypt();

	/**
	 * @brief Handles the "Decrypt" button click; decrypts the input file to the output file.
	 */
	afx_msg void OnBnClickedDecrypt();

protected:
	/** @brief Application icon handle used for the dialog's title bar and minimized state. */
	HICON m_hIcon;

	/** @brief "Compute" button control; enabled only when a file has been selected. */
	CButton m_btnCompute;

	/** @brief "Encrypt" button control; enabled when both input and output files are set. */
	CButton m_btnEncrypt;

	/** @brief "Decrypt" button control; enabled when both input and output files are set. */
	CButton m_btnDecrypt;

	/** @brief Edit control that displays the path of the file chosen for checksum computation. */
	CEdit m_editFilename;

	/** @brief Edit control that displays the computed MD5 checksum string. */
	CEdit m_editChecksum;

	/** @brief Edit control that displays the path of the encryption input file. */
	CEdit m_editInputName;

	/** @brief Edit control that displays the path of the encryption output file. */
	CEdit m_editOutputName;

	/** @brief Path of the file selected for checksum computation. */
	CString m_strFilename;

	/** @brief Computed MD5 checksum of the selected file. */
	CString m_strChecksum;

	/** @brief Path of the source file used for encryption or decryption. */
	CString m_strInputName;

	/** @brief Path of the destination file produced by encryption or decryption. */
	CString m_strOutputName;

	DECLARE_MESSAGE_MAP()
};
