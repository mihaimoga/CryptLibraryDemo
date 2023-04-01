/* This file is part of CryptLibraryDemo application developed by Stefan-Mihai MOGA.

CryptLibraryDemo is free software: you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the Open
Source Initiative, either version 3 of the License, or any later version.

CryptLibraryDemo is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with
CryptLibraryDemo. If not, see <http://www.opensource.org/licenses/gpl-3.0.html>*/

// CryptographyExt.h : Demo for Microsoft's Crypt Library functions.

#pragma once

#define CRYPT_LIBRARY_NAME _T("Crypt")
#define MD5CHECKSUM_LENGTH 0x10
#define SHA1CHECKSUM_LENGTH 0x14
#define MAX_STR_BUFFER 0x1000
#define MAX_CRYPT_TAIL 0x1000

// for CLongBinary
#include <afxdb_.h>
#include <WinCrypt.h>

void TraceLastError(LPCTSTR lpszLibrary, LPCTSTR lpszOperation, DWORD dwLastError);

CString GetComputerID();

BOOL ConvertHexaToBinary(LPBYTE lpszOutputBuffer, DWORD dwOutputLength, LPCTSTR lpszInputBuffer, DWORD dwInputLength);
BOOL ConvertHexaToBinary(CLongBinary* pTargetBinary, CLongBinary* pSourceBinary);

BOOL ConvertBinaryToHexa(LPTSTR lpszOutputBuffer, DWORD dwOutputLength, LPBYTE lpszInputBuffer, DWORD dwInputLength);
BOOL ConvertBinaryToHexa(CLongBinary* pTargetBinary, CLongBinary* pSourceBinary);

// recommended values for nAlgorithm are CALG_MD5 and CALG_SHA1
BOOL GetChecksumBuffer(ALG_ID nAlgorithm, LPBYTE lpszOutputBuffer, DWORD& dwOutputLength, LPBYTE lpszInputBuffer, DWORD dwInputLength);
BOOL GetChecksumString(ALG_ID nAlgorithm, CString& strResult, CString strBuffer);
BOOL GetChecksumFile(ALG_ID nAlgorithm, CString& strResult, CString strPathName);

// recommended values for nAlgorithm are CALG_RC4 and CALG_3DES
BOOL EncryptBuffer(ALG_ID nAlgorithm, LPBYTE lpszOutputBuffer, DWORD& dwOutputLength, LPBYTE lpszInputBuffer, DWORD dwInputLength, LPBYTE lpszSecretKey, DWORD dwSecretKey);
BOOL EncryptFile(ALG_ID nAlgorithm, CString strOutputName, CString strInputName, LPBYTE lpszSecretKey, DWORD dwSecretKey);
BOOL DecryptBuffer(ALG_ID nAlgorithm, LPBYTE lpszOutputBuffer, DWORD& dwOutputLength, LPBYTE lpszInputBuffer, DWORD dwInputLength, LPBYTE lpszSecretKey, DWORD dwSecretKey);
BOOL DecryptFile(ALG_ID nAlgorithm, CString strOutputName, CString strInputName, LPBYTE lpszSecretKey, DWORD dwSecretKey);
