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

// CryptographyExt.cpp : Demo for Microsoft's Crypt Library functions.

#include "stdafx.h"
#include "CryptographyExt.h"

#define SECURITY_WIN32
#include <Security.h>
#pragma comment(lib, "secur32")

#include <nb30.h>
#pragma comment(lib, "netapi32")

#include <wincrypt.h>
#pragma comment(lib, "crypt32")
#pragma comment(lib, "advapi32")

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

/**
 * @brief Outputs the last error from a Windows API call to the debug output.
 * @param lpszLibrary The name of the library where the error occurred.
 * @param lpszOperation The operation that failed.
 * @param dwLastError The error code returned by GetLastError().
 */
void TraceLastError(LPCTSTR lpszLibrary, LPCTSTR lpszOperation, DWORD dwLastError)
{
	// Display a message and the last error in the TRACE. 
	LPVOID lpszErrorBuffer = nullptr;
	CString	strLastError;

	::FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER | 
		FORMAT_MESSAGE_FROM_SYSTEM | 
		FORMAT_MESSAGE_IGNORE_INSERTS,
		nullptr,
		dwLastError,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR) &lpszErrorBuffer,
		0,
		nullptr);

	strLastError.Format(_T("[%s] %s: %s\n"), lpszLibrary, lpszOperation, (LPTSTR)lpszErrorBuffer);

	// free alocated buffer by FormatMessage
	LocalFree(lpszErrorBuffer); 

	// Display the last error.
	OutputDebugString(strLastError);
}

/**
 * @brief Retrieves a string identifying the current user and computer.
 * @return A string in the format "UserName:ComputerName".
 */
CString GetComputerID()
{
	CString strComputerID;
	// Attempt to get the user principal name, fallback to regular username and computer name.
	DWORD nLength = 0x100;
	TCHAR lpszUserName[0x100] = { 0, };
	if (GetUserNameEx(NameUserPrincipal, lpszUserName, &nLength))
	{
		lpszUserName[nLength] = 0;
		TRACE(_T("UserName = %s\n"), lpszUserName);
	}
	else
	{
		nLength = 0x100;
		if (GetUserName(lpszUserName, &nLength) != 0)
		{
			lpszUserName[nLength] = 0;
			TRACE(_T("UserName = %s\n"), lpszUserName);
		}
	}

	nLength = 0x100;
	TCHAR lpszComputerName[0x100] = { 0, };
	if (GetComputerNameEx(ComputerNamePhysicalDnsFullyQualified, lpszComputerName, &nLength))
	{
		lpszComputerName[nLength] = 0;
		TRACE(_T("ComputerName = %s\n"), lpszComputerName);
	}
	else
	{
		nLength = 0x100;
		if (GetComputerName(lpszComputerName, &nLength) != 0)
		{
			lpszComputerName[nLength] = 0;
			TRACE(_T("ComputerName = %s\n"), lpszComputerName);
		}
	}

	strComputerID = lpszUserName;
	strComputerID += _T(":");
	strComputerID += lpszComputerName;
	return strComputerID;
}

/**
 * @brief Converts a hexadecimal string stored in a CLongBinary to binary data.
 * @param pTargetBinary Output binary data.
 * @param pSourceBinary Input hexadecimal string data.
 * @return true if conversion succeeded, false otherwise.
 */
bool ConvertHexaToBinary(CLongBinary* pTargetBinary, CLongBinary* pSourceBinary)
{
	BYTE nDataValue;
	UINT nDataIndex;
	TCHAR chUpperNibble;
	TCHAR chLowerNibble;

	const CString strHexaDigit = _T("0123456789ABCDEF");

	if (!pTargetBinary || !pSourceBinary)
		return false;

	pTargetBinary->m_hData = nullptr;
	pTargetBinary->m_dwDataLength = pSourceBinary->m_dwDataLength / 2 / sizeof(TCHAR);

	if (!pSourceBinary->m_dwDataLength)
		return true;

	pTargetBinary->m_hData = GlobalAlloc(GPTR, pTargetBinary->m_dwDataLength + sizeof(BYTE));
	if (pTargetBinary->m_hData != nullptr)
	{
		TCHAR* pSourceArray = (TCHAR*)GlobalLock(pSourceBinary->m_hData);
		BYTE* pTargetArray = (BYTE*)GlobalLock(pTargetBinary->m_hData);
		if ((pSourceArray != nullptr) && (pTargetArray != nullptr))
		{
			for (UINT nIndex = 0; nIndex < pTargetBinary->m_dwDataLength; nIndex++)
			{
				nDataIndex = nIndex << 1; // multiply be two

				chUpperNibble = pSourceArray[nDataIndex];
				ASSERT(strHexaDigit.Find(chUpperNibble) != -1);
				nDataValue = (BYTE)(strHexaDigit.Find(chUpperNibble) * 0x10);

				chLowerNibble = pSourceArray[nDataIndex + 1];
				ASSERT(strHexaDigit.Find(chLowerNibble) != -1);
				nDataValue = (BYTE)(nDataValue + strHexaDigit.Find(chLowerNibble));

				pTargetArray[nIndex] = nDataValue;
			}

			VERIFY(GlobalUnlock(pTargetBinary->m_hData));
			VERIFY(GlobalUnlock(pSourceBinary->m_hData));

			return true;
		}
	}

	return false;
}

/**
 * @brief Converts a hexadecimal string buffer to binary data.
 * @param lpszOutputBuffer Output binary buffer.
 * @param dwOutputLength Length of output buffer.
 * @param lpszInputBuffer Input hexadecimal string buffer.
 * @param dwInputLength Length of input buffer.
 * @return true if conversion succeeded, false otherwise.
 */
bool ConvertHexaToBinary(LPBYTE lpszOutputBuffer, DWORD dwOutputLength, LPCTSTR lpszInputBuffer, DWORD dwInputLength)
{
	ASSERT(lpszOutputBuffer != nullptr);
	ASSERT(lpszInputBuffer != nullptr);
	ASSERT(dwInputLength <= (2 * dwOutputLength));

	BYTE nDataValue;
	UINT nDataIndex;
	TCHAR chUpperNibble;
	TCHAR chLowerNibble;

	const CString strHexaDigit = _T("0123456789ABCDEF");

	for (UINT nIndex = 0; nIndex < dwInputLength / 2; nIndex++)
	{
		nDataIndex = nIndex << 1; // multiply be two

		chUpperNibble = lpszInputBuffer[nDataIndex];
		ASSERT(strHexaDigit.Find(chUpperNibble) != -1);
		nDataValue = (BYTE)(strHexaDigit.Find(chUpperNibble) * 0x10);

		chLowerNibble = lpszInputBuffer[nDataIndex + 1];
		ASSERT(strHexaDigit.Find(chLowerNibble) != -1);
		nDataValue = (BYTE)(nDataValue + strHexaDigit.Find(chLowerNibble));

		lpszOutputBuffer[nIndex] = nDataValue;
	}

	return true;
}

/**
 * @brief Converts binary data in a CLongBinary to a hexadecimal string.
 * @param pTargetBinary Output hexadecimal string.
 * @param pSourceBinary Input binary data.
 * @return true if conversion succeeded, false otherwise.
 */
bool ConvertBinaryToHexa(CLongBinary* pTargetBinary, CLongBinary* pSourceBinary)
{
	BYTE nDataValue;
	UINT nDataIndex;

	const CString strHexaDigit = _T("0123456789ABCDEF");

	if (!pTargetBinary || !pSourceBinary)
		return false;

	pTargetBinary->m_hData = nullptr;
	pTargetBinary->m_dwDataLength = pSourceBinary->m_dwDataLength * 2 * sizeof(TCHAR);

	if (!pSourceBinary->m_dwDataLength)
		return true;

	pTargetBinary->m_hData = GlobalAlloc(GPTR, pTargetBinary->m_dwDataLength + sizeof(TCHAR));
	if (pTargetBinary->m_hData != nullptr)
	{
		BYTE* pSourceArray = (BYTE*)GlobalLock(pSourceBinary->m_hData);
		TCHAR* pTargetArray = (TCHAR*)GlobalLock(pTargetBinary->m_hData);
		if ((pSourceArray != nullptr) && (pTargetArray != nullptr))
		{

			for (UINT nIndex = 0; nIndex < pSourceBinary->m_dwDataLength; nIndex++)
			{
				nDataIndex = nIndex << 1;  // multiply be two
				nDataValue = pSourceArray[nIndex];

				pTargetArray[nDataIndex] = strHexaDigit.GetAt((nDataValue & 0xFF) / 0x10);

				pTargetArray[nDataIndex + 1] = strHexaDigit.GetAt((nDataValue & 0xFF) % 0x10);
			}

			VERIFY(GlobalUnlock(pTargetBinary->m_hData));
			VERIFY(GlobalUnlock(pSourceBinary->m_hData));

			return true;
		}
	}

	return false;
}

/**
 * @brief Converts binary data to a hexadecimal string buffer.
 * @param lpszOutputBuffer Output hexadecimal string buffer.
 * @param dwOutputLength Length of output buffer.
 * @param lpszInputBuffer Input binary buffer.
 * @param dwInputLength Length of input buffer.
 * @return true if conversion succeeded, false otherwise.
 */
bool ConvertBinaryToHexa(LPTSTR lpszOutputBuffer, DWORD dwOutputLength, LPBYTE lpszInputBuffer, DWORD dwInputLength)
{
	ASSERT(lpszOutputBuffer != nullptr);
	ASSERT(lpszInputBuffer != nullptr);
	ASSERT(dwOutputLength >= (2 * dwInputLength));

	BYTE nDataValue;
	UINT nDataIndex;

	const CString strHexaDigit = _T("0123456789ABCDEF");

	for (UINT nIndex = 0; nIndex < dwInputLength; nIndex++)
	{
		nDataIndex = nIndex << 1;  // multiply be two
		nDataValue = lpszInputBuffer[nIndex];

		lpszOutputBuffer[nDataIndex] = strHexaDigit.GetAt((nDataValue & 0xFF) / 0x10);

		lpszOutputBuffer[nDataIndex + 1] = strHexaDigit.GetAt((nDataValue & 0xFF) % 0x10);
	}

	lpszOutputBuffer[2 * dwInputLength] = _T('\0');

	return true;
}

/**
 * @brief Computes a cryptographic hash (checksum) of a buffer.
 * @param nAlgorithm Hash algorithm identifier (e.g., CALG_MD5, CALG_SHA1).
 * @param lpszOutputBuffer Output buffer for the hash.
 * @param dwOutputLength [in/out] On input, size of output buffer; on output, actual hash size.
 * @param lpszInputBuffer Input buffer to hash.
 * @param dwInputLength Length of input buffer.
 * @return true if hash computation succeeded, false otherwise.
 */
bool GetChecksumBuffer(ALG_ID nAlgorithm, LPBYTE lpszOutputBuffer, DWORD& dwOutputLength, LPBYTE lpszInputBuffer, DWORD dwInputLength)
{
	bool retVal = false;

	ASSERT(lpszOutputBuffer != nullptr);
	ASSERT(dwOutputLength != 0);
	ASSERT(lpszInputBuffer != nullptr);
	ASSERT(dwInputLength != 0);

	HCRYPTPROV hCryptProv = NULL;
	HCRYPTHASH hCryptHash = NULL;

	if (CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
	{
		if (CryptCreateHash(hCryptProv, nAlgorithm, NULL, 0, &hCryptHash))
		{
			if (CryptHashData(hCryptHash, lpszInputBuffer, dwInputLength, 0))
			{
				if (CryptGetHashParam(hCryptHash, HP_HASHVAL, lpszOutputBuffer, &dwOutputLength, 0))
				{
					retVal = true;
				}
				else
				{
					TraceLastError(CRYPT_LIBRARY_NAME, _T("CryptGetHashParam"), GetLastError());
				}
			}
			else
			{
				TraceLastError(CRYPT_LIBRARY_NAME, _T("CryptHashData"), GetLastError());
			}
			VERIFY(CryptDestroyHash(hCryptHash));
		}
		else
		{
			TraceLastError(CRYPT_LIBRARY_NAME, _T("CryptCreateHash"), GetLastError());
		}
		VERIFY(CryptReleaseContext(hCryptProv, 0));
	}
	else
	{
		TraceLastError(CRYPT_LIBRARY_NAME, _T("CryptAcquireContext"), GetLastError());
	}

	return retVal;
}

/**
 * @brief Computes a cryptographic hash (checksum) of a string and returns it as a hexadecimal string.
 * @param nAlgorithm Hash algorithm identifier (e.g., CALG_MD5, CALG_SHA1).
 * @param strResult Output string containing the checksum in hexadecimal.
 * @param strBuffer Input string to hash.
 * @return true if hash computation succeeded, false otherwise.
 */
bool GetChecksumString(ALG_ID nAlgorithm, CString& strResult, CString strBuffer)
{
	bool retVal = false;
	const int nChecksumLength = ((CALG_MD5 == nAlgorithm) ? MD5CHECKSUM_LENGTH : SHA1CHECKSUM_LENGTH);

	DWORD dwOutput = nChecksumLength;
	BYTE* lpszOutput = new BYTE[nChecksumLength];

	const DWORD dwInput = (strBuffer.GetLength() + 1) * sizeof(TCHAR);
	BYTE* lpszInput = new BYTE[dwInput];
	::CopyMemory(lpszInput, strBuffer.GetBuffer(), dwInput);
	strBuffer.ReleaseBuffer();

	if (GetChecksumBuffer(nAlgorithm, lpszOutput, dwOutput, lpszInput, dwInput))
	{
		LPTSTR lpszString = strResult.GetBufferSetLength(2 * nChecksumLength + 1);
		if (ConvertBinaryToHexa(lpszString, 2 * nChecksumLength + 1, lpszOutput, dwOutput))
		{
			strResult.ReleaseBuffer();
			retVal = true;
		}
	}

	if (lpszInput != nullptr)
	{
		delete []lpszInput;
		lpszInput = nullptr;
	}

	if (lpszOutput != nullptr)
	{
		delete []lpszOutput;
		lpszOutput = nullptr;
	}

	return retVal;
}

/**
 * @brief Computes a cryptographic hash (checksum) of a file and returns it as a hexadecimal string.
 * @param nAlgorithm Hash algorithm identifier (e.g., CALG_MD5, CALG_SHA1).
 * @param strResult Output string containing the checksum in hexadecimal.
 * @param strPathName Path to the file to hash.
 * @return true if hash computation succeeded, false otherwise.
 */
bool GetChecksumFile(ALG_ID nAlgorithm, CString& strResult, CString strPathName)
{
	bool retVal = false;
	const int nChecksumLength = ((CALG_MD5 == nAlgorithm) ? MD5CHECKSUM_LENGTH : SHA1CHECKSUM_LENGTH);

	DWORD dwOutput = nChecksumLength;
	BYTE* lpszOutput = new BYTE[nChecksumLength];

	BYTE* lpszInput = nullptr;
	try
	{
		CFile pInputFile(strPathName, CFile::modeRead | CFile::typeBinary);
		const UINT dwInput = (UINT)pInputFile.GetLength();
		if (dwInput > 0)
		{
			lpszInput = new BYTE[dwInput];
			if (dwInput == pInputFile.Read(lpszInput, dwInput))
			{
				if (GetChecksumBuffer(nAlgorithm, lpszOutput, dwOutput, lpszInput, dwInput))
				{
					LPTSTR lpszString = strResult.GetBufferSetLength(2 * nChecksumLength + 1);
					if (ConvertBinaryToHexa(lpszString, 2 * nChecksumLength + 1, lpszOutput, dwOutput))
					{
						strResult.ReleaseBuffer();
						retVal = true;
					}
				}
			}
		}
		pInputFile.Close();
	}
	catch (CFileException * pFileException)
	{
		TCHAR lpszError[MAX_STR_BUFFER] = { 0 };
		pFileException->GetErrorMessage(lpszError, MAX_STR_BUFFER);
		pFileException->Delete();
		OutputDebugString(lpszError);
		retVal = false;
	}

	if (lpszInput != nullptr)
	{
		delete []lpszInput;
		lpszInput = nullptr;
	}

	if (lpszOutput != nullptr)
	{
		delete []lpszOutput;
		lpszOutput = nullptr;
	}

	return retVal;
}

/**
 * @brief Encrypts a buffer using a specified algorithm and secret key.
 * @param nAlgorithm Encryption algorithm identifier (e.g., CALG_RC4).
 * @param lpszOutputBuffer Output buffer for encrypted data.
 * @param dwOutputLength [in/out] On input, size of output buffer; on output, actual encrypted size.
 * @param lpszInputBuffer Input buffer to encrypt.
 * @param dwInputLength Length of input buffer.
 * @param lpszSecretKey Secret key buffer.
 * @param dwSecretKey Length of secret key.
 * @return true if encryption succeeded, false otherwise.
 */
bool EncryptBuffer(ALG_ID nAlgorithm, LPBYTE lpszOutputBuffer, DWORD& dwOutputLength, LPBYTE lpszInputBuffer, DWORD dwInputLength, LPBYTE lpszSecretKey, DWORD dwSecretKey)
{
	bool retVal = false;
	DWORD dwHowManyBytes = dwInputLength;

	ASSERT(lpszOutputBuffer != nullptr);
	ASSERT(dwOutputLength != 0);
	ASSERT(lpszInputBuffer != nullptr);
	ASSERT(dwInputLength != 0);
	ASSERT(lpszSecretKey != nullptr);
	ASSERT(dwSecretKey != 0);

	HCRYPTPROV hCryptProv = NULL;
	HCRYPTHASH hCryptHash = NULL;
	HCRYPTKEY hCryptKey = NULL;

	::CopyMemory(lpszOutputBuffer, lpszInputBuffer, dwHowManyBytes);

	if (CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
	{
		if (CryptCreateHash(hCryptProv, CALG_MD5, NULL, 0, &hCryptHash))
		{
			if (CryptHashData(hCryptHash, lpszSecretKey, dwSecretKey, 0))
			{
				if (CryptDeriveKey(hCryptProv, nAlgorithm, hCryptHash, CRYPT_EXPORTABLE, &hCryptKey))
				{
					if (CryptEncrypt(hCryptKey, NULL, true, 0, lpszOutputBuffer, &dwHowManyBytes, dwOutputLength))
					{
						dwOutputLength = dwHowManyBytes;
						retVal = true;
					}
					else
					{
						TraceLastError(CRYPT_LIBRARY_NAME, _T("CryptEncrypt"), GetLastError());
					}
					VERIFY(CryptDestroyKey(hCryptKey));
				}
				else
				{
					TraceLastError(CRYPT_LIBRARY_NAME, _T("CryptDeriveKey"), GetLastError());
				}
			}
			else
			{
				TraceLastError(CRYPT_LIBRARY_NAME, _T("CryptHashData"), GetLastError());
			}
			VERIFY(CryptDestroyHash(hCryptHash));
		}
		else
		{
			TraceLastError(CRYPT_LIBRARY_NAME, _T("CryptCreateHash"), GetLastError());
		}
		VERIFY(CryptReleaseContext(hCryptProv, 0));
	}
	else
	{
		TraceLastError(CRYPT_LIBRARY_NAME, _T("CryptAcquireContext"), GetLastError());
	}

	return retVal;
}

/**
 * @brief Encrypts a file using a specified algorithm and secret key.
 * @param nAlgorithm Encryption algorithm identifier (e.g., CALG_RC4).
 * @param strOutputName Output file path.
 * @param strInputName Input file path.
 * @param lpszSecretKey Secret key buffer.
 * @param dwSecretKey Length of secret key.
 * @return true if encryption succeeded, false otherwise.
 */
bool EncryptFile(ALG_ID nAlgorithm, CString strOutputName, CString strInputName, LPBYTE lpszSecretKey, DWORD dwSecretKey)
{
	bool retVal = false;

	BYTE* lpszOutput = nullptr;
	BYTE* lpszInput = nullptr;
	try
	{
		CFile pInputFile(strInputName, CFile::modeRead | CFile::typeBinary);
		const UINT dwInput = (UINT)pInputFile.GetLength();
		if (dwInput > 0)
		{
			lpszInput = new BYTE[dwInput];
			if (dwInput == pInputFile.Read(lpszInput, dwInput))
			{
				DWORD dwOutput = dwInput + MAX_CRYPT_TAIL;
				lpszOutput = new BYTE[dwOutput];
				if (EncryptBuffer(nAlgorithm, lpszOutput, dwOutput, lpszInput, dwInput, lpszSecretKey, dwSecretKey))
				{
					CFile pOutputFile(strOutputName, CFile::modeCreate | CFile::modeWrite | CFile::typeBinary);
					pOutputFile.Write(lpszOutput, dwOutput);
					pOutputFile.Close();
					retVal = true;
				}
			}
		}
		pInputFile.Close();
	}
	catch (CFileException * pFileException)
	{
		TCHAR lpszError[MAX_STR_BUFFER] = { 0 };
		pFileException->GetErrorMessage(lpszError, MAX_STR_BUFFER);
		pFileException->Delete();
		OutputDebugString(lpszError);
		retVal = false;
	}

	if (lpszInput != nullptr)
	{
		delete []lpszInput;
		lpszInput = nullptr;
	}

	if (lpszOutput != nullptr)
	{
		delete []lpszOutput;
		lpszOutput = nullptr;
	}

	return retVal;
}

/**
 * @brief Decrypts a buffer using a specified algorithm and secret key.
 * @param nAlgorithm Decryption algorithm identifier (e.g., CALG_RC4).
 * @param lpszOutputBuffer Output buffer for decrypted data.
 * @param dwOutputLength [in/out] On input, size of output buffer; on output, actual decrypted size.
 * @param lpszInputBuffer Input buffer to decrypt.
 * @param dwInputLength Length of input buffer.
 * @param lpszSecretKey Secret key buffer.
 * @param dwSecretKey Length of secret key.
 * @return true if decryption succeeded, false otherwise.
 */
bool DecryptBuffer(ALG_ID nAlgorithm, LPBYTE lpszOutputBuffer, DWORD& dwOutputLength, LPBYTE lpszInputBuffer, DWORD dwInputLength, LPBYTE lpszSecretKey, DWORD dwSecretKey)
{
	bool retVal = false;
	DWORD dwHowManyBytes = dwInputLength;

	ASSERT(lpszOutputBuffer != nullptr);
	ASSERT(dwOutputLength != 0);
	ASSERT(lpszInputBuffer != nullptr);
	ASSERT(dwInputLength != 0);
	ASSERT(lpszSecretKey != nullptr);
	ASSERT(dwSecretKey != 0);

	HCRYPTPROV hCryptProv = NULL;
	HCRYPTHASH hCryptHash = NULL;
	HCRYPTKEY hCryptKey = NULL;

	::CopyMemory(lpszOutputBuffer, lpszInputBuffer, dwHowManyBytes);

	if (CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
	{
		if (CryptCreateHash(hCryptProv, CALG_MD5, NULL, 0, &hCryptHash))
		{
			if (CryptHashData(hCryptHash, lpszSecretKey, dwSecretKey, 0))
			{
				if (CryptDeriveKey(hCryptProv, nAlgorithm, hCryptHash, CRYPT_EXPORTABLE, &hCryptKey))
				{
					if (CryptDecrypt(hCryptKey, NULL, true, 0, lpszOutputBuffer, &dwHowManyBytes))
					{
						dwOutputLength = dwHowManyBytes;
						retVal = true;
					}
					else
					{
						TraceLastError(CRYPT_LIBRARY_NAME, _T("CryptDecrypt"), GetLastError());
					}
					VERIFY(CryptDestroyKey(hCryptKey));
				}
				else
				{
					TraceLastError(CRYPT_LIBRARY_NAME, _T("CryptDeriveKey"), GetLastError());
				}
			}
			else
			{
				TraceLastError(CRYPT_LIBRARY_NAME, _T("CryptHashData"), GetLastError());
			}
			VERIFY(CryptDestroyHash(hCryptHash));
		}
		else
		{
			TraceLastError(CRYPT_LIBRARY_NAME, _T("CryptCreateHash"), GetLastError());
		}
		VERIFY(CryptReleaseContext(hCryptProv, 0));
	}
	else
	{
		TraceLastError(CRYPT_LIBRARY_NAME, _T("CryptAcquireContext"), GetLastError());
	}

	return retVal;
}

/**
 * @brief Decrypts a file using a specified algorithm and secret key.
 * @param nAlgorithm Decryption algorithm identifier (e.g., CALG_RC4).
 * @param strOutputName Output file path.
 * @param strInputName Input file path.
 * @param lpszSecretKey Secret key buffer.
 * @param dwSecretKey Length of secret key.
 * @return true if decryption succeeded, false otherwise.
 */
bool DecryptFile(ALG_ID nAlgorithm, CString strOutputName, CString strInputName, LPBYTE lpszSecretKey, DWORD dwSecretKey)
{
	bool retVal = false;

	BYTE* lpszOutput = nullptr;
	BYTE* lpszInput = nullptr;
	try
	{
		CFile pInputFile(strInputName, CFile::modeRead | CFile::typeBinary);
		const UINT dwInput = (UINT)pInputFile.GetLength();
		if (dwInput > 0)
		{
			lpszInput = new BYTE[dwInput];
			if (dwInput == pInputFile.Read(lpszInput, dwInput))
			{
				DWORD dwOutput = dwInput + MAX_CRYPT_TAIL;
				lpszOutput = new BYTE[dwOutput];
				if (DecryptBuffer(nAlgorithm, lpszOutput, dwOutput, lpszInput, dwInput, lpszSecretKey, dwSecretKey))
				{
					CFile pOutputFile(strOutputName, CFile::modeCreate | CFile::modeWrite | CFile::typeBinary);
					pOutputFile.Write(lpszOutput, dwOutput);
					pOutputFile.Close();
					retVal = true;
				}
			}
		}
		pInputFile.Close();
	}
	catch (CFileException * pFileException)
	{
		TCHAR lpszError[MAX_STR_BUFFER] = { 0 };
		pFileException->GetErrorMessage(lpszError, MAX_STR_BUFFER);
		pFileException->Delete();
		OutputDebugString(lpszError);
		retVal = false;
	}

	if (lpszInput != nullptr)
	{
		delete []lpszInput;
		lpszInput = nullptr;
	}

	if (lpszOutput != nullptr)
	{
		delete []lpszOutput;
		lpszOutput = nullptr;
	}

	return retVal;
}
