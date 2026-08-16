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

	// Convert the numeric error code into a human-readable string.
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

	// Build a formatted string: "[Library] Operation: error message"
	strLastError.Format(_T("[%s] %s: %s\n"), lpszLibrary, lpszOperation, (LPTSTR)lpszErrorBuffer);

	// Free the buffer allocated by FormatMessage.
	LocalFree(lpszErrorBuffer); 

	// Write the error message to the debug output stream.
	OutputDebugString(strLastError);
}

/**
 * @brief Retrieves a string identifying the current user and computer.
 * @return A string in the format "UserName:ComputerName".
 */
CString GetComputerID()
{
	CString strComputerID;
	// Attempt to get the user principal name (e.g. user@domain); fall back to the
	// simple SAM account name if the principal name is unavailable.
	DWORD nLength = 0x100;
	TCHAR lpszUserName[0x100] = { 0, };
	if (GetUserNameEx(NameUserPrincipal, lpszUserName, &nLength))
	{
		lpszUserName[nLength] = 0;
		TRACE(_T("UserName = %s\n"), lpszUserName);
	}
	else
	{
		// NameUserPrincipal failed; fall back to the flat user name.
		nLength = 0x100;
		if (GetUserName(lpszUserName, &nLength) != 0)
		{
			lpszUserName[nLength] = 0;
			TRACE(_T("UserName = %s\n"), lpszUserName);
		}
	}

	// Attempt to get the fully-qualified DNS name; fall back to the NetBIOS name.
	nLength = 0x100;
	TCHAR lpszComputerName[0x100] = { 0, };
	if (GetComputerNameEx(ComputerNamePhysicalDnsFullyQualified, lpszComputerName, &nLength))
	{
		lpszComputerName[nLength] = 0;
		TRACE(_T("ComputerName = %s\n"), lpszComputerName);
	}
	else
	{
		// Fully-qualified DNS name unavailable; use the flat NetBIOS computer name.
		nLength = 0x100;
		if (GetComputerName(lpszComputerName, &nLength) != 0)
		{
			lpszComputerName[nLength] = 0;
			TRACE(_T("ComputerName = %s\n"), lpszComputerName);
		}
	}

	// Combine user and computer names into a single colon-separated identifier.
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

	// Lookup table for valid hexadecimal characters (uppercase).
	const CString strHexaDigit = _T("0123456789ABCDEF");

	// Validate input pointers.
	if (!pTargetBinary || !pSourceBinary)
		return false;

	pTargetBinary->m_hData = nullptr;
	// Each binary byte is represented by two hex characters (TCHAR-wide), so divide by 2*sizeof(TCHAR).
	pTargetBinary->m_dwDataLength = pSourceBinary->m_dwDataLength / 2 / sizeof(TCHAR);

	// Nothing to convert if source is empty.
	if (!pSourceBinary->m_dwDataLength)
		return true;

	// Allocate global memory for the output binary data (+1 byte for safety).
	pTargetBinary->m_hData = GlobalAlloc(GPTR, pTargetBinary->m_dwDataLength + sizeof(BYTE));
	if (pTargetBinary->m_hData != nullptr)
	{
		// Lock both global handles to obtain raw pointers.
		TCHAR* pSourceArray = (TCHAR*)GlobalLock(pSourceBinary->m_hData);
		BYTE* pTargetArray = (BYTE*)GlobalLock(pTargetBinary->m_hData);
		if ((pSourceArray != nullptr) && (pTargetArray != nullptr))
		{
			for (UINT nIndex = 0; nIndex < pTargetBinary->m_dwDataLength; nIndex++)
			{
				nDataIndex = nIndex << 1; // each output byte occupies two input characters

				// Extract and validate the high nibble character.
				chUpperNibble = pSourceArray[nDataIndex];
				ASSERT(strHexaDigit.Find(chUpperNibble) != -1);
				nDataValue = (BYTE)(strHexaDigit.Find(chUpperNibble) * 0x10); // shift into high nibble

				// Extract and validate the low nibble character.
				chLowerNibble = pSourceArray[nDataIndex + 1];
				ASSERT(strHexaDigit.Find(chLowerNibble) != -1);
				nDataValue = (BYTE)(nDataValue + strHexaDigit.Find(chLowerNibble)); // combine nibbles

				pTargetArray[nIndex] = nDataValue;
			}

			// Unlock both global memory handles before returning.
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
	// The hex string must be no longer than twice the output buffer size.
	ASSERT(dwInputLength <= (2 * dwOutputLength));

	BYTE nDataValue;
	UINT nDataIndex;
	TCHAR chUpperNibble;
	TCHAR chLowerNibble;

	// Lookup table for valid hexadecimal characters (uppercase).
	const CString strHexaDigit = _T("0123456789ABCDEF");

	// Iterate over each output byte; two input characters produce one output byte.
	for (UINT nIndex = 0; nIndex < dwInputLength / 2; nIndex++)
	{
		nDataIndex = nIndex << 1; // each output byte occupies two input characters

		// Decode the high nibble.
		chUpperNibble = lpszInputBuffer[nDataIndex];
		ASSERT(strHexaDigit.Find(chUpperNibble) != -1);
		nDataValue = (BYTE)(strHexaDigit.Find(chUpperNibble) * 0x10); // shift into high nibble

		// Decode the low nibble and combine with the high nibble.
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

	// Lookup table for mapping a nibble value (0-15) to its hex character.
	const CString strHexaDigit = _T("0123456789ABCDEF");

	// Validate input pointers.
	if (!pTargetBinary || !pSourceBinary)
		return false;

	pTargetBinary->m_hData = nullptr;
	// Each source byte expands to two TCHAR hex characters.
	pTargetBinary->m_dwDataLength = pSourceBinary->m_dwDataLength * 2 * sizeof(TCHAR);

	// Nothing to convert if source is empty.
	if (!pSourceBinary->m_dwDataLength)
		return true;

	// Allocate global memory for the hex string (+1 TCHAR for the null terminator).
	pTargetBinary->m_hData = GlobalAlloc(GPTR, pTargetBinary->m_dwDataLength + sizeof(TCHAR));
	if (pTargetBinary->m_hData != nullptr)
	{
		// Lock both global handles to obtain raw pointers.
		BYTE* pSourceArray = (BYTE*)GlobalLock(pSourceBinary->m_hData);
		TCHAR* pTargetArray = (TCHAR*)GlobalLock(pTargetBinary->m_hData);
		if ((pSourceArray != nullptr) && (pTargetArray != nullptr))
		{
			for (UINT nIndex = 0; nIndex < pSourceBinary->m_dwDataLength; nIndex++)
			{
				nDataIndex = nIndex << 1;  // each input byte produces two output characters
				nDataValue = pSourceArray[nIndex];

				// Write the high nibble character.
				pTargetArray[nDataIndex] = strHexaDigit.GetAt((nDataValue & 0xFF) / 0x10);
				// Write the low nibble character.
				pTargetArray[nDataIndex + 1] = strHexaDigit.GetAt((nDataValue & 0xFF) % 0x10);
			}

			// Unlock both global memory handles before returning.
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
	// Output buffer must hold at least 2 characters per input byte.
	ASSERT(dwOutputLength >= (2 * dwInputLength));

	BYTE nDataValue;
	UINT nDataIndex;

	// Lookup table for mapping a nibble value (0-15) to its hex character.
	const CString strHexaDigit = _T("0123456789ABCDEF");

	// Convert each input byte into two hexadecimal output characters.
	for (UINT nIndex = 0; nIndex < dwInputLength; nIndex++)
	{
		nDataIndex = nIndex << 1;  // each input byte produces two output characters
		nDataValue = lpszInputBuffer[nIndex];

		// Write the high nibble character.
		lpszOutputBuffer[nDataIndex] = strHexaDigit.GetAt((nDataValue & 0xFF) / 0x10);
		// Write the low nibble character.
		lpszOutputBuffer[nDataIndex + 1] = strHexaDigit.GetAt((nDataValue & 0xFF) % 0x10);
	}

	// Null-terminate the output hex string.
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

	// Acquire a handle to the default RSA cryptographic provider (verification context only).
	if (CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
	{
		// Create a hash object for the requested algorithm (e.g. CALG_MD5 or CALG_SHA1).
		if (CryptCreateHash(hCryptProv, nAlgorithm, NULL, 0, &hCryptHash))
		{
			// Feed the input buffer into the hash object.
			if (CryptHashData(hCryptHash, lpszInputBuffer, dwInputLength, 0))
			{
				// Retrieve the computed hash value into the caller-supplied output buffer.
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
			// Release the hash object regardless of success or failure.
			VERIFY(CryptDestroyHash(hCryptHash));
		}
		else
		{
			TraceLastError(CRYPT_LIBRARY_NAME, _T("CryptCreateHash"), GetLastError());
		}
		// Release the cryptographic provider context.
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
	// Determine the expected hash size based on the algorithm.
	const int nChecksumLength = ((CALG_MD5 == nAlgorithm) ? MD5CHECKSUM_LENGTH : SHA1CHECKSUM_LENGTH);

	// Allocate a buffer to receive the raw binary hash.
	DWORD dwOutput = nChecksumLength;
	BYTE* lpszOutput = new BYTE[nChecksumLength];

	// Copy the input string (including null terminator) into a byte buffer for hashing.
	const DWORD dwInput = (strBuffer.GetLength() + 1) * sizeof(TCHAR);
	BYTE* lpszInput = new BYTE[dwInput];
	::CopyMemory(lpszInput, strBuffer.GetBuffer(), dwInput);
	strBuffer.ReleaseBuffer();

	// Compute the hash over the raw bytes of the string.
	if (GetChecksumBuffer(nAlgorithm, lpszOutput, dwOutput, lpszInput, dwInput))
	{
		// Convert the binary hash to a printable hexadecimal string.
		LPTSTR lpszString = strResult.GetBufferSetLength(2 * nChecksumLength + 1);
		if (ConvertBinaryToHexa(lpszString, 2 * nChecksumLength + 1, lpszOutput, dwOutput))
		{
			strResult.ReleaseBuffer();
			retVal = true;
		}
	}

	// Free temporary input buffer.
	if (lpszInput != nullptr)
	{
		delete []lpszInput;
		lpszInput = nullptr;
	}

	// Free temporary output buffer.
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
	// Determine the expected hash size based on the algorithm.
	const int nChecksumLength = ((CALG_MD5 == nAlgorithm) ? MD5CHECKSUM_LENGTH : SHA1CHECKSUM_LENGTH);

	// Allocate a buffer to receive the raw binary hash.
	DWORD dwOutput = nChecksumLength;
	BYTE* lpszOutput = new BYTE[nChecksumLength];

	BYTE* lpszInput = nullptr;
	try
	{
		// Open the file in binary read mode.
		CFile pInputFile(strPathName, CFile::modeRead | CFile::typeBinary);
		const UINT dwInput = (UINT)pInputFile.GetLength();
		if (dwInput > 0)
		{
			// Read the entire file into memory.
			lpszInput = new BYTE[dwInput];
			if (dwInput == pInputFile.Read(lpszInput, dwInput))
			{
				// Compute the hash over the file contents.
				if (GetChecksumBuffer(nAlgorithm, lpszOutput, dwOutput, lpszInput, dwInput))
				{
					// Convert the binary hash to a printable hexadecimal string.
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
		// Log the file I/O error and report failure.
		TCHAR lpszError[MAX_STR_BUFFER] = { 0 };
		pFileException->GetErrorMessage(lpszError, MAX_STR_BUFFER);
		pFileException->Delete();
		OutputDebugString(lpszError);
		retVal = false;
	}

	// Free temporary input buffer.
	if (lpszInput != nullptr)
	{
		delete []lpszInput;
		lpszInput = nullptr;
	}

	// Free temporary output buffer.
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
	// CryptEncrypt works in-place; track how many bytes are being processed.
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

	// Copy plaintext into the output buffer; CryptEncrypt encrypts it in-place.
	::CopyMemory(lpszOutputBuffer, lpszInputBuffer, dwHowManyBytes);

	// Acquire a handle to the default RSA cryptographic provider.
	if (CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
	{
		// Create an MD5 hash object used to derive the session key from the secret.
		if (CryptCreateHash(hCryptProv, CALG_MD5, NULL, 0, &hCryptHash))
		{
			// Hash the caller-supplied secret key material.
			if (CryptHashData(hCryptHash, lpszSecretKey, dwSecretKey, 0))
			{
				// Derive a session key for the requested encryption algorithm from the hash.
				if (CryptDeriveKey(hCryptProv, nAlgorithm, hCryptHash, CRYPT_EXPORTABLE, &hCryptKey))
				{
					// Encrypt the data in-place; dwHowManyBytes receives the ciphertext length.
					if (CryptEncrypt(hCryptKey, NULL, true, 0, lpszOutputBuffer, &dwHowManyBytes, dwOutputLength))
					{
						// Update the caller's length variable with the actual ciphertext size.
						dwOutputLength = dwHowManyBytes;
						retVal = true;
					}
					else
					{
						TraceLastError(CRYPT_LIBRARY_NAME, _T("CryptEncrypt"), GetLastError());
					}
					// Release the session key.
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
			// Release the hash object.
			VERIFY(CryptDestroyHash(hCryptHash));
		}
		else
		{
			TraceLastError(CRYPT_LIBRARY_NAME, _T("CryptCreateHash"), GetLastError());
		}
		// Release the cryptographic provider context.
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
		// Open the source file in binary read mode.
		CFile pInputFile(strInputName, CFile::modeRead | CFile::typeBinary);
		const UINT dwInput = (UINT)pInputFile.GetLength();
		if (dwInput > 0)
		{
			// Read the entire plaintext file into memory.
			lpszInput = new BYTE[dwInput];
			if (dwInput == pInputFile.Read(lpszInput, dwInput))
			{
				// Allocate extra space for any cipher padding added by the algorithm.
				DWORD dwOutput = dwInput + MAX_CRYPT_TAIL;
				lpszOutput = new BYTE[dwOutput];
				// Encrypt the plaintext buffer.
				if (EncryptBuffer(nAlgorithm, lpszOutput, dwOutput, lpszInput, dwInput, lpszSecretKey, dwSecretKey))
				{
					// Write the ciphertext to the output file.
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
		// Log the file I/O error and report failure.
		TCHAR lpszError[MAX_STR_BUFFER] = { 0 };
		pFileException->GetErrorMessage(lpszError, MAX_STR_BUFFER);
		pFileException->Delete();
		OutputDebugString(lpszError);
		retVal = false;
	}

	// Free temporary plaintext buffer.
	if (lpszInput != nullptr)
	{
		delete []lpszInput;
		lpszInput = nullptr;
	}

	// Free temporary ciphertext buffer.
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
	// CryptDecrypt works in-place; track the number of ciphertext bytes.
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

	// Copy ciphertext into the output buffer; CryptDecrypt decrypts it in-place.
	::CopyMemory(lpszOutputBuffer, lpszInputBuffer, dwHowManyBytes);

	// Acquire a handle to the default RSA cryptographic provider.
	if (CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
	{
		// Create an MD5 hash object used to re-derive the session key from the secret.
		if (CryptCreateHash(hCryptProv, CALG_MD5, NULL, 0, &hCryptHash))
		{
			// Hash the caller-supplied secret key material.
			if (CryptHashData(hCryptHash, lpszSecretKey, dwSecretKey, 0))
			{
				// Derive the same session key that was used during encryption.
				if (CryptDeriveKey(hCryptProv, nAlgorithm, hCryptHash, CRYPT_EXPORTABLE, &hCryptKey))
				{
					// Decrypt the data in-place; dwHowManyBytes receives the plaintext length.
					if (CryptDecrypt(hCryptKey, NULL, true, 0, lpszOutputBuffer, &dwHowManyBytes))
					{
						// Update the caller's length variable with the actual plaintext size.
						dwOutputLength = dwHowManyBytes;
						retVal = true;
					}
					else
					{
						TraceLastError(CRYPT_LIBRARY_NAME, _T("CryptDecrypt"), GetLastError());
					}
					// Release the session key.
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
			// Release the hash object.
			VERIFY(CryptDestroyHash(hCryptHash));
		}
		else
		{
			TraceLastError(CRYPT_LIBRARY_NAME, _T("CryptCreateHash"), GetLastError());
		}
		// Release the cryptographic provider context.
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
		// Open the encrypted source file in binary read mode.
		CFile pInputFile(strInputName, CFile::modeRead | CFile::typeBinary);
		const UINT dwInput = (UINT)pInputFile.GetLength();
		if (dwInput > 0)
		{
			// Read the entire ciphertext file into memory.
			lpszInput = new BYTE[dwInput];
			if (dwInput == pInputFile.Read(lpszInput, dwInput))
			{
				// Allocate extra space to accommodate any padding that was added during encryption.
				DWORD dwOutput = dwInput + MAX_CRYPT_TAIL;
				lpszOutput = new BYTE[dwOutput];
				// Decrypt the ciphertext buffer into the output buffer.
				if (DecryptBuffer(nAlgorithm, lpszOutput, dwOutput, lpszInput, dwInput, lpszSecretKey, dwSecretKey))
				{
					// Write the recovered plaintext to the output file.
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
		// Log the file I/O error and report failure.
		TCHAR lpszError[MAX_STR_BUFFER] = { 0 };
		pFileException->GetErrorMessage(lpszError, MAX_STR_BUFFER);
		pFileException->Delete();
		OutputDebugString(lpszError);
		retVal = false;
	}

	// Free temporary ciphertext buffer.
	if (lpszInput != nullptr)
	{
		delete []lpszInput;
		lpszInput = nullptr;
	}

	// Free temporary plaintext buffer.
	if (lpszOutput != nullptr)
	{
		delete []lpszOutput;
		lpszOutput = nullptr;
	}

	return retVal;
}
