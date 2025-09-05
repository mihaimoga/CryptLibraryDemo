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

// CryptographyExt.h : Demo for Microsoft's Crypt Library functions.

#pragma once

/**
 * @def CRYPT_LIBRARY_NAME
 * @brief Name used for cryptographic library error tracing.
 */
#define CRYPT_LIBRARY_NAME _T("Crypt")

/**
 * @def MD5CHECKSUM_LENGTH
 * @brief Length in bytes of an MD5 checksum.
 */
#define MD5CHECKSUM_LENGTH 0x10

/**
 * @def SHA1CHECKSUM_LENGTH
 * @brief Length in bytes of a SHA1 checksum.
 */
#define SHA1CHECKSUM_LENGTH 0x14

/**
 * @def MAX_STR_BUFFER
 * @brief Maximum buffer size for string operations.
 */
#define MAX_STR_BUFFER 0x1000

/**
 * @def MAX_CRYPT_TAIL
 * @brief Maximum tail size for cryptographic operations.
 */
#define MAX_CRYPT_TAIL 0x1000

// for CLongBinary
#include <afxdb_.h>
#include <WinCrypt.h>

/**
 * @brief Outputs the last error from a Windows API call to the debug output.
 * @param lpszLibrary The name of the library where the error occurred.
 * @param lpszOperation The operation that failed.
 * @param dwLastError The error code returned by GetLastError().
 */
void TraceLastError(LPCTSTR lpszLibrary, LPCTSTR lpszOperation, DWORD dwLastError);

/**
 * @brief Retrieves a string identifying the current user and computer.
 * @return A string in the format "UserName:ComputerName".
 */
CString GetComputerID();

/**
 * @brief Converts a hexadecimal string buffer to binary data.
 * @param lpszOutputBuffer Output binary buffer.
 * @param dwOutputLength Length of output buffer.
 * @param lpszInputBuffer Input hexadecimal string buffer.
 * @param dwInputLength Length of input buffer.
 * @return true if conversion succeeded, false otherwise.
 */
bool ConvertHexaToBinary(LPBYTE lpszOutputBuffer, DWORD dwOutputLength, LPCTSTR lpszInputBuffer, DWORD dwInputLength);

/**
 * @brief Converts a hexadecimal string stored in a CLongBinary to binary data.
 * @param pTargetBinary Output binary data.
 * @param pSourceBinary Input hexadecimal string data.
 * @return true if conversion succeeded, false otherwise.
 */
bool ConvertHexaToBinary(CLongBinary* pTargetBinary, CLongBinary* pSourceBinary);

/**
 * @brief Converts binary data to a hexadecimal string buffer.
 * @param lpszOutputBuffer Output hexadecimal string buffer.
 * @param dwOutputLength Length of output buffer.
 * @param lpszInputBuffer Input binary buffer.
 * @param dwInputLength Length of input buffer.
 * @return true if conversion succeeded, false otherwise.
 */
bool ConvertBinaryToHexa(LPTSTR lpszOutputBuffer, DWORD dwOutputLength, LPBYTE lpszInputBuffer, DWORD dwInputLength);

/**
 * @brief Converts binary data in a CLongBinary to a hexadecimal string.
 * @param pTargetBinary Output hexadecimal string.
 * @param pSourceBinary Input binary data.
 * @return true if conversion succeeded, false otherwise.
 */
bool ConvertBinaryToHexa(CLongBinary* pTargetBinary, CLongBinary* pSourceBinary);

/**
 * @brief Computes a cryptographic hash (checksum) of a buffer.
 * @param nAlgorithm Hash algorithm identifier (e.g., CALG_MD5, CALG_SHA1).
 * @param lpszOutputBuffer Output buffer for the hash.
 * @param dwOutputLength [in/out] On input, size of output buffer; on output, actual hash size.
 * @param lpszInputBuffer Input buffer to hash.
 * @param dwInputLength Length of input buffer.
 * @return true if hash computation succeeded, false otherwise.
 */
bool GetChecksumBuffer(ALG_ID nAlgorithm, LPBYTE lpszOutputBuffer, DWORD& dwOutputLength, LPBYTE lpszInputBuffer, DWORD dwInputLength);

/**
 * @brief Computes a cryptographic hash (checksum) of a string and returns it as a hexadecimal string.
 * @param nAlgorithm Hash algorithm identifier (e.g., CALG_MD5, CALG_SHA1).
 * @param strResult Output string containing the checksum in hexadecimal.
 * @param strBuffer Input string to hash.
 * @return true if hash computation succeeded, false otherwise.
 */
bool GetChecksumString(ALG_ID nAlgorithm, CString& strResult, CString strBuffer);

/**
 * @brief Computes a cryptographic hash (checksum) of a file and returns it as a hexadecimal string.
 * @param nAlgorithm Hash algorithm identifier (e.g., CALG_MD5, CALG_SHA1).
 * @param strResult Output string containing the checksum in hexadecimal.
 * @param strPathName Path to the file to hash.
 * @return true if hash computation succeeded, false otherwise.
 */
bool GetChecksumFile(ALG_ID nAlgorithm, CString& strResult, CString strPathName);

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
bool EncryptBuffer(ALG_ID nAlgorithm, LPBYTE lpszOutputBuffer, DWORD& dwOutputLength, LPBYTE lpszInputBuffer, DWORD dwInputLength, LPBYTE lpszSecretKey, DWORD dwSecretKey);

/**
 * @brief Encrypts a file using a specified algorithm and secret key.
 * @param nAlgorithm Encryption algorithm identifier (e.g., CALG_RC4).
 * @param strOutputName Output file path.
 * @param strInputName Input file path.
 * @param lpszSecretKey Secret key buffer.
 * @param dwSecretKey Length of secret key.
 * @return true if encryption succeeded, false otherwise.
 */
bool EncryptFile(ALG_ID nAlgorithm, CString strOutputName, CString strInputName, LPBYTE lpszSecretKey, DWORD dwSecretKey);

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
bool DecryptBuffer(ALG_ID nAlgorithm, LPBYTE lpszOutputBuffer, DWORD& dwOutputLength, LPBYTE lpszInputBuffer, DWORD dwInputLength, LPBYTE lpszSecretKey, DWORD dwSecretKey);

/**
 * @brief Decrypts a file using a specified algorithm and secret key.
 * @param nAlgorithm Decryption algorithm identifier (e.g., CALG_RC4).
 * @param strOutputName Output file path.
 * @param strInputName Input file path.
 * @param lpszSecretKey Secret key buffer.
 * @param dwSecretKey Length of secret key.
 * @return true if decryption succeeded, false otherwise.
 */
bool DecryptFile(ALG_ID nAlgorithm, CString strOutputName, CString strInputName, LPBYTE lpszSecretKey, DWORD dwSecretKey);
