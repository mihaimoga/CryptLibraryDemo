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

// TestHelpers.cpp : shared helpers for the CryptLibraryDemo unit tests.

#include "stdafx.h"
#include "TestHelpers.h"

#include <algorithm>
#include <atomic>
#include <fstream>
#include <mutex>
#include <string>
#include <thread>

#include <bcrypt.h>
#pragma comment(lib, "bcrypt")

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace TestHelpers
{
	ByteVector FromHex(LPCSTR lpszHexa)
	{
		ByteVector vResult;
		int nHighNibble = -1;
		for (LPCSTR lpszDigit = lpszHexa; *lpszDigit != '\0'; lpszDigit++)
		{
			const char chDigit = *lpszDigit;
			if (chDigit == ' ')
				continue;

			int nNibble = -1;
			if (chDigit >= '0' && chDigit <= '9')
				nNibble = chDigit - '0';
			else if (chDigit >= 'A' && chDigit <= 'F')
				nNibble = chDigit - 'A' + 10;
			else if (chDigit >= 'a' && chDigit <= 'f')
				nNibble = chDigit - 'a' + 10;
			if (nNibble < 0)
				Assert::Fail(L"FromHex: invalid hexadecimal digit.");

			if (nHighNibble < 0)
			{
				nHighNibble = nNibble;
			}
			else
			{
				vResult.push_back(static_cast<BYTE>((nHighNibble << 4) | nNibble));
				nHighNibble = -1;
			}
		}
		if (nHighNibble >= 0)
			Assert::Fail(L"FromHex: odd number of hexadecimal digits.");

		return vResult;
	}

	CString ToHex(const BYTE* lpData, size_t nLength)
	{
		static const TCHAR s_lpszDigits[] = _T("0123456789ABCDEF");

		CString strResult;
		LPTSTR lpszBuffer = strResult.GetBuffer(static_cast<int>(2 * nLength));
		for (size_t nIndex = 0; nIndex < nLength; nIndex++)
		{
			lpszBuffer[2 * nIndex] = s_lpszDigits[lpData[nIndex] >> 4];
			lpszBuffer[2 * nIndex + 1] = s_lpszDigits[lpData[nIndex] & 0x0F];
		}
		strResult.ReleaseBuffer(static_cast<int>(2 * nLength));
		return strResult;
	}

	CString ToHex(const ByteVector& vData)
	{
		return ToHex(vData.data(), vData.size());
	}

	ByteVector AsciiBytes(LPCSTR lpszText)
	{
		const size_t nLength = strlen(lpszText);
		const BYTE* lpData = reinterpret_cast<const BYTE*>(lpszText);
		return ByteVector(lpData, lpData + nLength);
	}

	ByteVector Utf16Bytes(const CString& strText)
	{
		const BYTE* lpData = reinterpret_cast<const BYTE*>(strText.GetString());
		return ByteVector(lpData, lpData + (static_cast<size_t>(strText.GetLength()) + 1) * sizeof(TCHAR));
	}

	ByteVector Repeat(BYTE nValue, size_t nCount)
	{
		return ByteVector(nCount, nValue);
	}

	ByteVector AllByteValues()
	{
		ByteVector vResult(256);
		for (size_t nIndex = 0; nIndex < vResult.size(); nIndex++)
			vResult[nIndex] = static_cast<BYTE>(nIndex);
		return vResult;
	}

	ByteVector PseudoRandomBytes(size_t nLength, unsigned int nSeed)
	{
		// xorshift32: tiny, dependency free and identical on every platform.
		unsigned int nState = (nSeed != 0) ? nSeed : 0x2545F491u;
		ByteVector vResult(nLength);
		for (size_t nIndex = 0; nIndex < nLength; nIndex++)
		{
			nState ^= nState << 13;
			nState ^= nState >> 17;
			nState ^= nState << 5;
			vResult[nIndex] = static_cast<BYTE>(nState >> 11);
		}
		return vResult;
	}

	bool TryReferenceHash(ALG_ID nAlgorithm, const ByteVector& vData, ByteVector& vHash)
	{
		BCRYPT_ALG_HANDLE hAlgorithm = nullptr;
		ULONG nHashLength = 0;
		switch (nAlgorithm)
		{
		case CALG_MD2:
			hAlgorithm = BCRYPT_MD2_ALG_HANDLE;
			nHashLength = 16;
			break;
		case CALG_MD4:
			hAlgorithm = BCRYPT_MD4_ALG_HANDLE;
			nHashLength = 16;
			break;
		case CALG_MD5:
			hAlgorithm = BCRYPT_MD5_ALG_HANDLE;
			nHashLength = 16;
			break;
		case CALG_SHA1:
			hAlgorithm = BCRYPT_SHA1_ALG_HANDLE;
			nHashLength = 20;
			break;
		default:
			return false;
		}

		ByteVector vResult(nHashLength);
		const NTSTATUS nStatus = BCryptHash(hAlgorithm, nullptr, 0,
			const_cast<PUCHAR>(vData.data()), static_cast<ULONG>(vData.size()),
			vResult.data(), nHashLength);
		if (!BCRYPT_SUCCESS(nStatus))
			return false;

		vHash.swap(vResult);
		return true;
	}

	ByteVector ReferenceHash(ALG_ID nAlgorithm, const ByteVector& vData)
	{
		ByteVector vHash;
		if (!TryReferenceHash(nAlgorithm, vData, vHash))
			Assert::Fail(L"ReferenceHash: unsupported algorithm or BCryptHash failed.");

		return vHash;
	}

	bool TryReferenceRc4(const ByteVector& vSecret, const ByteVector& vData, ByteVector& vResult)
	{
		ByteVector vKey;
		if (!TryReferenceHash(CALG_MD5, vSecret, vKey))
			return false;

		// Key scheduling.
		BYTE arrState[256];
		for (size_t nIndex = 0; nIndex < 256; nIndex++)
			arrState[nIndex] = static_cast<BYTE>(nIndex);
		size_t nSwap = 0;
		for (size_t nIndex = 0; nIndex < 256; nIndex++)
		{
			nSwap = (nSwap + arrState[nIndex] + vKey[nIndex % vKey.size()]) & 0xFF;
			std::swap(arrState[nIndex], arrState[nSwap]);
		}

		// Keystream generation.
		ByteVector vOutput(vData.size());
		size_t nFirst = 0;
		size_t nSecond = 0;
		for (size_t nIndex = 0; nIndex < vData.size(); nIndex++)
		{
			nFirst = (nFirst + 1) & 0xFF;
			nSecond = (nSecond + arrState[nFirst]) & 0xFF;
			std::swap(arrState[nFirst], arrState[nSecond]);
			vOutput[nIndex] = static_cast<BYTE>(vData[nIndex] ^ arrState[(arrState[nFirst] + arrState[nSecond]) & 0xFF]);
		}

		vResult.swap(vOutput);
		return true;
	}

	ByteVector ReferenceRc4(const ByteVector& vSecret, const ByteVector& vData)
	{
		ByteVector vResult;
		if (!TryReferenceRc4(vSecret, vData, vResult))
			Assert::Fail(L"ReferenceRc4: the MD5 key derivation failed.");

		return vResult;
	}

	void AssertBytesEqual(const ByteVector& vExpected, const ByteVector& vActual, LPCWSTR lpszMessage)
	{
		if (vExpected == vActual)
			return;

		size_t nDifference = 0;
		const size_t nCommon = (std::min)(vExpected.size(), vActual.size());
		while (nDifference < nCommon && vExpected[nDifference] == vActual[nDifference])
			nDifference++;

		// Large buffers are shortened so that the failure message stays readable.
		const size_t nPreview = 64;
		const CString strExpected = ToHex(vExpected.data(), (std::min)(vExpected.size(), nPreview)) + ((vExpected.size() > nPreview) ? _T("...") : _T(""));
		const CString strActual = ToHex(vActual.data(), (std::min)(vActual.size(), nPreview)) + ((vActual.size() > nPreview) ? _T("...") : _T(""));

		CString strMessage;
		strMessage.Format(_T("%s\nByte sequences differ: first difference at index %I64u, expected %I64u byte(s), actual %I64u byte(s).\nExpected: %s\nActual:   %s"),
			(lpszMessage != nullptr) ? lpszMessage : _T(""),
			static_cast<ULONGLONG>(nDifference),
			static_cast<ULONGLONG>(vExpected.size()),
			static_cast<ULONGLONG>(vActual.size()),
			(LPCTSTR)strExpected,
			(LPCTSTR)strActual);
		Assert::Fail(strMessage);
	}

	void AssertBytesNotEqual(const ByteVector& vUnexpected, const ByteVector& vActual, LPCWSTR lpszMessage)
	{
		if (vUnexpected != vActual)
			return;

		CString strMessage;
		strMessage.Format(_T("%s\nByte sequences are equal but must differ (%I64u byte(s))."),
			(lpszMessage != nullptr) ? lpszMessage : _T(""),
			static_cast<ULONGLONG>(vActual.size()));
		Assert::Fail(strMessage);
	}

	void AssertStringsEqual(const CString& strExpected, const CString& strActual, LPCTSTR lpszMessage)
	{
		if (strExpected.GetLength() == strActual.GetLength() && strExpected.Compare(strActual) == 0)
			return;

		CString strMessage;
		strMessage.Format(_T("%s\nExpected: \"%s\" (%d characters)\nActual:   \"%s\" (%d characters)"),
			(lpszMessage != nullptr) ? lpszMessage : _T(""),
			(LPCTSTR)strExpected, strExpected.GetLength(),
			(LPCTSTR)strActual, strActual.GetLength());
		Assert::Fail(strMessage);
	}

	TempDirectory::TempDirectory()
	{
		static std::atomic<unsigned int> s_nSequence(0);

		std::error_code errorCode;
		const std::filesystem::path pathTemp = std::filesystem::temp_directory_path(errorCode);
		if (errorCode)
			Assert::Fail(L"TempDirectory: cannot locate the temporary directory.");

		CString strName;
		strName.Format(_T("CryptLibraryDemoTests_%lu_%I64u_%u"), ::GetCurrentProcessId(), ::GetTickCount64(), ++s_nSequence);
		m_pathRoot = pathTemp / strName.GetString();

		std::filesystem::create_directories(m_pathRoot, errorCode);
		if (errorCode || !std::filesystem::is_directory(m_pathRoot))
			Assert::Fail(L"TempDirectory: cannot create the test directory.");
	}

	TempDirectory::~TempDirectory()
	{
		// Best effort: a leftover folder in %TEMP% must not fail a test.
		std::error_code errorCode;
		std::filesystem::remove_all(m_pathRoot, errorCode);
	}

	CString TempDirectory::Path(LPCTSTR lpszName) const
	{
		return CString((m_pathRoot / lpszName).c_str());
	}

	CString TempDirectory::CreateSubfolder(LPCTSTR lpszName) const
	{
		const std::filesystem::path pathSubfolder = m_pathRoot / lpszName;
		std::error_code errorCode;
		std::filesystem::create_directories(pathSubfolder, errorCode);
		if (errorCode)
			Assert::Fail(L"TempDirectory: cannot create a sub folder.");
		return CString(pathSubfolder.c_str());
	}

	bool WriteBinaryFile(LPCTSTR lpszPath, const ByteVector& vData)
	{
		std::ofstream file(std::filesystem::path(lpszPath), std::ios::binary | std::ios::trunc);
		if (!file)
			return false;
		if (!vData.empty())
			file.write(reinterpret_cast<const char*>(vData.data()), static_cast<std::streamsize>(vData.size()));
		file.close();
		return !file.fail();
	}

	ByteVector ReadBinaryFile(LPCTSTR lpszPath)
	{
		std::ifstream file(std::filesystem::path(lpszPath), std::ios::binary | std::ios::ate);
		if (!file)
			return ByteVector();

		const std::streamoff nLength = file.tellg();
		if (nLength <= 0)
			return ByteVector();

		ByteVector vData(static_cast<size_t>(nLength));
		file.seekg(0, std::ios::beg);
		file.read(reinterpret_cast<char*>(vData.data()), nLength);
		if (file.gcount() != nLength)
			vData.clear();
		return vData;
	}

	bool PathExists(LPCTSTR lpszPath)
	{
		std::error_code errorCode;
		return std::filesystem::exists(std::filesystem::path(lpszPath), errorCode);
	}

	ULONGLONG GetFileLength(LPCTSTR lpszPath)
	{
		std::error_code errorCode;
		const std::uintmax_t nLength = std::filesystem::file_size(std::filesystem::path(lpszPath), errorCode);
		return errorCode ? 0 : static_cast<ULONGLONG>(nLength);
	}

	OpenFileHandle::OpenFileHandle(LPCTSTR lpszPath)
		: m_hFile(::CreateFile(lpszPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr))
	{
	}

	OpenFileHandle::~OpenFileHandle()
	{
		if (m_hFile != INVALID_HANDLE_VALUE)
			::CloseHandle(m_hFile);
	}

	bool OpenFileHandle::IsOpen() const
	{
		return m_hFile != INVALID_HANDLE_VALUE;
	}

	void WorkerFailures::Add(const CString& strMessage)
	{
		std::lock_guard<std::mutex> lock(m_mutex);
		m_arrMessages.push_back(strMessage);
	}

	void WorkerFailures::AssertNone() const
	{
		const size_t MAX_LISTED = 5;

		CString strMessage;
		{
			std::lock_guard<std::mutex> lock(m_mutex);
			if (m_arrMessages.empty())
				return;

			const size_t nListed = (m_arrMessages.size() < MAX_LISTED) ? m_arrMessages.size() : MAX_LISTED;
			strMessage.Format(_T("The worker threads found %I64u problem(s), the first %I64u:"),
				static_cast<ULONGLONG>(m_arrMessages.size()), static_cast<ULONGLONG>(nListed));
			for (size_t nIndex = 0; nIndex < nListed; nIndex++)
			{
				strMessage += _T("\n");
				strMessage += m_arrMessages[nIndex];
			}
		}
		Assert::Fail(strMessage);
	}

	void RunConcurrently(unsigned int nThreads, const std::function<void(unsigned int nThread, WorkerFailures& failures)>& fnWorker)
	{
		WorkerFailures failures;
		std::atomic<bool> bStart(false);

		std::vector<std::thread> arrThreads;
		try
		{
			for (unsigned int nThread = 0; nThread < nThreads; nThread++)
			{
				arrThreads.emplace_back([&fnWorker, &failures, &bStart, nThread]()
				{
					while (!bStart)
						std::this_thread::yield();

					// An exception must not escape a thread: that would end the test host.
					try
					{
						fnWorker(nThread, failures);
					}
					catch (...)
					{
						CString strMessage;
						strMessage.Format(_T("An exception escaped from thread %u."), nThread);
						failures.Add(strMessage);
					}
				});
			}
		}
		catch (...)
		{
			failures.Add(_T("A thread could not be started."));
		}

		// The threads that were started are released, and joined, even when one could not be.
		bStart = true;
		for (std::thread& thread : arrThreads)
			thread.join();

		failures.AssertNone();
	}

	namespace
	{
		// Exception codes raised by OutputDebugStringA/W (DBG_PRINTEXCEPTION_C and DBG_PRINTEXCEPTION_WIDE_C).
		const DWORD DBG_PRINT_EXCEPTION_ANSI = 0x40010006;
		const DWORD DBG_PRINT_EXCEPTION_WIDE = 0x4001000A;

		std::mutex g_DebugOutputLock;
		std::wstring g_strDebugOutput;
		PVOID g_pDebugOutputHandler = nullptr;

		LONG CALLBACK DebugOutputHandler(PEXCEPTION_POINTERS pExceptionInfo)
		{
			const EXCEPTION_RECORD* pRecord = pExceptionInfo->ExceptionRecord;
			const bool bAnsi = (pRecord->ExceptionCode == DBG_PRINT_EXCEPTION_ANSI);
			const bool bWide = (pRecord->ExceptionCode == DBG_PRINT_EXCEPTION_WIDE);
			if ((!bAnsi && !bWide) || pRecord->NumberParameters < 2)
				return EXCEPTION_CONTINUE_SEARCH;

			try
			{
				// ExceptionInformation[0] is the length including the NUL, [1] the text.
				const size_t nMaxLength = static_cast<size_t>(pRecord->ExceptionInformation[0]);
				std::wstring strText;
				if (bWide)
				{
					const wchar_t* lpszText = reinterpret_cast<const wchar_t*>(pRecord->ExceptionInformation[1]);
					strText.assign(lpszText, wcsnlen(lpszText, nMaxLength));
				}
				else
				{
					const char* lpszText = reinterpret_cast<const char*>(pRecord->ExceptionInformation[1]);
					strText = (LPCWSTR)CStringW(lpszText, static_cast<int>(strnlen(lpszText, nMaxLength)));
				}

				std::lock_guard<std::mutex> lock(g_DebugOutputLock);
				g_strDebugOutput += strText;
			}
			catch (...)
			{
				return EXCEPTION_CONTINUE_SEARCH;
			}

			// Tell OutputDebugString that a debugger took the text, so it is not forwarded again.
			return EXCEPTION_CONTINUE_EXECUTION;
		}
	}

	DebugOutputCapture::DebugOutputCapture()
	{
		{
			std::lock_guard<std::mutex> lock(g_DebugOutputLock);
			g_strDebugOutput.clear();
		}
		g_pDebugOutputHandler = ::AddVectoredExceptionHandler(1, DebugOutputHandler);
	}

	DebugOutputCapture::~DebugOutputCapture()
	{
		if (g_pDebugOutputHandler != nullptr)
		{
			::RemoveVectoredExceptionHandler(g_pDebugOutputHandler);
			g_pDebugOutputHandler = nullptr;
		}
	}

	bool DebugOutputCapture::IsSupported()
	{
		return !::IsDebuggerPresent();
	}

	CString DebugOutputCapture::Text() const
	{
		std::lock_guard<std::mutex> lock(g_DebugOutputLock);
		return CString(g_strDebugOutput.c_str());
	}

#ifdef _DEBUG
	namespace
	{
		std::mutex g_AssertionLock;
		std::vector<CString> g_arrAssertions;

		void RecordReport(const CString& strMessage)
		{
			std::lock_guard<std::mutex> lock(g_AssertionLock);
			g_arrAssertions.push_back(strMessage);
		}

		int __cdecl ReportHookA(int nReportType, char* lpszMessage, int* pnReturnValue)
		{
			if (nReportType != _CRT_ASSERT && nReportType != _CRT_ERROR)
				return FALSE;

			RecordReport(CString((lpszMessage != nullptr) ? lpszMessage : ""));
			if (pnReturnValue != nullptr)
				*pnReturnValue = 0; // neither break into the debugger nor retry
			return TRUE; // handled: no dialog
		}

		int __cdecl ReportHookW(int nReportType, wchar_t* lpszMessage, int* pnReturnValue)
		{
			if (nReportType != _CRT_ASSERT && nReportType != _CRT_ERROR)
				return FALSE;

			RecordReport(CString((lpszMessage != nullptr) ? lpszMessage : L""));
			if (pnReturnValue != nullptr)
				*pnReturnValue = 0;
			return TRUE;
		}
	}
#endif

	void AssertionMonitor::Install()
	{
#ifdef _DEBUG
		_CrtSetReportHook2(_CRT_RPTHOOK_INSTALL, ReportHookA);
		_CrtSetReportHookW2(_CRT_RPTHOOK_INSTALL, ReportHookW);
#endif
	}

	void AssertionMonitor::Uninstall()
	{
#ifdef _DEBUG
		_CrtSetReportHook2(_CRT_RPTHOOK_REMOVE, ReportHookA);
		_CrtSetReportHookW2(_CRT_RPTHOOK_REMOVE, ReportHookW);
#endif
	}

	void AssertionMonitor::Reset()
	{
#ifdef _DEBUG
		std::lock_guard<std::mutex> lock(g_AssertionLock);
		g_arrAssertions.clear();
#endif
	}

	void AssertionMonitor::VerifyNoAssertions()
	{
#ifdef _DEBUG
		CString strMessage;
		{
			std::lock_guard<std::mutex> lock(g_AssertionLock);
			for (const CString& strAssertion : g_arrAssertions)
			{
				strMessage += strAssertion;
				strMessage += _T("\n");
			}
			g_arrAssertions.clear();
		}
		if (!strMessage.IsEmpty())
			Assert::Fail(CString(_T("The code under test failed an ASSERT or VERIFY:\n")) + strMessage);
#endif
	}
}
