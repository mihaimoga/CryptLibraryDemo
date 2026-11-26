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

// SystemInfoTests.cpp : unit tests for GetComputerID and TraceLastError.

#include "stdafx.h"
#include "CryptographyExt.h"
#include "TestHelpers.h"

#define SECURITY_WIN32
#include <Security.h>
#pragma comment(lib, "secur32")

#include <vector>

using namespace Microsoft::VisualStudio::CppUnitTestFramework;
using namespace TestHelpers;

namespace CryptLibraryDemoTests
{
	namespace
	{
		const unsigned int CONCURRENT_THREADS = 4;

		/** Looking up the principal name can contact a domain controller, so GetComputerID is called sparingly. */
		const unsigned int ID_CALLS_PER_THREAD = 5;
		const unsigned int TRACE_CALLS_PER_THREAD = 25;

		/** Much larger than the 256 characters GetComputerID reserves, so the expected names are never truncated. */
		const size_t NAME_BUFFER_LENGTH = 4096;

		struct KnownError
		{
			DWORD dwError;
			LPCTSTR lpszName;
		};

		/** Codes as GetLastError reports them after a failed system or CryptoAPI call. */
		const KnownError KNOWN_ERRORS[] =
		{
			{ ERROR_SUCCESS, _T("ERROR_SUCCESS") },
			{ ERROR_FILE_NOT_FOUND, _T("ERROR_FILE_NOT_FOUND") },
			{ ERROR_ACCESS_DENIED, _T("ERROR_ACCESS_DENIED") },
			{ ERROR_SHARING_VIOLATION, _T("ERROR_SHARING_VIOLATION") },
			{ ERROR_INVALID_PARAMETER, _T("ERROR_INVALID_PARAMETER") },
			{ ERROR_MORE_DATA, _T("ERROR_MORE_DATA") },
			{ static_cast<DWORD>(NTE_BAD_HASH), _T("NTE_BAD_HASH") },
			{ static_cast<DWORD>(NTE_BAD_KEY), _T("NTE_BAD_KEY") },
			{ static_cast<DWORD>(NTE_BAD_LEN), _T("NTE_BAD_LEN") },
			{ static_cast<DWORD>(NTE_BAD_DATA), _T("NTE_BAD_DATA") },
			{ static_cast<DWORD>(NTE_BAD_ALGID), _T("NTE_BAD_ALGID") },
			{ static_cast<DWORD>(NTE_BAD_FLAGS), _T("NTE_BAD_FLAGS") },
			{ static_cast<DWORD>(NTE_BAD_TYPE), _T("NTE_BAD_TYPE") },
			{ static_cast<DWORD>(NTE_NO_MEMORY), _T("NTE_NO_MEMORY") },
			{ static_cast<DWORD>(NTE_PERM), _T("NTE_PERM") },
			{ static_cast<DWORD>(NTE_FAIL), _T("NTE_FAIL") },
			{ static_cast<DWORD>(NTE_PROV_TYPE_NOT_DEF), _T("NTE_PROV_TYPE_NOT_DEF") },
			{ static_cast<DWORD>(NTE_KEYSET_NOT_DEF), _T("NTE_KEYSET_NOT_DEF") },
		};

		/** Codes the system has no text for. */
		const DWORD UNKNOWN_ERRORS[] = { 0xDEADBEEF, 0x0FFFFFFF, 0xFFFF };

		// ------------------------------------------------------------------
		// GetComputerID
		// ------------------------------------------------------------------

		/** The user name GetComputerID documents: the principal name if the account has one, otherwise the account name. */
		CString ExpectedUserName(bool& bPrincipalName)
		{
			std::vector<TCHAR> arrBuffer(NAME_BUFFER_LENGTH, 0);
			ULONG nLength = static_cast<ULONG>(arrBuffer.size());
			bPrincipalName = (::GetUserNameEx(NameUserPrincipal, arrBuffer.data(), &nLength) != FALSE);
			if (!bPrincipalName)
			{
				DWORD nAccountLength = static_cast<DWORD>(arrBuffer.size());
				Assert::IsTrue(::GetUserName(arrBuffer.data(), &nAccountLength) != FALSE, L"GetUserName failed");
			}
			return CString(arrBuffer.data());
		}

		/** The computer name GetComputerID documents: the fully qualified DNS name if there is one, otherwise the NetBIOS name. */
		CString ExpectedComputerName(bool& bDnsName)
		{
			std::vector<TCHAR> arrBuffer(NAME_BUFFER_LENGTH, 0);
			DWORD nLength = static_cast<DWORD>(arrBuffer.size());
			bDnsName = (::GetComputerNameEx(ComputerNamePhysicalDnsFullyQualified, arrBuffer.data(), &nLength) != FALSE);
			if (!bDnsName)
			{
				nLength = static_cast<DWORD>(arrBuffer.size());
				Assert::IsTrue(::GetComputerName(arrBuffer.data(), &nLength) != FALSE, L"GetComputerName failed");
			}
			return CString(arrBuffer.data());
		}

		/** Splits "UserName:ComputerName" at the last colon, which a computer name cannot contain. */
		void SplitComputerID(const CString& strID, CString& strUserName, CString& strComputerName)
		{
			const int nSeparator = strID.ReverseFind(_T(':'));
			Assert::IsTrue(nSeparator >= 0, L"The ID has no colon: " + strID);
			strUserName = strID.Left(nSeparator);
			strComputerName = strID.Mid(nSeparator + 1);
		}

		// ------------------------------------------------------------------
		// TraceLastError
		// ------------------------------------------------------------------

		/** Debug output cannot be captured while a debugger is attached; the test then logs a note and returns. */
		bool CanCaptureDebugOutput()
		{
			if (DebugOutputCapture::IsSupported())
				return true;

			Logger::WriteMessage(L"Skipped: a debugger is attached and consumes the debug output.");
			return false;
		}

		/** The text the system has for an error code, without its trailing line break; empty if it has none. */
		CString SystemMessage(DWORD dwError)
		{
			LPTSTR lpszBuffer = nullptr;
			const DWORD nLength = ::FormatMessage(
				FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
				nullptr, dwError, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
				reinterpret_cast<LPTSTR>(&lpszBuffer), 0, nullptr);

			CString strMessage;
			if (nLength > 0 && lpszBuffer != nullptr)
				strMessage = CString(lpszBuffer, static_cast<int>(nLength));
			::LocalFree(lpszBuffer);
			strMessage.TrimRight();
			return strMessage;
		}

		/** SystemMessage for a code the test cannot do without. */
		CString RequireSystemMessage(DWORD dwError)
		{
			const CString strMessage = SystemMessage(dwError);
			CString strFailure;
			strFailure.Format(_T("The system has no text for error code 0x%08lX"), dwError);
			Assert::IsFalse(strMessage.IsEmpty(), strFailure);
			return strMessage;
		}

		/** The text of an entry, without its line break. */
		CString FormatEntry(const CString& strLibrary, const CString& strOperation, const CString& strMessage)
		{
			CString strEntry;
			strEntry.Format(_T("[%s] %s: %s"), strLibrary.GetString(), strOperation.GetString(), strMessage.GetString());
			return strEntry;
		}

		/** Position of the first occurrence of the entry, at or after nStart, that is followed by a line break; -1 if there is none. */
		int FindEntry(const CString& strOutput, const CString& strEntry, int nStart = 0)
		{
			for (int nPos = strOutput.Find(strEntry, nStart); nPos >= 0; nPos = strOutput.Find(strEntry, nPos + 1))
			{
				int nEnd = nPos + strEntry.GetLength();
				while (nEnd < strOutput.GetLength() && strOutput[nEnd] == _T('\r'))
					nEnd++;

				if (nEnd < strOutput.GetLength() && strOutput[nEnd] == _T('\n'))
					return nPos;
			}
			return -1;
		}

		/** How many times the entry was written, each time followed by a line break. */
		int CountEntries(const CString& strOutput, const CString& strEntry)
		{
			int nCount = 0;
			for (int nPos = FindEntry(strOutput, strEntry); nPos >= 0; nPos = FindEntry(strOutput, strEntry, nPos + 1))
				nCount++;
			return nCount;
		}

		/** Fails unless the output holds "[library] operation: message" followed by a line break. */
		void AssertEntryWritten(const CString& strOutput, const CString& strLibrary, const CString& strOperation, const CString& strMessage)
		{
			const CString strEntry = FormatEntry(strLibrary, strOperation, strMessage);
			CString strFailure;
			strFailure.Format(_T("Expected \"%s\" followed by a line break. Debug output:\n%s"), strEntry.GetString(), strOutput.GetString());
			Assert::IsTrue(FindEntry(strOutput, strEntry) >= 0, strFailure);
		}
	}

	TEST_CLASS(GetComputerIdTests)
	{
	public:
		TEST_ASSERTION_GUARD()

		TEST_METHOD(Result_HasOneColonBetweenTheUserNameAndTheComputerName)
		{
			const CString strID = GetComputerID();

			int nColons = 0;
			for (int nIndex = 0; nIndex < strID.GetLength(); nIndex++)
			{
				if (strID[nIndex] == _T(':'))
					nColons++;
			}

			Assert::AreEqual(1, nColons, strID);
		}

		TEST_METHOD(Result_HasANonEmptyUserNameAndComputerName)
		{
			CString strUserName, strComputerName;
			SplitComputerID(GetComputerID(), strUserName, strComputerName);

			Assert::IsFalse(strUserName.IsEmpty(), L"The user name is empty");
			Assert::IsFalse(strComputerName.IsEmpty(), L"The computer name is empty");
		}

		TEST_METHOD(Result_HasNoControlCharacters)
		{
			const CString strID = GetComputerID();

			for (int nIndex = 0; nIndex < strID.GetLength(); nIndex++)
			{
				CString strFailure;
				strFailure.Format(_T("Character %d of \"%s\" is a control character"), nIndex, strID.GetString());
				Assert::IsTrue(strID[nIndex] >= _T(' '), strFailure);
			}
		}

		TEST_METHOD(UserName_IsThePrincipalNameOrElseTheAccountName)
		{
			bool bPrincipalName = false;
			const CString strExpected = ExpectedUserName(bPrincipalName);
			Logger::WriteMessage(bPrincipalName
				? L"The user name is the user principal name of the account."
				: L"The account has no user principal name, so the user name is the account name.");

			CString strUserName, strComputerName;
			SplitComputerID(GetComputerID(), strUserName, strComputerName);

			AssertStringsEqual(strExpected, strUserName, L"user name");
		}

		TEST_METHOD(ComputerName_IsTheDnsNameOrElseTheNetBiosName)
		{
			bool bDnsName = false;
			const CString strExpected = ExpectedComputerName(bDnsName);
			Logger::WriteMessage(bDnsName
				? L"The computer name is the fully qualified DNS name."
				: L"The computer has no fully qualified DNS name, so the computer name is the NetBIOS name.");

			CString strUserName, strComputerName;
			SplitComputerID(GetComputerID(), strUserName, strComputerName);

			AssertStringsEqual(strExpected, strComputerName, L"computer name");
		}

		TEST_METHOD(Result_IsTheSameOnEveryCall)
		{
			const CString strFirst = GetComputerID();

			for (int nCall = 1; nCall < 5; nCall++)
				AssertStringsEqual(strFirst, GetComputerID(), L"a later call returned a different ID");
		}

		TEST_METHOD(Result_IsTheSameOnEveryThread)
		{
			const CString strExpected = GetComputerID();

			RunConcurrently(CONCURRENT_THREADS, [&strExpected](unsigned int nThread, WorkerFailures& failures)
			{
				for (unsigned int nCall = 0; nCall < ID_CALLS_PER_THREAD; nCall++)
				{
					const CString strActual = GetComputerID();
					if (strActual != strExpected)
					{
						CString strMessage;
						strMessage.Format(_T("thread %u, call %u returned \"%s\" instead of \"%s\""), nThread, nCall, (LPCTSTR)strActual, (LPCTSTR)strExpected);
						failures.Add(strMessage);
					}
				}
			});
		}
	};

	TEST_CLASS(TraceLastErrorTests)
	{
	public:
		TEST_ASSERTION_GUARD()

		TEST_METHOD(Entry_NamesTheLibraryTheOperationAndTheSystemMessage)
		{
			if (!CanCaptureDebugOutput())
				return;

			const CString strMessage = RequireSystemMessage(ERROR_FILE_NOT_FOUND);

			DebugOutputCapture capture;
			TraceLastError(_T("Crypt"), _T("CryptDeriveKey"), ERROR_FILE_NOT_FOUND);

			AssertEntryWritten(capture.Text(), _T("Crypt"), _T("CryptDeriveKey"), strMessage);
		}

		TEST_METHOD(EveryKnownErrorCode_WritesItsSystemMessage)
		{
			if (!CanCaptureDebugOutput())
				return;

			size_t nVerified = 0;
			for (const KnownError& error : KNOWN_ERRORS)
			{
				const CString strMessage = SystemMessage(error.dwError);
				if (strMessage.IsEmpty())
				{
					Logger::WriteMessage(CString(error.lpszName) + _T(": the system has no text for it, not verified"));
					continue;
				}

				DebugOutputCapture capture;
				TraceLastError(_T("Crypt"), error.lpszName, error.dwError);

				AssertEntryWritten(capture.Text(), _T("Crypt"), error.lpszName, strMessage);
				nVerified++;
			}

			Assert::IsTrue(nVerified > 0, L"No error code could be verified");
		}

		TEST_METHOD(SuccessiveCalls_WriteOneEntryEachInCallOrder)
		{
			if (!CanCaptureDebugOutput())
				return;

			const CString strFirst = FormatEntry(_T("Crypt"), _T("CryptAcquireContext"), RequireSystemMessage(ERROR_ACCESS_DENIED));
			const CString strSecond = FormatEntry(_T("Crypt"), _T("CryptCreateHash"), RequireSystemMessage(static_cast<DWORD>(NTE_BAD_ALGID)));
			const CString strThird = FormatEntry(_T("Crypt"), _T("CryptHashData"), RequireSystemMessage(ERROR_INVALID_PARAMETER));

			DebugOutputCapture capture;
			TraceLastError(_T("Crypt"), _T("CryptAcquireContext"), ERROR_ACCESS_DENIED);
			TraceLastError(_T("Crypt"), _T("CryptCreateHash"), static_cast<DWORD>(NTE_BAD_ALGID));
			TraceLastError(_T("Crypt"), _T("CryptHashData"), ERROR_INVALID_PARAMETER);
			const CString strOutput = capture.Text();

			Assert::AreEqual(1, CountEntries(strOutput, strFirst), strFirst);
			Assert::AreEqual(1, CountEntries(strOutput, strSecond), strSecond);
			Assert::AreEqual(1, CountEntries(strOutput, strThird), strThird);

			const int nFirst = FindEntry(strOutput, strFirst);
			const int nSecond = FindEntry(strOutput, strSecond);
			const int nThird = FindEntry(strOutput, strThird);
			Assert::IsTrue(nFirst < nSecond && nSecond < nThird, strOutput);
		}

		TEST_METHOD(EmptyLibraryAndOperation_AreWrittenAsEmptyBrackets)
		{
			if (!CanCaptureDebugOutput())
				return;

			const CString strMessage = RequireSystemMessage(ERROR_ACCESS_DENIED);

			DebugOutputCapture capture;
			TraceLastError(_T(""), _T(""), ERROR_ACCESS_DENIED);

			AssertEntryWritten(capture.Text(), _T(""), _T(""), strMessage);
		}

		TEST_METHOD(PercentCharactersInTheArguments_AreWrittenLiterally)
		{
			if (!CanCaptureDebugOutput())
				return;

			const CString strMessage = RequireSystemMessage(ERROR_ACCESS_DENIED);

			// Format specifiers that would show up as numbers if an argument were used as the format.
			DebugOutputCapture capture;
			TraceLastError(_T("50%d%%"), _T("%x %d"), ERROR_ACCESS_DENIED);

			AssertEntryWritten(capture.Text(), _T("50%d%%"), _T("%x %d"), strMessage);
		}

		TEST_METHOD(LongLibraryAndOperation_AreWrittenInFull)
		{
			if (!CanCaptureDebugOutput())
				return;

			const CString strMessage = RequireSystemMessage(ERROR_ACCESS_DENIED);
			const CString strLibrary(_T('L'), 2000);
			const CString strOperation(_T('O'), 3000);

			DebugOutputCapture capture;
			TraceLastError(strLibrary, strOperation, ERROR_ACCESS_DENIED);

			AssertEntryWritten(capture.Text(), strLibrary, strOperation, strMessage);
		}

		TEST_METHOD(NonAsciiText_IsWrittenIntact)
		{
			if (!CanCaptureDebugOutput())
				return;

			const CString strMessage = RequireSystemMessage(ERROR_ACCESS_DENIED);
			const CString strLibrary = _T("Biblioth\u00E8que");
			const CString strOperation = _T("\u65E5\u672C\u8A9E \u0416");

			DebugOutputCapture capture;
			TraceLastError(strLibrary, strOperation, ERROR_ACCESS_DENIED);

			AssertEntryWritten(capture.Text(), strLibrary, strOperation, strMessage);
		}

		TEST_METHOD(MessageWithInserts_IsWrittenWithoutExpandingThem)
		{
			if (!CanCaptureDebugOutput())
				return;

			// The text of ERROR_BAD_EXE_FORMAT starts with the insert "%1", which no argument could fill.
			const CString strMessage = RequireSystemMessage(ERROR_BAD_EXE_FORMAT);
			if (strMessage.Find(_T("%1")) < 0)
			{
				Logger::WriteMessage(L"Skipped: the system text of ERROR_BAD_EXE_FORMAT has no insert.");
				return;
			}

			DebugOutputCapture capture;
			TraceLastError(_T("Loader"), _T("CreateProcess"), ERROR_BAD_EXE_FORMAT);

			AssertEntryWritten(capture.Text(), _T("Loader"), _T("CreateProcess"), strMessage);
		}

		TEST_METHOD(UnknownErrorCode_StillWritesTheLibraryAndTheOperation)
		{
			if (!CanCaptureDebugOutput())
				return;

			for (DWORD dwError : UNKNOWN_ERRORS)
			{
				CString strOperation;
				strOperation.Format(_T("Operation 0x%08lX"), dwError);

				DebugOutputCapture capture;
				TraceLastError(_T("Crypt"), strOperation, dwError);
				const CString strOutput = capture.Text();

				const int nHeader = strOutput.Find(_T("[Crypt] ") + strOperation + _T(": "));
				Assert::IsTrue(nHeader >= 0, strOperation + _T(" was not written. Debug output:\n") + strOutput);
				Assert::IsTrue(strOutput.Find(_T('\n'), nHeader) >= 0, strOperation + _T(" has no line break. Debug output:\n") + strOutput);
			}
		}

		TEST_METHOD(ConcurrentCalls_WriteEveryEntryIntact)
		{
			if (!CanCaptureDebugOutput())
				return;

			const CString strMessage = RequireSystemMessage(ERROR_ACCESS_DENIED);

			DebugOutputCapture capture;
			RunConcurrently(CONCURRENT_THREADS, [](unsigned int nThread, WorkerFailures&)
			{
				for (unsigned int nCall = 0; nCall < TRACE_CALLS_PER_THREAD; nCall++)
				{
					CString strOperation;
					strOperation.Format(_T("call %u.%u"), nThread, nCall);
					TraceLastError(_T("Worker"), strOperation, ERROR_ACCESS_DENIED);
				}
			});

			const CString strOutput = capture.Text();
			for (unsigned int nThread = 0; nThread < CONCURRENT_THREADS; nThread++)
			{
				for (unsigned int nCall = 0; nCall < TRACE_CALLS_PER_THREAD; nCall++)
				{
					CString strOperation;
					strOperation.Format(_T("call %u.%u"), nThread, nCall);

					const CString strEntry = FormatEntry(_T("Worker"), strOperation, strMessage);
					Assert::AreEqual(1, CountEntries(strOutput, strEntry), strEntry);
				}
			}
		}
	};
}
