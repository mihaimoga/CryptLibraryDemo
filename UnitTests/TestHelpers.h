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

// TestHelpers.h : shared helpers for the CryptLibraryDemo unit tests.
// Include stdafx.h before this header.

#pragma once

#include "CppUnitTest.h"

#include <wincrypt.h>

#include <filesystem>
#include <functional>
#include <mutex>
#include <vector>

namespace TestHelpers
{
	/** Raw bytes: plaintext, ciphertext, digests and secret keys. */
	typedef std::vector<BYTE> ByteVector;

	// ---------------------------------------------------------------------
	// Test data. These helpers deliberately do not use the code under test.
	// ---------------------------------------------------------------------

	/** Decodes a hexadecimal string (either case, spaces ignored). */
	ByteVector FromHex(LPCSTR lpszHexa);

	/** Formats bytes as uppercase hexadecimal. */
	CString ToHex(const BYTE* lpData, size_t nLength);
	CString ToHex(const ByteVector& vData);

	/** The bytes of an ASCII string, without a terminator. */
	ByteVector AsciiBytes(LPCSTR lpszText);

	/**
	 * The UTF-16 bytes of a string including its terminating NUL. This is what
	 * GetChecksumString hashes and what the dialog passes as the secret key.
	 */
	ByteVector Utf16Bytes(const CString& strText);

	/** One byte value repeated nCount times. */
	ByteVector Repeat(BYTE nValue, size_t nCount);

	/** The 256 byte values 0x00..0xFF in ascending order. */
	ByteVector AllByteValues();

	/** Deterministic pseudo-random bytes, so that a failure can be reproduced. */
	ByteVector PseudoRandomBytes(size_t nLength, unsigned int nSeed);

	// ---------------------------------------------------------------------
	// Reference implementations used as independent oracles.
	// ---------------------------------------------------------------------

	/** MD2, MD4, MD5 or SHA-1 digest computed with CNG (BCrypt) instead of CryptoAPI. */
	ByteVector ReferenceHash(ALG_ID nAlgorithm, const ByteVector& vData);

	/** RC4 keyed with MD5(secret), which is how EncryptBuffer derives its RC4 session key. */
	ByteVector ReferenceRc4(const ByteVector& vSecret, const ByteVector& vData);

	/**
	 * ReferenceHash and ReferenceRc4 for the threads of RunConcurrently: they return false
	 * instead of failing the test, because such a thread must not assert (see WorkerFailures).
	 */
	bool TryReferenceHash(ALG_ID nAlgorithm, const ByteVector& vData, ByteVector& vHash);
	bool TryReferenceRc4(const ByteVector& vSecret, const ByteVector& vData, ByteVector& vResult);

	// ---------------------------------------------------------------------
	// Assertions
	// ---------------------------------------------------------------------

	/** Fails the running test, showing the first difference, unless both sequences are equal. */
	void AssertBytesEqual(const ByteVector& vExpected, const ByteVector& vActual, LPCWSTR lpszMessage = nullptr);

	/** Fails the running test when both sequences are equal. */
	void AssertBytesNotEqual(const ByteVector& vUnexpected, const ByteVector& vActual, LPCWSTR lpszMessage = nullptr);

	/** Fails the running test unless both strings are identical (case sensitive). */
	void AssertStringsEqual(const CString& strExpected, const CString& strActual, LPCTSTR lpszMessage = nullptr);

	// ---------------------------------------------------------------------
	// File system
	// ---------------------------------------------------------------------

	/** A unique directory below %TEMP% that is removed, with its content, on destruction. */
	class TempDirectory
	{
	public:
		TempDirectory();
		~TempDirectory();
		TempDirectory(const TempDirectory&) = delete;
		TempDirectory& operator=(const TempDirectory&) = delete;

		/** Full path of an entry inside the directory; the entry itself is not created. */
		CString Path(LPCTSTR lpszName) const;

		/** Creates a sub folder (and its parents) and returns its full path. */
		CString CreateSubfolder(LPCTSTR lpszName) const;

	private:
		std::filesystem::path m_pathRoot;
	};

	/** Creates or overwrites a file with the given content. */
	bool WriteBinaryFile(LPCTSTR lpszPath, const ByteVector& vData);

	/** Reads a whole file; an empty vector means an empty or unreadable file. */
	ByteVector ReadBinaryFile(LPCTSTR lpszPath);

	bool PathExists(LPCTSTR lpszPath);

	ULONGLONG GetFileLength(LPCTSTR lpszPath);

	/**
	 * Keeps a file open with every sharing flag allowed. The code under test opens
	 * files with MFC's default share mode, which is exclusive, so this makes it fail.
	 */
	class OpenFileHandle
	{
	public:
		explicit OpenFileHandle(LPCTSTR lpszPath);
		~OpenFileHandle();
		OpenFileHandle(const OpenFileHandle&) = delete;
		OpenFileHandle& operator=(const OpenFileHandle&) = delete;

		bool IsOpen() const;

	private:
		HANDLE m_hFile;
	};

	// ---------------------------------------------------------------------
	// Concurrency
	// ---------------------------------------------------------------------

	/**
	 * The problems found by the threads of RunConcurrently. Such a thread must not call Assert,
	 * nor a helper that does: on a thread the test framework did not start, a failed assertion
	 * raises an exception that nothing catches, and the whole test host ends, which loses the
	 * results of every test that has not run yet. A thread calls Add instead.
	 */
	class WorkerFailures
	{
	public:
		/** Records a problem; safe to call from any thread. */
		void Add(const CString& strMessage);

		/** Fails the running test, listing the first problems, when any was recorded. */
		void AssertNone() const;

	private:
		mutable std::mutex m_mutex;
		std::vector<CString> m_arrMessages;
	};

	/**
	 * Runs fnWorker on nThreads threads that are released together, waits for all of them and
	 * fails the running test when any of them recorded a problem. An exception that escapes
	 * fnWorker is recorded as a problem too. Call it from the test method, not from a thread.
	 */
	void RunConcurrently(unsigned int nThreads, const std::function<void(unsigned int nThread, WorkerFailures& failures)>& fnWorker);

	// ---------------------------------------------------------------------
	// Diagnostics
	// ---------------------------------------------------------------------

	/**
	 * Captures the text the process writes with OutputDebugString while the object is alive.
	 * A debugger consumes that text before it can be captured, see IsSupported().
	 */
	class DebugOutputCapture
	{
	public:
		DebugOutputCapture();
		~DebugOutputCapture();
		DebugOutputCapture(const DebugOutputCapture&) = delete;
		DebugOutputCapture& operator=(const DebugOutputCapture&) = delete;

		/** False when a debugger is attached. */
		static bool IsSupported();

		/** Everything captured since construction. */
		CString Text() const;
	};

	/**
	 * Debug builds report a failed ASSERT/VERIFY with a modal dialog. The monitor
	 * replaces that dialog: it records the report so a test can fail instead of hanging.
	 * It does nothing in Release builds, where ASSERT is compiled out.
	 */
	class AssertionMonitor
	{
	public:
		static void Install();
		static void Uninstall();

		/** Forgets the assertions recorded so far. */
		static void Reset();

		/** Fails the running test when an assertion was reported since Reset(). */
		static void VerifyNoAssertions();
	};
}

/**
 * Per-test hooks that fail a test when the code under test raised an ASSERT or
 * VERIFY (Debug builds). Use it once per TEST_CLASS, after "public:".
 */
#define TEST_ASSERTION_GUARD() \
	TEST_METHOD_INITIALIZE(ResetAssertionMonitor) { TestHelpers::AssertionMonitor::Reset(); } \
	TEST_METHOD_CLEANUP(VerifyAssertionMonitor) { TestHelpers::AssertionMonitor::VerifyNoAssertions(); }
