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

// ChecksumFileTests.cpp : unit tests for GetChecksumFile.

#include "stdafx.h"
#include "CryptographyExt.h"
#include "TestHelpers.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;
using namespace TestHelpers;

namespace CryptLibraryDemoTests
{
	namespace
	{
		/** Creates a file with the given content, runs GetChecksumFile on it and fails the test when it reports an error. */
		CString ChecksumOfContent(ALG_ID nAlgorithm, const TempDirectory& dir, const ByteVector& vContent)
		{
			const CString strPath = dir.Path(_T("content.bin"));
			Assert::IsTrue(WriteBinaryFile(strPath, vContent), L"the test file cannot be written");

			CString strResult;
			Assert::IsTrue(GetChecksumFile(nAlgorithm, strResult, strPath), L"GetChecksumFile failed");
			return strResult;
		}

		CString Describe(size_t nLength)
		{
			CString strText;
			strText.Format(_T("file length %I64u"), static_cast<ULONGLONG>(nLength));
			return strText;
		}
	}

	TEST_CLASS(GetChecksumFileTests)
	{
	public:
		TEST_ASSERTION_GUARD()

		// ------------------------------------------------------------------
		// Known answers
		// ------------------------------------------------------------------

		TEST_METHOD(Md5_OfFileContainingAbc_ReturnsTheKnownDigest)
		{
			TempDirectory dir;
			AssertStringsEqual(CString("900150983CD24FB0D6963F7D28E17F72"), ChecksumOfContent(CALG_MD5, dir, AsciiBytes("abc")));
		}

		TEST_METHOD(Sha1_OfFileContainingAbc_ReturnsTheKnownDigest)
		{
			TempDirectory dir;
			AssertStringsEqual(CString("A9993E364706816ABA3E25717850C26C9CD0D89D"), ChecksumOfContent(CALG_SHA1, dir, AsciiBytes("abc")));
		}

		TEST_METHOD(Md2AndMd4_OfFileContainingMessageDigest_ReturnTheRfcDigests)
		{
			TempDirectory dir;
			AssertStringsEqual(CString("AB4F496BFB2A530B219FF33031FE06B0"), ChecksumOfContent(CALG_MD2, dir, AsciiBytes("message digest")), _T("MD2"));
			AssertStringsEqual(CString("D9130A8164549FE818874806E1C7014B"), ChecksumOfContent(CALG_MD4, dir, AsciiBytes("message digest")), _T("MD4"));
		}

		TEST_METHOD(FileWithAllByteValues_ReturnsTheKnownDigests)
		{
			TempDirectory dir;
			AssertStringsEqual(CString("E2C865DB4162BED963BFAA9EF6AC18F0"), ChecksumOfContent(CALG_MD5, dir, AllByteValues()), _T("MD5"));
			AssertStringsEqual(CString("4916D6BDB7F78E6803698CAB32D1586EA457DFC8"), ChecksumOfContent(CALG_SHA1, dir, AllByteValues()), _T("SHA-1"));
		}

		TEST_METHOD(FileWithOneMillionAs_ReturnsTheKnownDigests)
		{
			TempDirectory dir;
			const ByteVector vContent = Repeat('a', 1000000);
			AssertStringsEqual(CString("7707D6AE4E027C70EEA2A935C2296F21"), ChecksumOfContent(CALG_MD5, dir, vContent), _T("MD5"));
			AssertStringsEqual(CString("34AA973CD4C4DAA4F61EEB2BDBAD27316534016F"), ChecksumOfContent(CALG_SHA1, dir, vContent), _T("SHA-1"));
		}

		TEST_METHOD(FileOfOneByte_ReturnsTheKnownDigests)
		{
			TempDirectory dir;
			AssertStringsEqual(CString("93B885ADFE0DA089CDF634904FD59F71"), ChecksumOfContent(CALG_MD5, dir, Repeat(0x00, 1)), _T("MD5"));
			AssertStringsEqual(CString("5BA93C9DB0CFF93F52B521D7420E43F6EDA2784F"), ChecksumOfContent(CALG_SHA1, dir, Repeat(0x00, 1)), _T("SHA-1"));
		}

		// ------------------------------------------------------------------
		// Cross check against CNG
		// ------------------------------------------------------------------

		TEST_METHOD(FilesAroundTheBlockAndPageBoundaries_MatchCng)
		{
			static const size_t arrLengths[] = { 1, 2, 55, 56, 63, 64, 65, 4095, 4096, 4097, 65535, 65536, 65537 };

			TempDirectory dir;
			for (size_t nLength : arrLengths)
			{
				const ByteVector vContent = PseudoRandomBytes(nLength, static_cast<unsigned int>(nLength));
				AssertStringsEqual(ToHex(ReferenceHash(CALG_MD5, vContent)), ChecksumOfContent(CALG_MD5, dir, vContent), Describe(nLength) + _T(", MD5"));
				AssertStringsEqual(ToHex(ReferenceHash(CALG_SHA1, vContent)), ChecksumOfContent(CALG_SHA1, dir, vContent), Describe(nLength) + _T(", SHA-1"));
			}
		}

		TEST_METHOD(Md2AndMd4_OfFiles_MatchCng)
		{
			static const size_t arrLengths[] = { 1, 15, 16, 17, 1000 };

			TempDirectory dir;
			for (size_t nLength : arrLengths)
			{
				const ByteVector vContent = PseudoRandomBytes(nLength, static_cast<unsigned int>(nLength));
				AssertStringsEqual(ToHex(ReferenceHash(CALG_MD2, vContent)), ChecksumOfContent(CALG_MD2, dir, vContent), Describe(nLength) + _T(", MD2"));
				AssertStringsEqual(ToHex(ReferenceHash(CALG_MD4, vContent)), ChecksumOfContent(CALG_MD4, dir, vContent), Describe(nLength) + _T(", MD4"));
			}
		}

		TEST_METHOD(LargeFile_MatchesCng)
		{
			TempDirectory dir;
			const ByteVector vContent = PseudoRandomBytes(5000001, 2026);

			AssertStringsEqual(ToHex(ReferenceHash(CALG_MD5, vContent)), ChecksumOfContent(CALG_MD5, dir, vContent), _T("MD5"));
			AssertStringsEqual(ToHex(ReferenceHash(CALG_SHA1, vContent)), ChecksumOfContent(CALG_SHA1, dir, vContent), _T("SHA-1"));
		}

		// ------------------------------------------------------------------
		// Format of the result
		// ------------------------------------------------------------------

		TEST_METHOD(Result_HasTwoUppercaseHexadecimalDigitsPerDigestByte)
		{
			TempDirectory dir;
			const ByteVector vContent = AsciiBytes("format check");

			Assert::AreEqual(2 * MD5CHECKSUM_LENGTH, ChecksumOfContent(CALG_MD5, dir, vContent).GetLength(), L"MD5");
			Assert::AreEqual(2 * SHA1CHECKSUM_LENGTH, ChecksumOfContent(CALG_SHA1, dir, vContent).GetLength(), L"SHA-1");
			Assert::AreEqual(2 * MD5CHECKSUM_LENGTH, ChecksumOfContent(CALG_MD2, dir, vContent).GetLength(), L"MD2");
			Assert::AreEqual(2 * MD5CHECKSUM_LENGTH, ChecksumOfContent(CALG_MD4, dir, vContent).GetLength(), L"MD4");

			const CString strResult = ChecksumOfContent(CALG_SHA1, dir, vContent);
			Assert::AreEqual(strResult.GetLength(), strResult.SpanIncluding(_T("0123456789ABCDEF")).GetLength(), strResult);
		}

		TEST_METHOD(PreviousContentOfTheResult_IsReplaced)
		{
			TempDirectory dir;
			const CString strPath = dir.Path(_T("abc.txt"));
			Assert::IsTrue(WriteBinaryFile(strPath, AsciiBytes("abc")));
			CString strResult(_T("a previous value that is much longer than any of the checksums"));

			Assert::IsTrue(GetChecksumFile(CALG_MD5, strResult, strPath));

			AssertStringsEqual(CString("900150983CD24FB0D6963F7D28E17F72"), strResult);
		}

		TEST_METHOD(SameFile_GivesTheSameChecksumEveryTime)
		{
			TempDirectory dir;
			const ByteVector vContent = PseudoRandomBytes(10000, 5);

			const CString strFirst = ChecksumOfContent(CALG_SHA1, dir, vContent);
			AssertStringsEqual(strFirst, ChecksumOfContent(CALG_SHA1, dir, vContent));
		}

		TEST_METHOD(ChangingOneByteOfTheFile_ChangesTheChecksum)
		{
			TempDirectory dir;
			ByteVector vContent = PseudoRandomBytes(10000, 6);
			const CString strBefore = ChecksumOfContent(CALG_MD5, dir, vContent);

			vContent[9999] ^= 0x80;

			Assert::AreNotEqual((LPCTSTR)strBefore, (LPCTSTR)ChecksumOfContent(CALG_MD5, dir, vContent), false);
		}

		// ------------------------------------------------------------------
		// Paths
		// ------------------------------------------------------------------

		TEST_METHOD(PathWithSpacesAndUnicodeCharacters_IsSupported)
		{
			TempDirectory dir;
			const CString strFolder = dir.CreateSubfolder(_T("sub folder \u00e9"));
			const CString strPath = strFolder + _T("\\my file \u4e2d\u6587.bin");
			Assert::IsTrue(WriteBinaryFile(strPath, AsciiBytes("abc")));

			CString strResult;
			Assert::IsTrue(GetChecksumFile(CALG_MD5, strResult, strPath));

			AssertStringsEqual(CString("900150983CD24FB0D6963F7D28E17F72"), strResult);
		}

		// ------------------------------------------------------------------
		// Failures
		// ------------------------------------------------------------------

		TEST_METHOD(EmptyFile_ReturnsFalse)
		{
			TempDirectory dir;
			const CString strPath = dir.Path(_T("empty.bin"));
			Assert::IsTrue(WriteBinaryFile(strPath, ByteVector()));
			Assert::AreEqual<ULONGLONG>(0, GetFileLength(strPath), L"the test file must be empty");

			CString strResult;
			Assert::IsFalse(GetChecksumFile(CALG_MD5, strResult, strPath));
		}

		TEST_METHOD(MissingFile_ReturnsFalse)
		{
			TempDirectory dir;
			CString strResult;
			Assert::IsFalse(GetChecksumFile(CALG_MD5, strResult, dir.Path(_T("missing.bin"))));
		}

		TEST_METHOD(MissingFolder_ReturnsFalse)
		{
			TempDirectory dir;
			CString strResult;
			Assert::IsFalse(GetChecksumFile(CALG_MD5, strResult, dir.Path(_T("no such folder\\file.bin"))));
		}

		TEST_METHOD(Directory_ReturnsFalse)
		{
			TempDirectory dir;
			const CString strFolder = dir.CreateSubfolder(_T("folder"));
			CString strResult;
			Assert::IsFalse(GetChecksumFile(CALG_MD5, strResult, strFolder));
		}

		TEST_METHOD(EmptyPath_ReturnsFalse)
		{
			CString strResult;
			Assert::IsFalse(GetChecksumFile(CALG_MD5, strResult, _T("")));
		}

		TEST_METHOD(FileThatCannotBeOpened_ReturnsFalseAndSucceedsOnceItIsReleased)
		{
			TempDirectory dir;
			const CString strPath = dir.Path(_T("busy.bin"));
			Assert::IsTrue(WriteBinaryFile(strPath, AsciiBytes("abc")));

			{
				// The file is opened with MFC's default sharing mode, which does not tolerate another open handle.
				OpenFileHandle handle(strPath);
				Assert::IsTrue(handle.IsOpen(), L"the test cannot open the file");

				CString strBusyResult;
				Assert::IsFalse(GetChecksumFile(CALG_MD5, strBusyResult, strPath));
			}

			CString strResult;
			Assert::IsTrue(GetChecksumFile(CALG_MD5, strResult, strPath));
			AssertStringsEqual(CString("900150983CD24FB0D6963F7D28E17F72"), strResult);
		}

		TEST_METHOD(UnsupportedAlgorithm_ReturnsFalse)
		{
			TempDirectory dir;
			const CString strPath = dir.Path(_T("abc.bin"));
			Assert::IsTrue(WriteBinaryFile(strPath, AsciiBytes("abc")));

			CString strResult;
			Assert::IsFalse(GetChecksumFile(CALG_RC4, strResult, strPath), L"RC4 is a cipher");
			Assert::IsFalse(GetChecksumFile(CALG_SHA_256, strResult, strPath), L"SHA-2 is a documented limitation");
			Assert::IsFalse(GetChecksumFile(0xFFFFFFFFu, strResult, strPath), L"unknown algorithm");
		}

		// ------------------------------------------------------------------
		// Side effects
		// ------------------------------------------------------------------

		TEST_METHOD(AfterASuccessfulCall_TheFileIsClosedAndUnchanged)
		{
			TempDirectory dir;
			const CString strPath = dir.Path(_T("data.bin"));
			const ByteVector vContent = PseudoRandomBytes(3000, 9);
			Assert::IsTrue(WriteBinaryFile(strPath, vContent));

			CString strResult;
			Assert::IsTrue(GetChecksumFile(CALG_SHA1, strResult, strPath));

			AssertBytesEqual(vContent, ReadBinaryFile(strPath), L"the content must not change");
			Assert::IsTrue(::DeleteFile(strPath) != FALSE, L"a handle to the file was left open");
		}

		TEST_METHOD(AfterAFailedCall_TheFileIsClosed)
		{
			TempDirectory dir;
			const CString strPath = dir.Path(_T("data.bin"));
			Assert::IsTrue(WriteBinaryFile(strPath, AsciiBytes("abc")));

			CString strResult;
			Assert::IsFalse(GetChecksumFile(CALG_RC4, strResult, strPath));

			Assert::IsTrue(::DeleteFile(strPath) != FALSE, L"a handle to the file was left open");
		}
	};
}
