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

// ChecksumStringTests.cpp : unit tests for GetChecksumString.

#include "stdafx.h"
#include "CryptographyExt.h"
#include "TestHelpers.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;
using namespace TestHelpers;

namespace CryptLibraryDemoTests
{
	namespace
	{
		struct StringAnswer
		{
			LPCTSTR lpszText;
			LPCSTR lpszMd5;
			LPCSTR lpszSha1;
		};

		// The expected digests were computed over the UTF-16 text including its terminating NUL.
		const StringAnswer ANSWERS[] =
		{
			{ _T(""), "C4103F122D27677C9DB144CAE1394A66", "1489F923C4DCA729178B3E3233458550D8DDDF29" },
			{ _T("abc"), "0325B2BC5BC6ECFBAC751818498ECE3F", "710A9AB5E5CDA543FA5F3DE349A1A1466E0104AD" },
			{ _T("ABC"), "EBBD00CFBF4377D11FF2E02C52B41E0D", "078CC3CA30E5968F7DA594EDDB008033DF5892BB" },
			{ _T("Hello, CryptoAPI!"), "FE6F7BBFE717B84A957029302E21EDF9", "457D443AB180FB21BB67E832FCD929BE0F2D220A" },
			{ _T("\u00dc\u00f1\u00ee\u00e7\u00f6d\u00e9 \u20ac \u4e2d\u6587"), "5638D0491D31D9F6B0CE174B19C283E5", "7BF4FE86953639DE0C271629E8F836277048FACE" },
		};

		/** Runs GetChecksumString and fails the test when it reports an error. */
		CString ChecksumOf(ALG_ID nAlgorithm, const CString& strText)
		{
			CString strResult;
			Assert::IsTrue(GetChecksumString(nAlgorithm, strResult, strText), L"GetChecksumString failed");
			return strResult;
		}

		bool IsUppercaseHexadecimal(const CString& strText)
		{
			for (int nIndex = 0; nIndex < strText.GetLength(); nIndex++)
			{
				const TCHAR chDigit = strText[nIndex];
				const bool bDigit = (chDigit >= _T('0') && chDigit <= _T('9'));
				const bool bLetter = (chDigit >= _T('A') && chDigit <= _T('F'));
				if (!bDigit && !bLetter)
					return false;
			}
			return true;
		}

		/** The digest of the UTF-16 text including its terminating NUL, as uppercase hexadecimal, computed with CNG. */
		CString ReferenceChecksumOf(ALG_ID nAlgorithm, const CString& strText)
		{
			return ToHex(ReferenceHash(nAlgorithm, Utf16Bytes(strText)));
		}
	}

	TEST_CLASS(GetChecksumStringTests)
	{
	public:
		TEST_ASSERTION_GUARD()

		// ------------------------------------------------------------------
		// Known answers
		// ------------------------------------------------------------------

		TEST_METHOD(Md5_KnownStrings_ReturnTheExpectedDigest)
		{
			for (const StringAnswer& answer : ANSWERS)
				AssertStringsEqual(CString(answer.lpszMd5), ChecksumOf(CALG_MD5, answer.lpszText), answer.lpszText);
		}

		TEST_METHOD(Sha1_KnownStrings_ReturnTheExpectedDigest)
		{
			for (const StringAnswer& answer : ANSWERS)
				AssertStringsEqual(CString(answer.lpszSha1), ChecksumOf(CALG_SHA1, answer.lpszText), answer.lpszText);
		}

		TEST_METHOD(Md5_OfTenThousandAs_ReturnsTheExpectedDigest)
		{
			const CString strText(_T('a'), 10000);
			AssertStringsEqual(CString("71BF2DE4A4EA0F6764237C44EBC1092E"), ChecksumOf(CALG_MD5, strText));
		}

		TEST_METHOD(Sha1_OfTenThousandAs_ReturnsTheExpectedDigest)
		{
			const CString strText(_T('a'), 10000);
			AssertStringsEqual(CString("83C8F7EFF8168BD257E8F708793A0547D998384A"), ChecksumOf(CALG_SHA1, strText));
		}

		TEST_METHOD(Md2AndMd4_OfAbc_ReturnTheExpectedDigests)
		{
			AssertStringsEqual(CString("7D9A94F50A3665620357D35081BF912E"), ChecksumOf(CALG_MD2, _T("abc")), _T("MD2"));
			AssertStringsEqual(CString("8A133163FBA523AA53BB21C2232EF6F3"), ChecksumOf(CALG_MD4, _T("abc")), _T("MD4"));
		}

		// ------------------------------------------------------------------
		// Format of the result
		// ------------------------------------------------------------------

		TEST_METHOD(Result_HasTwoHexadecimalDigitsPerDigestByte)
		{
			Assert::AreEqual(2 * MD5CHECKSUM_LENGTH, ChecksumOf(CALG_MD5, _T("abc")).GetLength(), L"MD5");
			Assert::AreEqual(2 * SHA1CHECKSUM_LENGTH, ChecksumOf(CALG_SHA1, _T("abc")).GetLength(), L"SHA-1");
			Assert::AreEqual(2 * MD5CHECKSUM_LENGTH, ChecksumOf(CALG_MD2, _T("abc")).GetLength(), L"MD2");
			Assert::AreEqual(2 * MD5CHECKSUM_LENGTH, ChecksumOf(CALG_MD4, _T("abc")).GetLength(), L"MD4");
		}

		TEST_METHOD(Result_UsesOnlyUppercaseHexadecimalDigits)
		{
			static const ALG_ID arrAlgorithms[] = { CALG_MD2, CALG_MD4, CALG_MD5, CALG_SHA1 };

			bool bSawLetter = false;
			for (ALG_ID nAlgorithm : arrAlgorithms)
			{
				for (int nLength = 0; nLength < 25; nLength++)
				{
					const CString strResult = ChecksumOf(nAlgorithm, CString(_T('x'), nLength));
					Assert::IsTrue(IsUppercaseHexadecimal(strResult), strResult);
					bSawLetter = bSawLetter || (strResult.FindOneOf(_T("ABCDEF")) >= 0);
				}
			}
			Assert::IsTrue(bSawLetter, L"the samples must contain the letters A-F, otherwise the test proves nothing");
		}

		TEST_METHOD(PreviousContentOfTheResult_IsReplaced)
		{
			CString strResult(_T("a previous value that is much longer than any of the checksums"));

			Assert::IsTrue(GetChecksumString(CALG_MD5, strResult, _T("abc")));

			AssertStringsEqual(CString("0325B2BC5BC6ECFBAC751818498ECE3F"), strResult);
		}

		TEST_METHOD(ResultThatIsReused_NeverKeepsCharactersOfALongerDigest)
		{
			CString strResult;

			Assert::IsTrue(GetChecksumString(CALG_SHA1, strResult, _T("abc")));
			AssertStringsEqual(CString("710A9AB5E5CDA543FA5F3DE349A1A1466E0104AD"), strResult, _T("SHA-1"));

			Assert::IsTrue(GetChecksumString(CALG_MD5, strResult, _T("abc")));
			AssertStringsEqual(CString("0325B2BC5BC6ECFBAC751818498ECE3F"), strResult, _T("MD5 after SHA-1"));

			Assert::IsTrue(GetChecksumString(CALG_SHA1, strResult, _T("abc")));
			AssertStringsEqual(CString("710A9AB5E5CDA543FA5F3DE349A1A1466E0104AD"), strResult, _T("SHA-1 after MD5"));
		}

		// ------------------------------------------------------------------
		// What is hashed
		// ------------------------------------------------------------------

		TEST_METHOD(HashedData_IsTheUtf16TextIncludingTheTerminatingNul)
		{
			const CString strText(_T("abc"));
			const ByteVector vUtf16WithNul = Utf16Bytes(strText);
			ByteVector vUtf16WithoutNul = vUtf16WithNul;
			vUtf16WithoutNul.resize(vUtf16WithoutNul.size() - sizeof(TCHAR));

			const CString strActual = ChecksumOf(CALG_MD5, strText);

			AssertStringsEqual(ToHex(ReferenceHash(CALG_MD5, vUtf16WithNul)), strActual, _T("UTF-16 with the NUL"));
			Assert::AreNotEqual((LPCTSTR)ToHex(ReferenceHash(CALG_MD5, vUtf16WithoutNul)), (LPCTSTR)strActual, false, L"the NUL must be hashed");
			Assert::AreNotEqual((LPCTSTR)ToHex(ReferenceHash(CALG_MD5, AsciiBytes("abc"))), (LPCTSTR)strActual, false, L"the text is not hashed as ANSI");
		}

		TEST_METHOD(AllAlgorithms_MatchCngForTheSameUtf16Data)
		{
			static const ALG_ID arrAlgorithms[] = { CALG_MD2, CALG_MD4, CALG_MD5, CALG_SHA1 };
			static LPCTSTR arrNames[] = { _T("MD2"), _T("MD4"), _T("MD5"), _T("SHA-1") };

			for (size_t nIndex = 0; nIndex < _countof(arrAlgorithms); nIndex++)
			{
				for (const StringAnswer& answer : ANSWERS)
					AssertStringsEqual(ReferenceChecksumOf(arrAlgorithms[nIndex], answer.lpszText), ChecksumOf(arrAlgorithms[nIndex], answer.lpszText), arrNames[nIndex]);
			}
		}

		TEST_METHOD(CharactersOutsideTheBasicMultilingualPlane_AreHashedAsSurrogatePairs)
		{
			// U+1F600 is stored as the surrogate pair D83D DE00.
			const CString strText(_T("smile \U0001F600"));
			Assert::AreEqual(8, strText.GetLength(), L"the test string must hold a surrogate pair");
			AssertStringsEqual(ReferenceChecksumOf(CALG_SHA1, strText), ChecksumOf(CALG_SHA1, strText));
		}

		TEST_METHOD(EmbeddedNulCharacter_DoesNotTruncateTheText)
		{
			CString strText(_T("ab"));
			strText.AppendChar(_T('\0'));
			strText += _T("cd");
			Assert::AreEqual(5, strText.GetLength(), L"the test string must keep the characters after the NUL");

			const CString strActual = ChecksumOf(CALG_MD5, strText);

			AssertStringsEqual(ReferenceChecksumOf(CALG_MD5, strText), strActual);
			Assert::AreNotEqual((LPCTSTR)ChecksumOf(CALG_MD5, _T("ab")), (LPCTSTR)strActual, false, L"the characters after the NUL count");
		}

		TEST_METHOD(LongStrings_MatchCng)
		{
			static const int arrLengths[] = { 1000, 4095, 4096, 4097, 100000 };

			for (int nLength : arrLengths)
			{
				CString strText;
				for (int nIndex = 0; nIndex < nLength; nIndex++)
					strText.AppendChar(static_cast<TCHAR>(_T('A') + (nIndex % 26)));

				CString strMessage;
				strMessage.Format(_T("%d characters"), nLength);
				AssertStringsEqual(ReferenceChecksumOf(CALG_MD5, strText), ChecksumOf(CALG_MD5, strText), strMessage);
				AssertStringsEqual(ReferenceChecksumOf(CALG_SHA1, strText), ChecksumOf(CALG_SHA1, strText), strMessage);
			}
		}

		TEST_METHOD(StringsThatDifferOnlyInCase_GiveDifferentChecksums)
		{
			Assert::AreNotEqual((LPCTSTR)ChecksumOf(CALG_MD5, _T("abc")), (LPCTSTR)ChecksumOf(CALG_MD5, _T("ABC")), false, L"MD5");
			Assert::AreNotEqual((LPCTSTR)ChecksumOf(CALG_SHA1, _T("abc")), (LPCTSTR)ChecksumOf(CALG_SHA1, _T("ABC")), false, L"SHA-1");
		}

		TEST_METHOD(SameString_GivesTheSameChecksumEveryTime)
		{
			const CString strFirst = ChecksumOf(CALG_SHA1, _T("repeatable"));
			AssertStringsEqual(strFirst, ChecksumOf(CALG_SHA1, _T("repeatable")));
			AssertStringsEqual(strFirst, ChecksumOf(CALG_SHA1, _T("repeatable")));
		}

		// ------------------------------------------------------------------
		// Failures
		// ------------------------------------------------------------------

		TEST_METHOD(AlgorithmsThatAreNotSupportedHashes_ReturnFalse)
		{
			// The SHA-2 hashes are a documented limitation (README, "Limitations").
			static const ALG_ID arrAlgorithms[] = { CALG_RC4, CALG_3DES, CALG_AES_128, CALG_SHA_256, CALG_SHA_512, 0xFFFFFFFFu };

			for (ALG_ID nAlgorithm : arrAlgorithms)
			{
				CString strResult;
				CString strMessage;
				strMessage.Format(_T("algorithm 0x%08X"), nAlgorithm);
				Assert::IsFalse(GetChecksumString(nAlgorithm, strResult, _T("abc")), strMessage);
			}
		}

		TEST_METHOD(FailureOfAnUnsupportedAlgorithm_ReportsTheFailedStepOnTheDebugOutput)
		{
			if (!DebugOutputCapture::IsSupported())
			{
				Logger::WriteMessage(L"Skipped: a debugger is attached and consumes the debug output.");
				return;
			}

			DebugOutputCapture capture;
			CString strResult;
			Assert::IsFalse(GetChecksumString(CALG_RC4, strResult, _T("abc")));

			const CString strOutput = capture.Text();
			Assert::IsTrue(strOutput.Find(_T("[Crypt] CryptCreateHash: ")) >= 0, strOutput);
		}
	};
}
