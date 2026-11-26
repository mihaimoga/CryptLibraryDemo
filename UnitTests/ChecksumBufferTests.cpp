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

// ChecksumBufferTests.cpp : unit tests for GetChecksumBuffer.

#include "stdafx.h"
#include "CryptographyExt.h"
#include "TestHelpers.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;
using namespace TestHelpers;

namespace CryptLibraryDemoTests
{
	namespace
	{
		struct KnownAnswer
		{
			LPCSTR lpszInput;
			LPCSTR lpszDigest;
		};

		struct BlockBoundaryAnswer
		{
			size_t nLength; // number of 'a' characters
			LPCSTR lpszMd5;
			LPCSTR lpszSha1;
		};

		/** Runs GetChecksumBuffer over a copy of the input; an empty result means the call failed. */
		ByteVector Checksum(ALG_ID nAlgorithm, ByteVector vInput)
		{
			ByteVector vDigest(64, 0xCC);
			DWORD dwLength = static_cast<DWORD>(vDigest.size());
			if (!GetChecksumBuffer(nAlgorithm, vDigest.data(), dwLength, vInput.data(), static_cast<DWORD>(vInput.size())))
				return ByteVector();

			vDigest.resize(dwLength);
			return vDigest;
		}

		CString Describe(LPCTSTR lpszAlgorithm, size_t nLength)
		{
			CString strText;
			strText.Format(_T("%s, input length %I64u"), lpszAlgorithm, static_cast<ULONGLONG>(nLength));
			return strText;
		}

		const unsigned int CONCURRENT_THREADS = 4;
		const unsigned int CONCURRENT_ITERATIONS = 25;
	}

	TEST_CLASS(GetChecksumBufferTests)
	{
	public:
		TEST_ASSERTION_GUARD()

		// ------------------------------------------------------------------
		// Known answers: published vectors that do not depend on any library
		// ------------------------------------------------------------------

		TEST_METHOD(Md5_OfAbc_ReturnsRfc1321Digest)
		{
			AssertBytesEqual(FromHex("900150983CD24FB0D6963F7D28E17F72"), Checksum(CALG_MD5, AsciiBytes("abc")));
		}

		TEST_METHOD(Sha1_OfAbc_ReturnsFips180Digest)
		{
			AssertBytesEqual(FromHex("A9993E364706816ABA3E25717850C26C9CD0D89D"), Checksum(CALG_SHA1, AsciiBytes("abc")));
		}

		TEST_METHOD(Md5_OfQuickBrownFox_ReturnsKnownDigest)
		{
			AssertBytesEqual(FromHex("9E107D9D372BB6826BD81D3542A419D6"),
				Checksum(CALG_MD5, AsciiBytes("The quick brown fox jumps over the lazy dog")));
		}

		TEST_METHOD(Sha1_OfQuickBrownFox_ReturnsKnownDigest)
		{
			AssertBytesEqual(FromHex("2FD4E1C67A2D28FCED849EE1BB76E7391B93EB12"),
				Checksum(CALG_SHA1, AsciiBytes("The quick brown fox jumps over the lazy dog")));
		}

		TEST_METHOD(Md5_OfOneMillionAs_ReturnsKnownDigest)
		{
			AssertBytesEqual(FromHex("7707D6AE4E027C70EEA2A935C2296F21"), Checksum(CALG_MD5, Repeat('a', 1000000)));
		}

		TEST_METHOD(Sha1_OfOneMillionAs_ReturnsFips180Digest)
		{
			AssertBytesEqual(FromHex("34AA973CD4C4DAA4F61EEB2BDBAD27316534016F"), Checksum(CALG_SHA1, Repeat('a', 1000000)));
		}

		TEST_METHOD(Md5_OfAllByteValues_ReturnsKnownDigest)
		{
			AssertBytesEqual(FromHex("E2C865DB4162BED963BFAA9EF6AC18F0"), Checksum(CALG_MD5, AllByteValues()));
		}

		TEST_METHOD(Sha1_OfAllByteValues_ReturnsKnownDigest)
		{
			AssertBytesEqual(FromHex("4916D6BDB7F78E6803698CAB32D1586EA457DFC8"), Checksum(CALG_SHA1, AllByteValues()));
		}

		TEST_METHOD(Md5_OfSingleZeroByte_ReturnsKnownDigest)
		{
			AssertBytesEqual(FromHex("93B885ADFE0DA089CDF634904FD59F71"), Checksum(CALG_MD5, Repeat(0x00, 1)));
		}

		TEST_METHOD(Sha1_OfSingleZeroByte_ReturnsKnownDigest)
		{
			AssertBytesEqual(FromHex("5BA93C9DB0CFF93F52B521D7420E43F6EDA2784F"), Checksum(CALG_SHA1, Repeat(0x00, 1)));
		}

		TEST_METHOD(Md5_OfSingleLetter_ReturnsKnownDigest)
		{
			AssertBytesEqual(FromHex("7FC56270E7A70FA81A5935B72EACBE29"), Checksum(CALG_MD5, AsciiBytes("A")));
		}

		TEST_METHOD(Sha1_OfSingleLetter_ReturnsKnownDigest)
		{
			AssertBytesEqual(FromHex("6DCD4CE23D88E2EE9568BA546C007C63D9131C1B"), Checksum(CALG_SHA1, AsciiBytes("A")));
		}

		TEST_METHOD(Md5AndSha1_AroundTheBlockBoundaries_ReturnKnownDigests)
		{
			// MD5 and SHA-1 process 64 byte blocks and pad the last one, so the
			// interesting input lengths are just below, at and above 56 and 64.
			static const BlockBoundaryAnswer arrAnswers[] =
			{
				{ 55, "EF1772B6DFF9A122358552954AD0DF65", "C1C8BBDC22796E28C0E15163D20899B65621D65A" },
				{ 56, "3B0C8AC703F828B04C6C197006D17218", "C2DB330F6083854C99D4B5BFB6E8F29F201BE699" },
				{ 57, "652B906D60AF96844EBD21B674F35E93", "F08F24908D682555111BE7FF6F004E78283D989A" },
				{ 63, "B06521F39153D618550606BE297466D5", "03F09F5B158A7A8CDAD920BDDC29B81C18A551F5" },
				{ 64, "014842D480B571495A4A0363793F7367", "0098BA824B5C16427BD7A1122A5A442A25EC644D" },
				{ 65, "C743A45E0D2E6A95CB859ADAE0248435", "11655326C708D70319BE2610E8A57D9A5B959D3B" },
				{ 119, "8A7BD0732ED6A28CE75F6DABC90E1613", "EE971065AAA017E0632A8CA6C77BB3BF8B1DFC56" },
				{ 120, "5F61C0CCAD4CAC44C75FF505E1F1E537", "F34C1488385346A55709BA056DDD08280DD4C6D6" },
				{ 128, "E510683B3F5FFE4093D021808BC6FF70", "AD5B3FDBCB526778C2839D2F151EA753995E26A0" },
			};

			for (const BlockBoundaryAnswer& answer : arrAnswers)
			{
				AssertBytesEqual(FromHex(answer.lpszMd5), Checksum(CALG_MD5, Repeat('a', answer.nLength)), Describe(_T("MD5"), answer.nLength));
				AssertBytesEqual(FromHex(answer.lpszSha1), Checksum(CALG_SHA1, Repeat('a', answer.nLength)), Describe(_T("SHA-1"), answer.nLength));
			}
		}

		TEST_METHOD(Md2_Rfc1319TestSuite_ReturnsPublishedDigests)
		{
			// The empty message of the RFC cannot be hashed: GetChecksumBuffer requires a non-empty input.
			static const KnownAnswer arrAnswers[] =
			{
				{ "a", "32EC01EC4A6DAC72C0AB96FB34C0B5D1" },
				{ "abc", "DA853B0D3F88D99B30283A69E6DED6BB" },
				{ "message digest", "AB4F496BFB2A530B219FF33031FE06B0" },
				{ "abcdefghijklmnopqrstuvwxyz", "4E8DDFF3650292AB5A4108C3AA47940B" },
				{ "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "DA33DEF2A42DF13975352846C30338CD" },
				{ "12345678901234567890123456789012345678901234567890123456789012345678901234567890", "D5976F79D83D3A0DC9806C3C66F3EFD8" },
			};

			for (const KnownAnswer& answer : arrAnswers)
				AssertBytesEqual(FromHex(answer.lpszDigest), Checksum(CALG_MD2, AsciiBytes(answer.lpszInput)), CString(answer.lpszInput));
		}

		TEST_METHOD(Md4_Rfc1320TestSuite_ReturnsPublishedDigests)
		{
			static const KnownAnswer arrAnswers[] =
			{
				{ "a", "BDE52CB31DE33E46245E05FBDBD6FB24" },
				{ "abc", "A448017AAF21D8525FC10AE87AA6729D" },
				{ "message digest", "D9130A8164549FE818874806E1C7014B" },
				{ "abcdefghijklmnopqrstuvwxyz", "D79E1C308AA5BBCDEEA8ED63DF412DA9" },
				{ "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "043F8582F241DB351CE627E153E7F0E4" },
				{ "12345678901234567890123456789012345678901234567890123456789012345678901234567890", "E33B4DDC9C38F2199C3E7B164FCC0536" },
			};

			for (const KnownAnswer& answer : arrAnswers)
				AssertBytesEqual(FromHex(answer.lpszDigest), Checksum(CALG_MD4, AsciiBytes(answer.lpszInput)), CString(answer.lpszInput));
		}

		// ------------------------------------------------------------------
		// Cross check against CNG (BCrypt) for many input sizes and contents
		// ------------------------------------------------------------------

		TEST_METHOD(Md5_InputsOfLength1To130_MatchCng)
		{
			for (size_t nLength = 1; nLength <= 130; nLength++)
			{
				const ByteVector vInput = PseudoRandomBytes(nLength, static_cast<unsigned int>(nLength));
				AssertBytesEqual(ReferenceHash(CALG_MD5, vInput), Checksum(CALG_MD5, vInput), Describe(_T("MD5"), nLength));
			}
		}

		TEST_METHOD(Sha1_InputsOfLength1To130_MatchCng)
		{
			for (size_t nLength = 1; nLength <= 130; nLength++)
			{
				const ByteVector vInput = PseudoRandomBytes(nLength, static_cast<unsigned int>(nLength));
				AssertBytesEqual(ReferenceHash(CALG_SHA1, vInput), Checksum(CALG_SHA1, vInput), Describe(_T("SHA-1"), nLength));
			}
		}

		TEST_METHOD(Md2AndMd4_InputsOfLength1To70_MatchCng)
		{
			for (size_t nLength = 1; nLength <= 70; nLength++)
			{
				const ByteVector vInput = PseudoRandomBytes(nLength, static_cast<unsigned int>(nLength));
				AssertBytesEqual(ReferenceHash(CALG_MD2, vInput), Checksum(CALG_MD2, vInput), Describe(_T("MD2"), nLength));
				AssertBytesEqual(ReferenceHash(CALG_MD4, vInput), Checksum(CALG_MD4, vInput), Describe(_T("MD4"), nLength));
			}
		}

		TEST_METHOD(AllAlgorithms_LargeInputs_MatchCng)
		{
			static const size_t arrLengths[] = { 255, 256, 257, 511, 512, 513, 1000, 4095, 4096, 4097, 65535, 65536, 65537, 1048576 };
			static const ALG_ID arrAlgorithms[] = { CALG_MD2, CALG_MD4, CALG_MD5, CALG_SHA1 };
			static LPCTSTR arrNames[] = { _T("MD2"), _T("MD4"), _T("MD5"), _T("SHA-1") };

			for (size_t nLength : arrLengths)
			{
				const ByteVector vInput = PseudoRandomBytes(nLength, static_cast<unsigned int>(nLength));
				for (size_t nIndex = 0; nIndex < _countof(arrAlgorithms); nIndex++)
					AssertBytesEqual(ReferenceHash(arrAlgorithms[nIndex], vInput), Checksum(arrAlgorithms[nIndex], vInput), Describe(arrNames[nIndex], nLength));
			}
		}

		TEST_METHOD(Md5AndSha1_EverySingleByteInput_MatchCng)
		{
			for (unsigned int nValue = 0; nValue < 256; nValue++)
			{
				const ByteVector vInput = Repeat(static_cast<BYTE>(nValue), 1);
				AssertBytesEqual(ReferenceHash(CALG_MD5, vInput), Checksum(CALG_MD5, vInput), Describe(_T("MD5"), nValue));
				AssertBytesEqual(ReferenceHash(CALG_SHA1, vInput), Checksum(CALG_SHA1, vInput), Describe(_T("SHA-1"), nValue));
			}
		}

		// ------------------------------------------------------------------
		// Output size handling
		// ------------------------------------------------------------------

		TEST_METHOD(DigestLength_ReflectsTheAlgorithm)
		{
			Assert::AreEqual<size_t>(16, Checksum(CALG_MD2, AsciiBytes("abc")).size(), L"MD2");
			Assert::AreEqual<size_t>(16, Checksum(CALG_MD4, AsciiBytes("abc")).size(), L"MD4");
			Assert::AreEqual<size_t>(MD5CHECKSUM_LENGTH, Checksum(CALG_MD5, AsciiBytes("abc")).size(), L"MD5");
			Assert::AreEqual<size_t>(SHA1CHECKSUM_LENGTH, Checksum(CALG_SHA1, AsciiBytes("abc")).size(), L"SHA-1");
		}

		TEST_METHOD(OutputBufferLargerThanTheDigest_ReceivesOnlyTheDigest)
		{
			ByteVector vInput = AsciiBytes("abc");
			ByteVector vOutput(40, 0xCC);
			DWORD dwLength = static_cast<DWORD>(vOutput.size());

			Assert::IsTrue(GetChecksumBuffer(CALG_SHA1, vOutput.data(), dwLength, vInput.data(), static_cast<DWORD>(vInput.size())));

			Assert::AreEqual<DWORD>(SHA1CHECKSUM_LENGTH, dwLength, L"the length is updated to the digest size");
			ByteVector vExpected = FromHex("A9993E364706816ABA3E25717850C26C9CD0D89D");
			vExpected.resize(vOutput.size(), 0xCC);
			AssertBytesEqual(vExpected, vOutput, L"bytes after the digest must be left alone");
		}

		TEST_METHOD(OutputBufferOfExactlyTheDigestSize_Succeeds)
		{
			ByteVector vInput = AsciiBytes("abc");
			ByteVector vOutput(MD5CHECKSUM_LENGTH, 0xCC);
			DWORD dwLength = MD5CHECKSUM_LENGTH;

			Assert::IsTrue(GetChecksumBuffer(CALG_MD5, vOutput.data(), dwLength, vInput.data(), static_cast<DWORD>(vInput.size())));

			Assert::AreEqual<DWORD>(MD5CHECKSUM_LENGTH, dwLength);
			AssertBytesEqual(FromHex("900150983CD24FB0D6963F7D28E17F72"), vOutput);
		}

		TEST_METHOD(OutputBufferTooSmall_ReturnsFalseAndReportsTheRequiredSize)
		{
			ByteVector vInput = AsciiBytes("abc");
			ByteVector vOutput(MD5CHECKSUM_LENGTH, 0xCC);
			DWORD dwLength = 8; // the caller only offers the first 8 bytes of the buffer

			Assert::IsFalse(GetChecksumBuffer(CALG_MD5, vOutput.data(), dwLength, vInput.data(), static_cast<DWORD>(vInput.size())));

			Assert::AreEqual<DWORD>(MD5CHECKSUM_LENGTH, dwLength, L"the required size is reported");
			AssertBytesEqual(Repeat(0xCC, 8), ByteVector(vOutput.begin() + 8, vOutput.end()), L"nothing may be written beyond the offered size");
		}

		// ------------------------------------------------------------------
		// Input handling
		// ------------------------------------------------------------------

		TEST_METHOD(InputBuffer_IsNotModified)
		{
			const ByteVector vOriginal = PseudoRandomBytes(1000, 42);
			ByteVector vInput = vOriginal;
			ByteVector vOutput(SHA1CHECKSUM_LENGTH);
			DWORD dwLength = SHA1CHECKSUM_LENGTH;

			Assert::IsTrue(GetChecksumBuffer(CALG_SHA1, vOutput.data(), dwLength, vInput.data(), static_cast<DWORD>(vInput.size())));

			AssertBytesEqual(vOriginal, vInput);
		}

		TEST_METHOD(InputLength_LimitsTheHashedBytes)
		{
			ByteVector vInput = AsciiBytes("abcdef");
			ByteVector vOutput(MD5CHECKSUM_LENGTH);
			DWORD dwLength = MD5CHECKSUM_LENGTH;

			Assert::IsTrue(GetChecksumBuffer(CALG_MD5, vOutput.data(), dwLength, vInput.data(), 3));

			AssertBytesEqual(FromHex("900150983CD24FB0D6963F7D28E17F72"), vOutput, L"only \"abc\" is hashed");
		}

		TEST_METHOD(InputBufferWithEmbeddedZeroBytes_IsHashedCompletely)
		{
			const ByteVector vInput = FromHex("61 00 62 00 63 00");
			AssertBytesEqual(ReferenceHash(CALG_MD5, vInput), Checksum(CALG_MD5, vInput));
			AssertBytesNotEqual(Checksum(CALG_MD5, AsciiBytes("a")), Checksum(CALG_MD5, vInput), L"the data after a zero byte counts");
		}

		TEST_METHOD(SameInput_GivesTheSameDigestEveryTime)
		{
			const ByteVector vInput = PseudoRandomBytes(777, 7);
			const ByteVector vFirst = Checksum(CALG_SHA1, vInput);
			Assert::IsFalse(vFirst.empty());
			AssertBytesEqual(vFirst, Checksum(CALG_SHA1, vInput));
			AssertBytesEqual(vFirst, Checksum(CALG_SHA1, vInput));
		}

		TEST_METHOD(FlippingASingleBit_ChangesTheDigest)
		{
			const ByteVector vInput = PseudoRandomBytes(300, 11);
			ByteVector vFlipped = vInput;
			vFlipped[150] ^= 0x01;

			AssertBytesNotEqual(Checksum(CALG_MD5, vInput), Checksum(CALG_MD5, vFlipped), L"MD5");
			AssertBytesNotEqual(Checksum(CALG_SHA1, vInput), Checksum(CALG_SHA1, vFlipped), L"SHA-1");
		}

		TEST_METHOD(AppendingAByte_ChangesTheDigest)
		{
			const ByteVector vInput = AsciiBytes("abc");
			ByteVector vLonger = vInput;
			vLonger.push_back(0x00);

			AssertBytesNotEqual(Checksum(CALG_MD5, vInput), Checksum(CALG_MD5, vLonger));
		}

		// ------------------------------------------------------------------
		// Unsupported algorithms
		// ------------------------------------------------------------------

		TEST_METHOD(AlgorithmsThatAreNotHashes_ReturnFalse)
		{
			static const ALG_ID arrAlgorithms[] = { CALG_RC4, CALG_RC2, CALG_DES, CALG_3DES, CALG_RSA_SIGN, 0xFFFFFFFFu };

			for (ALG_ID nAlgorithm : arrAlgorithms)
			{
				CString strMessage;
				strMessage.Format(_T("algorithm 0x%08X"), nAlgorithm);
				Assert::IsTrue(Checksum(nAlgorithm, AsciiBytes("abc")).empty(), strMessage);
			}
		}

		TEST_METHOD(Sha2Hashes_AreNotAvailable_ReturnFalse)
		{
			// Documented limitation (README, "Limitations"): the PROV_RSA_FULL provider has no
			// SHA-2. Update this test together with the library when PROV_RSA_AES is adopted.
			Assert::IsTrue(Checksum(CALG_SHA_256, AsciiBytes("abc")).empty(), L"SHA-256");
			Assert::IsTrue(Checksum(CALG_SHA_384, AsciiBytes("abc")).empty(), L"SHA-384");
			Assert::IsTrue(Checksum(CALG_SHA_512, AsciiBytes("abc")).empty(), L"SHA-512");
		}

		TEST_METHOD(FailureOfAnUnsupportedAlgorithm_ReportsTheFailedStepOnTheDebugOutput)
		{
			if (!DebugOutputCapture::IsSupported())
			{
				Logger::WriteMessage(L"Skipped: a debugger is attached and consumes the debug output.");
				return;
			}

			DebugOutputCapture capture;
			Assert::IsTrue(Checksum(CALG_RC4, AsciiBytes("abc")).empty());

			const CString strOutput = capture.Text();
			Assert::IsTrue(strOutput.Find(_T("[Crypt] CryptCreateHash: ")) >= 0, strOutput);
		}

		TEST_METHOD(SuccessfulCall_WritesNothingToTheDebugOutput)
		{
			if (!DebugOutputCapture::IsSupported())
			{
				Logger::WriteMessage(L"Skipped: a debugger is attached and consumes the debug output.");
				return;
			}

			DebugOutputCapture capture;
			Assert::IsFalse(Checksum(CALG_MD5, AsciiBytes("abc")).empty());

			const CString strOutput = capture.Text();
			Assert::IsTrue(strOutput.Find(_T("[Crypt]")) < 0, strOutput);
		}

		// ------------------------------------------------------------------
		// Thread safety
		// ------------------------------------------------------------------

		TEST_METHOD(ConcurrentCalls_ReturnCorrectDigests)
		{
			// The threads must not assert, so they use TryReferenceHash instead of ReferenceHash.
			RunConcurrently(CONCURRENT_THREADS, [](unsigned int nThread, WorkerFailures& failures)
			{
				for (unsigned int nIteration = 0; nIteration < CONCURRENT_ITERATIONS; nIteration++)
				{
					const ByteVector vInput = PseudoRandomBytes(1 + nIteration * 37, nThread * 1000 + nIteration + 1);
					const bool bMd5 = ((nIteration % 2) == 0);
					const ALG_ID nAlgorithm = bMd5 ? CALG_MD5 : CALG_SHA1;

					ByteVector vExpected;
					CString strProblem;
					if (!TryReferenceHash(nAlgorithm, vInput, vExpected))
						strProblem = _T("the reference hash failed");
					else if (Checksum(nAlgorithm, vInput) != vExpected)
						strProblem = _T("the digest differs from the reference");

					if (!strProblem.IsEmpty())
					{
						CString strMessage;
						strMessage.Format(_T("thread %u, iteration %u, %s: %s"), nThread, nIteration, bMd5 ? _T("MD5") : _T("SHA-1"), (LPCTSTR)strProblem);
						failures.Add(strMessage);
					}
				}
			});
		}
	};
}
