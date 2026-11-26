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

// EncryptionBufferTests.cpp : unit tests for EncryptBuffer and DecryptBuffer.

#include "stdafx.h"
#include "CryptographyExt.h"
#include "TestHelpers.h"
#include "CipherTestData.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;
using namespace TestHelpers;

namespace CryptLibraryDemoTests
{
	namespace
	{
		/** Content of the output bytes the code under test must not touch. */
		const BYTE BYTE_SENTINEL = 0xA5;

		/** Bytes placed behind an output buffer to detect a write past its end. */
		const size_t GUARD_LENGTH = 8;

		const unsigned int CONCURRENT_THREADS = 4;
		const unsigned int CONCURRENT_ITERATIONS = 20;

		/** Plaintext sizes around the block sizes of the ciphers and around MAX_CRYPT_TAIL. */
		const size_t SIZES[] = { 1, 2, 7, 8, 9, 15, 16, 17, 63, 64, 65, 1000, 4095, 4096, 4097 };

		struct CryptResult
		{
			bool bSucceeded = false;
			ByteVector vData;

			/** The first guarantee of the function that was broken, such as modifying an input; empty when it kept them all. */
			CString strViolation;
		};

		CString DescribeCase(ALG_ID nAlgorithm, size_t nSize)
		{
			CString strText;
			strText.Format(_T("%s, %I64u byte(s)"), NameOf(nAlgorithm), static_cast<ULONGLONG>(nSize));
			return strText;
		}

		/** Records a guarantee that the function broke; only the first one is kept. */
		void Violate(CryptResult& result, LPCTSTR lpszMessage)
		{
			if (result.strViolation.IsEmpty())
				result.strViolation = lpszMessage;
		}

		/**
		 * EncryptBuffer over copies of the plaintext and the secret, into an output buffer that
		 * has nRoom bytes more than the plaintext. The default room is the one EncryptFile gives.
		 * It also checks that the function leaves its inputs and the memory behind the ciphertext
		 * alone, and reports what it did wrong in strViolation. It never asserts, so the threads
		 * of RunConcurrently can call it.
		 */
		CryptResult RunEncrypt(ALG_ID nAlgorithm, const ByteVector& vPlain, const ByteVector& vSecret, size_t nRoom = MAX_CRYPT_TAIL)
		{
			ByteVector vInput(vPlain);
			ByteVector vKey(vSecret);
			const size_t nCapacity = vPlain.size() + nRoom;
			ByteVector vOutput(nCapacity + GUARD_LENGTH, BYTE_SENTINEL);
			DWORD dwLength = static_cast<DWORD>(nCapacity);

			CryptResult result;
			result.bSucceeded = EncryptBuffer(nAlgorithm, vOutput.data(), dwLength, vInput.data(), static_cast<DWORD>(vInput.size()),
				vKey.data(), static_cast<DWORD>(vKey.size()));

			if (vInput != vPlain)
				Violate(result, _T("EncryptBuffer modified the plaintext"));
			if (vKey != vSecret)
				Violate(result, _T("EncryptBuffer modified the secret"));

			size_t nUntouched = nCapacity;
			if (result.bSucceeded)
			{
				if (dwLength > nCapacity)
				{
					Violate(result, _T("EncryptBuffer reports more bytes than the buffer holds"));
				}
				else
				{
					result.vData.assign(vOutput.begin(), vOutput.begin() + static_cast<ptrdiff_t>(dwLength));
					nUntouched = dwLength;
				}
			}
			for (size_t nIndex = nUntouched; nIndex < vOutput.size(); nIndex++)
			{
				if (vOutput[nIndex] != BYTE_SENTINEL)
				{
					Violate(result, _T("EncryptBuffer wrote behind the ciphertext"));
					break;
				}
			}
			return result;
		}

		/** RunEncrypt, failing the test when the function broke one of its guarantees. */
		CryptResult TryEncrypt(ALG_ID nAlgorithm, const ByteVector& vPlain, const ByteVector& vSecret, size_t nRoom = MAX_CRYPT_TAIL)
		{
			Assert::IsFalse(vPlain.empty() || vSecret.empty(), L"EncryptBuffer needs data and a secret");

			const CryptResult result = RunEncrypt(nAlgorithm, vPlain, vSecret, nRoom);
			Assert::IsTrue(result.strViolation.IsEmpty(), result.strViolation);
			return result;
		}

		/**
		 * DecryptBuffer over copies of the ciphertext and the secret, into an output buffer that
		 * has the room DecryptFile gives. It also checks that the function leaves its inputs and
		 * the memory behind the ciphertext alone, and reports what it did wrong in strViolation.
		 * It never asserts, so the threads of RunConcurrently can call it.
		 */
		CryptResult RunDecrypt(ALG_ID nAlgorithm, const ByteVector& vCipher, const ByteVector& vSecret)
		{
			ByteVector vInput(vCipher);
			ByteVector vKey(vSecret);
			const size_t nCapacity = vCipher.size() + MAX_CRYPT_TAIL;
			ByteVector vOutput(nCapacity + GUARD_LENGTH, BYTE_SENTINEL);
			DWORD dwLength = static_cast<DWORD>(nCapacity);

			CryptResult result;
			result.bSucceeded = DecryptBuffer(nAlgorithm, vOutput.data(), dwLength, vInput.data(), static_cast<DWORD>(vInput.size()),
				vKey.data(), static_cast<DWORD>(vKey.size()));

			if (vInput != vCipher)
				Violate(result, _T("DecryptBuffer modified the ciphertext"));
			if (vKey != vSecret)
				Violate(result, _T("DecryptBuffer modified the secret"));

			// The ciphertext is copied to the output and decrypted in place.
			for (size_t nIndex = vCipher.size(); nIndex < vOutput.size(); nIndex++)
			{
				if (vOutput[nIndex] != BYTE_SENTINEL)
				{
					Violate(result, _T("DecryptBuffer wrote behind the ciphertext"));
					break;
				}
			}

			if (result.bSucceeded)
			{
				if (dwLength > vCipher.size())
					Violate(result, _T("DecryptBuffer reports more plaintext than ciphertext"));
				else
					result.vData.assign(vOutput.begin(), vOutput.begin() + static_cast<ptrdiff_t>(dwLength));
			}
			return result;
		}

		/** RunDecrypt, failing the test when the function broke one of its guarantees. */
		CryptResult TryDecrypt(ALG_ID nAlgorithm, const ByteVector& vCipher, const ByteVector& vSecret)
		{
			Assert::IsFalse(vCipher.empty() || vSecret.empty(), L"DecryptBuffer needs data and a secret");

			const CryptResult result = RunDecrypt(nAlgorithm, vCipher, vSecret);
			Assert::IsTrue(result.strViolation.IsEmpty(), result.strViolation);
			return result;
		}

		ByteVector Encrypt(ALG_ID nAlgorithm, const ByteVector& vPlain, const ByteVector& vSecret)
		{
			const CryptResult result = TryEncrypt(nAlgorithm, vPlain, vSecret);
			Assert::IsTrue(result.bSucceeded, DescribeCase(nAlgorithm, vPlain.size()) + _T(": EncryptBuffer failed"));
			return result.vData;
		}

		ByteVector Decrypt(ALG_ID nAlgorithm, const ByteVector& vCipher, const ByteVector& vSecret)
		{
			const CryptResult result = TryDecrypt(nAlgorithm, vCipher, vSecret);
			Assert::IsTrue(result.bSucceeded, DescribeCase(nAlgorithm, vCipher.size()) + _T(": DecryptBuffer failed"));
			return result.vData;
		}

		/** True when decrypting did not give the plaintext back, which is what a wrong key or algorithm must cause. */
		bool IsNotRecovered(const CryptResult& result, const ByteVector& vPlain)
		{
			return !result.bSucceeded || result.vData != vPlain;
		}

		/** What is wrong with a call that had to succeed, or an empty string. It never asserts. */
		CString FindProblem(const CryptResult& result, LPCTSTR lpszFunction)
		{
			if (!result.strViolation.IsEmpty())
				return result.strViolation;
			if (!result.bSucceeded)
				return CString(lpszFunction) + _T(" failed");
			return CString();
		}

		void AssertKnownEncryptions(ALG_ID nAlgorithm)
		{
			size_t nChecked = 0;
			for (const KnownAnswer& answer : KNOWN_ANSWERS)
			{
				if (answer.nAlgorithm != nAlgorithm)
					continue;

				const ByteVector vPlain = AsciiBytes(answer.lpszPlaintext);
				AssertBytesEqual(FromHex(answer.lpszCiphertext), Encrypt(nAlgorithm, vPlain, Secret()), DescribeCase(nAlgorithm, vPlain.size()));
				nChecked++;
			}
			Assert::AreEqual(static_cast<size_t>(4), nChecked, L"number of known answers");
		}

		void AssertKnownDecryptions(ALG_ID nAlgorithm)
		{
			size_t nChecked = 0;
			for (const KnownAnswer& answer : KNOWN_ANSWERS)
			{
				if (answer.nAlgorithm != nAlgorithm)
					continue;

				const ByteVector vPlain = AsciiBytes(answer.lpszPlaintext);
				AssertBytesEqual(vPlain, Decrypt(nAlgorithm, FromHex(answer.lpszCiphertext), Secret()), DescribeCase(nAlgorithm, vPlain.size()));
				nChecked++;
			}
			Assert::AreEqual(static_cast<size_t>(4), nChecked, L"number of known answers");
		}
	}

	// ----------------------------------------------------------------------
	// EncryptBuffer
	// ----------------------------------------------------------------------

	TEST_CLASS(EncryptBufferTests)
	{
	public:
		TEST_ASSERTION_GUARD()

		// ------------------------------------------------------------------
		// Known answers from an independent implementation
		// ------------------------------------------------------------------

		TEST_METHOD(Rc4_KnownAnswers)
		{
			AssertKnownEncryptions(CALG_RC4);
		}

		TEST_METHOD(Rc2_KnownAnswers)
		{
			AssertKnownEncryptions(CALG_RC2);
		}

		TEST_METHOD(Des_KnownAnswers)
		{
			AssertKnownEncryptions(CALG_DES);
		}

		TEST_METHOD(TripleDes_KnownAnswers)
		{
			AssertKnownEncryptions(CALG_3DES);
		}

		TEST_METHOD(TripleDes112_KnownAnswers)
		{
			AssertKnownEncryptions(CALG_3DES_112);
		}

		TEST_METHOD(Rc4_PlaintextWithTerminator_KnownAnswer)
		{
			// 17 characters and the terminator, as the dialog encrypts a text.
			const ByteVector vPlain = AsciiBytes("Hello, CryptoAPI!");
			ByteVector vWithTerminator(vPlain);
			vWithTerminator.push_back(0);

			AssertBytesEqual(FromHex("4483C7DBC3B8DD1CE6C6702F7EDACCBCCF91"), Encrypt(CALG_RC4, vWithTerminator, Secret()));
		}

		TEST_METHOD(Rc4_DialogStyleSecret_KnownAnswer)
		{
			// The dialog uses the UTF-16 text of the key, including the terminator, as the secret.
			ByteVector vPlain = AsciiBytes("Hello, CryptoAPI!");
			vPlain.push_back(0);

			AssertBytesEqual(FromHex("877E1527AB7F40B944F01CDD2C374AE0F6B0"), Encrypt(CALG_RC4, vPlain, Utf16Bytes(_T("my secret"))));
		}

		// ------------------------------------------------------------------
		// RC4 against an independent software implementation
		// ------------------------------------------------------------------

		TEST_METHOD(Rc4_MatchesTheReferenceImplementation)
		{
			const ByteVector arrSecrets[] = { AsciiBytes("k"), AsciiBytes("Secret"), Utf16Bytes(_T("my secret")), PseudoRandomBytes(100, 1) };

			for (const ByteVector& vSecret : arrSecrets)
			{
				for (size_t nSize : SIZES)
				{
					const ByteVector vPlain = PseudoRandomBytes(nSize, static_cast<unsigned int>(nSize));

					AssertBytesEqual(ReferenceRc4(vSecret, vPlain), Encrypt(CALG_RC4, vPlain, vSecret), DescribeCase(CALG_RC4, nSize));
				}
			}
		}

		TEST_METHOD(Rc4_EncryptsEveryByteValue)
		{
			const ByteVector vPlain = AllByteValues();

			AssertBytesEqual(ReferenceRc4(Secret(), vPlain), Encrypt(CALG_RC4, vPlain, Secret()));
		}

		// ------------------------------------------------------------------
		// Length of the ciphertext and room in the output buffer
		// ------------------------------------------------------------------

		TEST_METHOD(Ciphertext_HasTheExpectedLength)
		{
			for (const Cipher& cipher : CIPHERS)
			{
				for (size_t nSize : SIZES)
				{
					const ByteVector vPlain = PseudoRandomBytes(nSize, 3);

					Assert::AreEqual(CiphertextLength(cipher, nSize), Encrypt(cipher.nAlgorithm, vPlain, Secret()).size(), DescribeCase(cipher.nAlgorithm, nSize));
				}
			}
		}

		TEST_METHOD(BlockCipher_PlaintextOfWholeBlocks_GetsAFullBlockOfPadding)
		{
			for (size_t nSize : { 8, 16, 24, 4096 })
			{
				const ByteVector vPlain = PseudoRandomBytes(nSize, 4);

				Assert::AreEqual(nSize + 8, Encrypt(CALG_DES, vPlain, Secret()).size(), DescribeCase(CALG_DES, nSize));
			}
		}

		TEST_METHOD(Rc4_NeedsNoRoomBeyondThePlaintext)
		{
			const ByteVector vPlain = PseudoRandomBytes(100, 5);

			const CryptResult result = TryEncrypt(CALG_RC4, vPlain, Secret(), 0);

			Assert::IsTrue(result.bSucceeded);
			AssertBytesEqual(ReferenceRc4(Secret(), vPlain), result.vData);
		}

		TEST_METHOD(BlockCipher_WithJustEnoughRoomForThePadding_Succeeds)
		{
			for (const Cipher& cipher : CIPHERS)
			{
				if (cipher.nBlockSize == 0)
					continue;

				for (size_t nSize : { 1, 7, 8, 9, 16 })
				{
					const ByteVector vPlain = PseudoRandomBytes(nSize, 6);
					const size_t nRoom = CiphertextLength(cipher, nSize) - nSize;

					const CryptResult result = TryEncrypt(cipher.nAlgorithm, vPlain, Secret(), nRoom);

					Assert::IsTrue(result.bSucceeded, DescribeCase(cipher.nAlgorithm, nSize));
					Assert::AreEqual(CiphertextLength(cipher, nSize), result.vData.size(), DescribeCase(cipher.nAlgorithm, nSize));
				}
			}
		}

		TEST_METHOD(BlockCipher_WithoutRoomForThePadding_ReturnsFalse)
		{
			for (const Cipher& cipher : CIPHERS)
			{
				if (cipher.nBlockSize == 0)
					continue;

				for (size_t nSize : { 1, 7, 8, 9, 16 })
				{
					const ByteVector vPlain = PseudoRandomBytes(nSize, 7);
					const size_t nRoom = CiphertextLength(cipher, nSize) - nSize - 1;

					Assert::IsFalse(TryEncrypt(cipher.nAlgorithm, vPlain, Secret(), nRoom).bSucceeded, DescribeCase(cipher.nAlgorithm, nSize));
				}
			}
		}

		TEST_METHOD(OutputLength_ReportsTheCiphertextSizeNotTheCapacity)
		{
			ByteVector vPlain = AsciiBytes("Attack at dawn");
			ByteVector vSecret = Secret();
			ByteVector vOutput(5000, BYTE_SENTINEL);
			DWORD dwLength = static_cast<DWORD>(vOutput.size());

			Assert::IsTrue(EncryptBuffer(CALG_3DES, vOutput.data(), dwLength, vPlain.data(), static_cast<DWORD>(vPlain.size()),
				vSecret.data(), static_cast<DWORD>(vSecret.size())));

			Assert::AreEqual(static_cast<DWORD>(16), dwLength);
		}

		// ------------------------------------------------------------------
		// Properties of the encryption
		// ------------------------------------------------------------------

		TEST_METHOD(Encryption_IsDeterministic)
		{
			const ByteVector vPlain = PseudoRandomBytes(100, 8);

			for (const Cipher& cipher : CIPHERS)
				AssertBytesEqual(Encrypt(cipher.nAlgorithm, vPlain, Secret()), Encrypt(cipher.nAlgorithm, vPlain, Secret()), cipher.lpszName);
		}

		TEST_METHOD(Encryption_ChangesTheData)
		{
			const ByteVector vPlain = Repeat(0x00, 32);

			for (const Cipher& cipher : CIPHERS)
			{
				const ByteVector vCipher = Encrypt(cipher.nAlgorithm, vPlain, Secret());
				AssertBytesNotEqual(vPlain, ByteVector(vCipher.begin(), vCipher.begin() + 32), cipher.lpszName);
			}
		}

		TEST_METHOD(DifferentSecrets_GiveDifferentCiphertexts)
		{
			const ByteVector vPlain = PseudoRandomBytes(40, 9);

			for (const Cipher& cipher : CIPHERS)
				AssertBytesNotEqual(Encrypt(cipher.nAlgorithm, vPlain, AsciiBytes("Secret1")), Encrypt(cipher.nAlgorithm, vPlain, AsciiBytes("Secret2")), cipher.lpszName);
		}

		TEST_METHOD(AnyBitOfTheSecret_ChangesTheCiphertext)
		{
			const ByteVector vPlain = PseudoRandomBytes(40, 10);
			const ByteVector vSecret = AsciiBytes("Secret");

			for (const Cipher& cipher : CIPHERS)
			{
				const ByteVector vReference = Encrypt(cipher.nAlgorithm, vPlain, vSecret);
				for (size_t nByte = 0; nByte < vSecret.size(); nByte++)
				{
					ByteVector vOtherSecret(vSecret);
					vOtherSecret[nByte] ^= 0x01;
					AssertBytesNotEqual(vReference, Encrypt(cipher.nAlgorithm, vPlain, vOtherSecret), cipher.lpszName);
				}
			}
		}

		TEST_METHOD(DifferentCiphers_GiveDifferentCiphertexts)
		{
			const ByteVector vPlain = PseudoRandomBytes(40, 11);

			for (size_t nFirst = 0; nFirst < _countof(CIPHERS); nFirst++)
			{
				for (size_t nSecond = nFirst + 1; nSecond < _countof(CIPHERS); nSecond++)
				{
					CString strMessage;
					strMessage.Format(_T("%s and %s"), CIPHERS[nFirst].lpszName, CIPHERS[nSecond].lpszName);
					AssertBytesNotEqual(Encrypt(CIPHERS[nFirst].nAlgorithm, vPlain, Secret()), Encrypt(CIPHERS[nSecond].nAlgorithm, vPlain, Secret()), strMessage);
				}
			}
		}

		TEST_METHOD(TerminatorOfTheSecret_IsPartOfTheKey)
		{
			// The whole length of the secret is hashed, so "abc" and "abc" plus a NUL are different keys.
			const ByteVector vPlain = PseudoRandomBytes(40, 12);
			ByteVector vWithTerminator = AsciiBytes("abc");
			vWithTerminator.push_back(0);

			for (const Cipher& cipher : CIPHERS)
				AssertBytesNotEqual(Encrypt(cipher.nAlgorithm, vPlain, AsciiBytes("abc")), Encrypt(cipher.nAlgorithm, vPlain, vWithTerminator), cipher.lpszName);
		}

		TEST_METHOD(SecretOfOneByte_IsAccepted)
		{
			const ByteVector vPlain = PseudoRandomBytes(40, 13);

			AssertBytesEqual(ReferenceRc4(Repeat('x', 1), vPlain), Encrypt(CALG_RC4, vPlain, Repeat('x', 1)));
		}

		TEST_METHOD(VeryLongSecret_IsAccepted)
		{
			const ByteVector vPlain = PseudoRandomBytes(40, 14);
			const ByteVector vSecret = PseudoRandomBytes(10000, 15);

			AssertBytesEqual(ReferenceRc4(vSecret, vPlain), Encrypt(CALG_RC4, vPlain, vSecret));
		}

		// ------------------------------------------------------------------
		// Failures
		// ------------------------------------------------------------------

		TEST_METHOD(UnsupportedAlgorithms_ReturnFalse)
		{
			const ByteVector vPlain = AsciiBytes("Attack at dawn");

			for (const UnsupportedAlgorithm& algorithm : UNSUPPORTED_ALGORITHMS)
				Assert::IsFalse(TryEncrypt(algorithm.nAlgorithm, vPlain, Secret()).bSucceeded, algorithm.lpszName);
		}

		TEST_METHOD(UnsupportedAlgorithm_ReportsTheFailedStepOnTheDebugOutput)
		{
			if (!DebugOutputCapture::IsSupported())
			{
				Logger::WriteMessage(L"Skipped: a debugger is attached and consumes the debug output.");
				return;
			}

			DebugOutputCapture capture;
			Assert::IsFalse(TryEncrypt(CALG_AES_128, AsciiBytes("abc"), Secret()).bSucceeded);

			const CString strOutput = capture.Text();
			Assert::IsTrue(strOutput.Find(_T("[Crypt] CryptDeriveKey: ")) >= 0, strOutput);
		}

		TEST_METHOD(MissingRoomForThePadding_ReportsTheFailedStepOnTheDebugOutput)
		{
			if (!DebugOutputCapture::IsSupported())
			{
				Logger::WriteMessage(L"Skipped: a debugger is attached and consumes the debug output.");
				return;
			}

			DebugOutputCapture capture;
			Assert::IsFalse(TryEncrypt(CALG_DES, Repeat('a', 16), Secret(), 0).bSucceeded);

			const CString strOutput = capture.Text();
			Assert::IsTrue(strOutput.Find(_T("[Crypt] CryptEncrypt: ")) >= 0, strOutput);
		}

		TEST_METHOD(SuccessfulCall_WritesNothingToTheDebugOutput)
		{
			if (!DebugOutputCapture::IsSupported())
			{
				Logger::WriteMessage(L"Skipped: a debugger is attached and consumes the debug output.");
				return;
			}

			DebugOutputCapture capture;
			Assert::IsTrue(TryEncrypt(CALG_RC4, AsciiBytes("abc"), Secret()).bSucceeded);

			const CString strOutput = capture.Text();
			Assert::IsTrue(strOutput.Find(_T("[Crypt]")) < 0, strOutput);
		}
	};

	// ----------------------------------------------------------------------
	// DecryptBuffer
	// ----------------------------------------------------------------------

	TEST_CLASS(DecryptBufferTests)
	{
	public:
		TEST_ASSERTION_GUARD()

		TEST_METHOD(Rc4_KnownAnswers)
		{
			AssertKnownDecryptions(CALG_RC4);
		}

		TEST_METHOD(Rc2_KnownAnswers)
		{
			AssertKnownDecryptions(CALG_RC2);
		}

		TEST_METHOD(Des_KnownAnswers)
		{
			AssertKnownDecryptions(CALG_DES);
		}

		TEST_METHOD(TripleDes_KnownAnswers)
		{
			AssertKnownDecryptions(CALG_3DES);
		}

		TEST_METHOD(TripleDes112_KnownAnswers)
		{
			AssertKnownDecryptions(CALG_3DES_112);
		}

		TEST_METHOD(Rc4_DialogStyleSecret_KnownAnswer)
		{
			ByteVector vExpected = AsciiBytes("Hello, CryptoAPI!");
			vExpected.push_back(0);

			AssertBytesEqual(vExpected, Decrypt(CALG_RC4, FromHex("877E1527AB7F40B944F01CDD2C374AE0F6B0"), Utf16Bytes(_T("my secret"))));
		}

		TEST_METHOD(Rc4_DecryptionIsTheSameOperationAsEncryption)
		{
			const ByteVector vData = PseudoRandomBytes(100, 20);

			AssertBytesEqual(Encrypt(CALG_RC4, vData, Secret()), Decrypt(CALG_RC4, vData, Secret()));
		}

		TEST_METHOD(Rc4_DecryptsLikeTheReferenceImplementation)
		{
			for (size_t nSize : SIZES)
			{
				const ByteVector vCipher = PseudoRandomBytes(nSize, 21);

				AssertBytesEqual(ReferenceRc4(Secret(), vCipher), Decrypt(CALG_RC4, vCipher, Secret()), DescribeCase(CALG_RC4, nSize));
			}
		}

		TEST_METHOD(OutputLength_ReportsThePlaintextSizeNotTheCapacity)
		{
			ByteVector vCipher = FromHex("AF563915CC7A3BA8C7347D149934F3DC"); // "Attack at dawn" under 3DES
			ByteVector vSecret = Secret();
			ByteVector vOutput(5000, BYTE_SENTINEL);
			DWORD dwLength = static_cast<DWORD>(vOutput.size());

			Assert::IsTrue(DecryptBuffer(CALG_3DES, vOutput.data(), dwLength, vCipher.data(), static_cast<DWORD>(vCipher.size()),
				vSecret.data(), static_cast<DWORD>(vSecret.size())));

			Assert::AreEqual(static_cast<DWORD>(14), dwLength);
		}

		// ------------------------------------------------------------------
		// Data that cannot be decrypted into the plaintext
		// ------------------------------------------------------------------

		TEST_METHOD(BlockCipher_CiphertextThatIsNoMultipleOfTheBlockSize_ReturnsFalse)
		{
			for (const Cipher& cipher : CIPHERS)
			{
				if (cipher.nBlockSize == 0)
					continue;

				for (size_t nSize : { 1, 5, 7, 9, 13, 15, 17 })
					Assert::IsFalse(TryDecrypt(cipher.nAlgorithm, PseudoRandomBytes(nSize, 22), Secret()).bSucceeded, DescribeCase(cipher.nAlgorithm, nSize));
			}
		}

		TEST_METHOD(WrongSecret_DoesNotRecoverThePlaintext)
		{
			const ByteVector vPlain = AsciiBytes("Attack at dawn, bring the long ladders");

			for (const Cipher& cipher : CIPHERS)
			{
				const ByteVector vCipher = Encrypt(cipher.nAlgorithm, vPlain, Secret());

				Assert::IsTrue(IsNotRecovered(TryDecrypt(cipher.nAlgorithm, vCipher, AsciiBytes("secret")), vPlain), cipher.lpszName);
			}
		}

		TEST_METHOD(WrongAlgorithm_DoesNotRecoverThePlaintext)
		{
			const ByteVector vPlain = AsciiBytes("Attack at dawn, bring the long ladders");

			for (const Cipher& encryption : CIPHERS)
			{
				const ByteVector vCipher = Encrypt(encryption.nAlgorithm, vPlain, Secret());

				for (const Cipher& decryption : CIPHERS)
				{
					if (decryption.nAlgorithm == encryption.nAlgorithm)
						continue;

					CString strMessage;
					strMessage.Format(_T("encrypted with %s, decrypted with %s"), encryption.lpszName, decryption.lpszName);
					Assert::IsTrue(IsNotRecovered(TryDecrypt(decryption.nAlgorithm, vCipher, Secret()), vPlain), strMessage);
				}
			}
		}

		TEST_METHOD(ModifiedCiphertext_DoesNotRecoverThePlaintext)
		{
			const ByteVector vPlain = AsciiBytes("Attack at dawn, bring the long ladders");

			for (const Cipher& cipher : CIPHERS)
			{
				const ByteVector vCipher = Encrypt(cipher.nAlgorithm, vPlain, Secret());

				for (size_t nIndex : { static_cast<size_t>(0), vCipher.size() / 2, vCipher.size() - 1 })
				{
					ByteVector vModified(vCipher);
					vModified[nIndex] ^= 0x01;

					CString strMessage;
					strMessage.Format(_T("%s, byte %I64u modified"), cipher.lpszName, static_cast<ULONGLONG>(nIndex));
					Assert::IsTrue(IsNotRecovered(TryDecrypt(cipher.nAlgorithm, vModified, Secret()), vPlain), strMessage);
				}
			}
		}

		// ------------------------------------------------------------------
		// Failures
		// ------------------------------------------------------------------

		TEST_METHOD(UnsupportedAlgorithms_ReturnFalse)
		{
			const ByteVector vCipher = FromHex("A2339DCA1F111C3DAF846F4B553DC896");

			for (const UnsupportedAlgorithm& algorithm : UNSUPPORTED_ALGORITHMS)
				Assert::IsFalse(TryDecrypt(algorithm.nAlgorithm, vCipher, Secret()).bSucceeded, algorithm.lpszName);
		}

		TEST_METHOD(UnsupportedAlgorithm_ReportsTheFailedStepOnTheDebugOutput)
		{
			if (!DebugOutputCapture::IsSupported())
			{
				Logger::WriteMessage(L"Skipped: a debugger is attached and consumes the debug output.");
				return;
			}

			DebugOutputCapture capture;
			Assert::IsFalse(TryDecrypt(CALG_AES_128, FromHex("A2339DCA1F111C3DAF846F4B553DC896"), Secret()).bSucceeded);

			const CString strOutput = capture.Text();
			Assert::IsTrue(strOutput.Find(_T("[Crypt] CryptDeriveKey: ")) >= 0, strOutput);
		}

		TEST_METHOD(CiphertextOfTheWrongSize_ReportsTheFailedStepOnTheDebugOutput)
		{
			if (!DebugOutputCapture::IsSupported())
			{
				Logger::WriteMessage(L"Skipped: a debugger is attached and consumes the debug output.");
				return;
			}

			DebugOutputCapture capture;
			Assert::IsFalse(TryDecrypt(CALG_DES, PseudoRandomBytes(13, 23), Secret()).bSucceeded);

			const CString strOutput = capture.Text();
			Assert::IsTrue(strOutput.Find(_T("[Crypt] CryptDecrypt: ")) >= 0, strOutput);
		}

		TEST_METHOD(SuccessfulCall_WritesNothingToTheDebugOutput)
		{
			if (!DebugOutputCapture::IsSupported())
			{
				Logger::WriteMessage(L"Skipped: a debugger is attached and consumes the debug output.");
				return;
			}

			DebugOutputCapture capture;
			Assert::IsTrue(TryDecrypt(CALG_RC4, FromHex("4D"), Secret()).bSucceeded);

			const CString strOutput = capture.Text();
			Assert::IsTrue(strOutput.Find(_T("[Crypt]")) < 0, strOutput);
		}
	};

	// ----------------------------------------------------------------------
	// EncryptBuffer followed by DecryptBuffer
	// ----------------------------------------------------------------------

	TEST_CLASS(EncryptionRoundTripTests)
	{
	public:
		TEST_ASSERTION_GUARD()

		TEST_METHOD(EveryCipher_RestoresThePlaintext)
		{
			for (const Cipher& cipher : CIPHERS)
			{
				for (size_t nSize : SIZES)
				{
					const ByteVector vPlain = PseudoRandomBytes(nSize, static_cast<unsigned int>(nSize) + 1000);

					AssertBytesEqual(vPlain, Decrypt(cipher.nAlgorithm, Encrypt(cipher.nAlgorithm, vPlain, Secret()), Secret()), DescribeCase(cipher.nAlgorithm, nSize));
				}
			}
		}

		TEST_METHOD(EveryCipher_RestoresBinaryData)
		{
			const ByteVector arrData[] = { AllByteValues(), Repeat(0x00, 100), Repeat(0xFF, 100) };

			for (const Cipher& cipher : CIPHERS)
			{
				for (const ByteVector& vPlain : arrData)
					AssertBytesEqual(vPlain, Decrypt(cipher.nAlgorithm, Encrypt(cipher.nAlgorithm, vPlain, Secret()), Secret()), DescribeCase(cipher.nAlgorithm, vPlain.size()));
			}
		}

		TEST_METHOD(EveryCipher_RestoresDataWithADialogStyleSecret)
		{
			const ByteVector vSecret = Utf16Bytes(GetComputerID());
			const ByteVector vPlain = PseudoRandomBytes(500, 30);

			for (const Cipher& cipher : CIPHERS)
				AssertBytesEqual(vPlain, Decrypt(cipher.nAlgorithm, Encrypt(cipher.nAlgorithm, vPlain, vSecret), vSecret), cipher.lpszName);
		}

		TEST_METHOD(Rc4_AppliedTwice_RestoresThePlaintext)
		{
			// The dialog calls the same operation to encrypt and to decrypt a file.
			const ByteVector vPlain = PseudoRandomBytes(1234, 31);

			AssertBytesEqual(vPlain, Encrypt(CALG_RC4, Encrypt(CALG_RC4, vPlain, Secret()), Secret()));
		}

		TEST_METHOD(LargeData_IsRestored)
		{
			const ByteVector vPlain = PseudoRandomBytes(1000000, 32);

			for (ALG_ID nAlgorithm : { CALG_RC4, CALG_3DES })
				AssertBytesEqual(vPlain, Decrypt(nAlgorithm, Encrypt(nAlgorithm, vPlain, Secret()), Secret()), NameOf(nAlgorithm));
		}

		TEST_METHOD(ConcurrentCalls_ReturnCorrectResults)
		{
			// The threads must not assert, so they use the Run* helpers and the Try* references.
			RunConcurrently(CONCURRENT_THREADS, [](unsigned int nThread, WorkerFailures& failures)
			{
				for (unsigned int nIteration = 0; nIteration < CONCURRENT_ITERATIONS; nIteration++)
				{
					const Cipher& cipher = CIPHERS[(nThread + nIteration) % _countof(CIPHERS)];
					const ByteVector vPlain = PseudoRandomBytes(1 + nIteration * 41, nThread * 1000 + nIteration + 1);
					const ByteVector vSecret = PseudoRandomBytes(1 + nThread * 7 + nIteration, nIteration + 1);

					const CryptResult encrypted = RunEncrypt(cipher.nAlgorithm, vPlain, vSecret);
					CString strProblem = FindProblem(encrypted, _T("EncryptBuffer"));
					if (strProblem.IsEmpty())
					{
						const CryptResult decrypted = RunDecrypt(cipher.nAlgorithm, encrypted.vData, vSecret);
						strProblem = FindProblem(decrypted, _T("DecryptBuffer"));
						if (strProblem.IsEmpty() && decrypted.vData != vPlain)
							strProblem = _T("the decrypted data differs from the plaintext");
					}
					if (strProblem.IsEmpty() && cipher.nAlgorithm == CALG_RC4)
					{
						ByteVector vReference;
						if (!TryReferenceRc4(vSecret, vPlain, vReference))
							strProblem = _T("the reference RC4 failed");
						else if (vReference != encrypted.vData)
							strProblem = _T("the ciphertext differs from the reference RC4");
					}

					if (!strProblem.IsEmpty())
					{
						CString strMessage;
						strMessage.Format(_T("thread %u, iteration %u, %s: %s"), nThread, nIteration, cipher.lpszName, (LPCTSTR)strProblem);
						failures.Add(strMessage);
					}
				}
			});
		}
	};
}
