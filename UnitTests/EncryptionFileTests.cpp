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

// EncryptionFileTests.cpp : unit tests for EncryptFile and DecryptFile.

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
		const unsigned int CONCURRENT_THREADS = 4;
		const unsigned int CONCURRENT_ITERATIONS = 10;

		/** File sizes around the block sizes of the ciphers and around MAX_CRYPT_TAIL. */
		const size_t SIZES[] = { 1, 7, 8, 9, 100, 4096, 4097, 70000 };

		CString DescribeCase(ALG_ID nAlgorithm, size_t nSize)
		{
			CString strText;
			strText.Format(_T("%s, file length %I64u"), NameOf(nAlgorithm), static_cast<ULONGLONG>(nSize));
			return strText;
		}

		/** A path inside the directory where no file exists, so that a stale file cannot hide a missing output. */
		CString FreshPath(const TempDirectory& dir, LPCTSTR lpszName)
		{
			const CString strPath = dir.Path(lpszName);
			::DeleteFile(strPath);
			return strPath;
		}

		/** The content of a file that must exist. */
		ByteVector ContentOf(const CString& strPath)
		{
			Assert::IsTrue(PathExists(strPath), strPath + _T(" does not exist"));
			return ReadBinaryFile(strPath);
		}

		/** EncryptFile over a copy of the secret, which also verifies that the call leaves the secret alone. */
		bool RunEncryptFile(ALG_ID nAlgorithm, const CString& strOutput, const CString& strInput, const ByteVector& vSecret)
		{
			ByteVector vKey(vSecret);
			const bool bResult = EncryptFile(nAlgorithm, strOutput, strInput, vKey.data(), static_cast<DWORD>(vKey.size()));
			AssertBytesEqual(vSecret, vKey, L"EncryptFile modified the secret");
			return bResult;
		}

		/** DecryptFile over a copy of the secret, which also verifies that the call leaves the secret alone. */
		bool RunDecryptFile(ALG_ID nAlgorithm, const CString& strOutput, const CString& strInput, const ByteVector& vSecret)
		{
			ByteVector vKey(vSecret);
			const bool bResult = DecryptFile(nAlgorithm, strOutput, strInput, vKey.data(), static_cast<DWORD>(vKey.size()));
			AssertBytesEqual(vSecret, vKey, L"DecryptFile modified the secret");
			return bResult;
		}

		/** Writes the plaintext to a file, encrypts that file and returns the content of the output file. */
		ByteVector EncryptedContent(ALG_ID nAlgorithm, const TempDirectory& dir, const ByteVector& vPlain, const ByteVector& vSecret)
		{
			const CString strInput = dir.Path(_T("plain.bin"));
			const CString strOutput = FreshPath(dir, _T("cipher.bin"));
			Assert::IsTrue(WriteBinaryFile(strInput, vPlain), L"the test file cannot be written");

			Assert::IsTrue(RunEncryptFile(nAlgorithm, strOutput, strInput, vSecret), DescribeCase(nAlgorithm, vPlain.size()) + _T(": EncryptFile failed"));
			return ContentOf(strOutput);
		}

		/** Writes the ciphertext to a file, decrypts that file and returns the content of the output file. */
		ByteVector DecryptedContent(ALG_ID nAlgorithm, const TempDirectory& dir, const ByteVector& vCipher, const ByteVector& vSecret)
		{
			const CString strInput = dir.Path(_T("cipher.bin"));
			const CString strOutput = FreshPath(dir, _T("plain.bin"));
			Assert::IsTrue(WriteBinaryFile(strInput, vCipher), L"the test file cannot be written");

			Assert::IsTrue(RunDecryptFile(nAlgorithm, strOutput, strInput, vSecret), DescribeCase(nAlgorithm, vCipher.size()) + _T(": DecryptFile failed"));
			return ContentOf(strOutput);
		}

		/** The ciphertext EncryptBuffer gives, to compare with what EncryptFile writes. */
		ByteVector BufferCiphertext(ALG_ID nAlgorithm, const ByteVector& vPlain, const ByteVector& vSecret)
		{
			ByteVector vInput(vPlain);
			ByteVector vKey(vSecret);
			ByteVector vOutput(vPlain.size() + MAX_CRYPT_TAIL);
			DWORD dwLength = static_cast<DWORD>(vOutput.size());

			Assert::IsTrue(EncryptBuffer(nAlgorithm, vOutput.data(), dwLength, vInput.data(), static_cast<DWORD>(vInput.size()),
				vKey.data(), static_cast<DWORD>(vKey.size())), DescribeCase(nAlgorithm, vPlain.size()) + _T(": EncryptBuffer failed"));
			vOutput.resize(dwLength);
			return vOutput;
		}

		/** Writes the data to a file, encrypts it and decrypts the result with the same cipher and secret. */
		ByteVector RoundTrip(ALG_ID nAlgorithm, const TempDirectory& dir, const ByteVector& vPlain, const ByteVector& vSecret)
		{
			const CString strPlain = dir.Path(_T("plain.bin"));
			const CString strCipher = FreshPath(dir, _T("cipher.bin"));
			const CString strRestored = FreshPath(dir, _T("restored.bin"));
			Assert::IsTrue(WriteBinaryFile(strPlain, vPlain), L"the test file cannot be written");

			Assert::IsTrue(RunEncryptFile(nAlgorithm, strCipher, strPlain, vSecret), DescribeCase(nAlgorithm, vPlain.size()) + _T(": EncryptFile failed"));
			Assert::IsTrue(RunDecryptFile(nAlgorithm, strRestored, strCipher, vSecret), DescribeCase(nAlgorithm, vPlain.size()) + _T(": DecryptFile failed"));
			return ContentOf(strRestored);
		}
	}

	// ----------------------------------------------------------------------
	// EncryptFile
	// ----------------------------------------------------------------------

	TEST_CLASS(EncryptFileTests)
	{
	public:
		TEST_ASSERTION_GUARD()

		// ------------------------------------------------------------------
		// Content of the output file
		// ------------------------------------------------------------------

		TEST_METHOD(EveryCipher_WritesTheKnownCiphertexts)
		{
			TempDirectory dir;

			size_t nChecked = 0;
			for (const KnownAnswer& answer : KNOWN_ANSWERS)
			{
				const ByteVector vPlain = AsciiBytes(answer.lpszPlaintext);
				AssertBytesEqual(FromHex(answer.lpszCiphertext), EncryptedContent(answer.nAlgorithm, dir, vPlain, Secret()), DescribeCase(answer.nAlgorithm, vPlain.size()));
				nChecked++;
			}
			Assert::AreEqual(_countof(KNOWN_ANSWERS), nChecked, L"number of known answers");
		}

		TEST_METHOD(Rc4_WritesTheReferenceCiphertext)
		{
			TempDirectory dir;

			for (size_t nSize : SIZES)
			{
				const ByteVector vPlain = PseudoRandomBytes(nSize, static_cast<unsigned int>(nSize) + 2000);

				AssertBytesEqual(ReferenceRc4(Secret(), vPlain), EncryptedContent(CALG_RC4, dir, vPlain, Secret()), DescribeCase(CALG_RC4, nSize));
			}
		}

		TEST_METHOD(Rc4_WithADialogStyleSecret_WritesTheReferenceCiphertext)
		{
			TempDirectory dir;
			const ByteVector vSecret = Utf16Bytes(GetComputerID());
			const ByteVector vPlain = PseudoRandomBytes(5000, 2001);

			AssertBytesEqual(ReferenceRc4(vSecret, vPlain), EncryptedContent(CALG_RC4, dir, vPlain, vSecret));
		}

		TEST_METHOD(EveryCipher_WritesTheCiphertextOfEncryptBuffer)
		{
			TempDirectory dir;

			for (const Cipher& cipher : CIPHERS)
			{
				for (size_t nSize : SIZES)
				{
					const ByteVector vPlain = PseudoRandomBytes(nSize, static_cast<unsigned int>(nSize) + 2100);
					const ByteVector vCipher = EncryptedContent(cipher.nAlgorithm, dir, vPlain, Secret());

					AssertBytesEqual(BufferCiphertext(cipher.nAlgorithm, vPlain, Secret()), vCipher, DescribeCase(cipher.nAlgorithm, nSize));
					Assert::AreEqual(CiphertextLength(cipher, nSize), vCipher.size(), DescribeCase(cipher.nAlgorithm, nSize));
				}
			}
		}

		TEST_METHOD(BinaryContent_IsEncryptedByteForByte)
		{
			TempDirectory dir;
			const ByteVector arrData[] = { AllByteValues(), Repeat(0x00, 300), Repeat(0xFF, 300) };

			for (const ByteVector& vPlain : arrData)
				AssertBytesEqual(ReferenceRc4(Secret(), vPlain), EncryptedContent(CALG_RC4, dir, vPlain, Secret()), DescribeCase(CALG_RC4, vPlain.size()));
		}

		TEST_METHOD(LargeFile_IsEncrypted)
		{
			TempDirectory dir;
			const ByteVector vPlain = PseudoRandomBytes(3000000, 2200);

			AssertBytesEqual(ReferenceRc4(Secret(), vPlain), EncryptedContent(CALG_RC4, dir, vPlain, Secret()), L"RC4");

			const ByteVector vCipher = EncryptedContent(CALG_3DES, dir, vPlain, Secret());
			Assert::AreEqual(static_cast<size_t>(3000008), vCipher.size(), L"3DES length");
			AssertBytesEqual(BufferCiphertext(CALG_3DES, vPlain, Secret()), vCipher, L"3DES");
		}

		// ------------------------------------------------------------------
		// Files and paths
		// ------------------------------------------------------------------

		TEST_METHOD(AfterASuccessfulCall_TheInputIsUnchangedAndBothFilesAreClosed)
		{
			TempDirectory dir;
			const CString strInput = dir.Path(_T("plain.bin"));
			const CString strOutput = FreshPath(dir, _T("cipher.bin"));
			const ByteVector vPlain = PseudoRandomBytes(3000, 2300);
			Assert::IsTrue(WriteBinaryFile(strInput, vPlain));

			Assert::IsTrue(RunEncryptFile(CALG_RC4, strOutput, strInput, Secret()));

			AssertBytesEqual(vPlain, ReadBinaryFile(strInput), L"the input must not change");
			Assert::IsTrue(::DeleteFile(strOutput) != FALSE, L"a handle to the output file was left open");
			Assert::IsTrue(::DeleteFile(strInput) != FALSE, L"a handle to the input file was left open");
		}

		TEST_METHOD(ExistingOutputFile_IsReplacedCompletely)
		{
			TempDirectory dir;
			const CString strInput = dir.Path(_T("plain.bin"));
			const CString strOutput = dir.Path(_T("cipher.bin"));
			const ByteVector vPlain = AsciiBytes("Attack at dawn");
			Assert::IsTrue(WriteBinaryFile(strInput, vPlain));
			Assert::IsTrue(WriteBinaryFile(strOutput, Repeat(0xEE, 10000)), L"the old output cannot be written");

			Assert::IsTrue(RunEncryptFile(CALG_RC4, strOutput, strInput, Secret()));

			AssertBytesEqual(ReferenceRc4(Secret(), vPlain), ReadBinaryFile(strOutput), L"nothing of the old output may remain");
		}

		TEST_METHOD(PathsWithSpacesAndUnicodeCharacters_AreSupported)
		{
			TempDirectory dir;
			const CString strFolder = dir.CreateSubfolder(_T("sub folder \u00e9"));
			const CString strInput = strFolder + _T("\\my plain \u4e2d\u6587.txt");
			const CString strOutput = strFolder + _T("\\my cipher \u00fc\u00df.enc");
			const ByteVector vPlain = AsciiBytes("Attack at dawn");
			Assert::IsTrue(WriteBinaryFile(strInput, vPlain));

			Assert::IsTrue(RunEncryptFile(CALG_RC4, strOutput, strInput, Secret()));

			AssertBytesEqual(ReferenceRc4(Secret(), vPlain), ContentOf(strOutput));
		}

		// ------------------------------------------------------------------
		// Failures
		// ------------------------------------------------------------------

		TEST_METHOD(EmptyInputFile_ReturnsFalseAndCreatesNoOutput)
		{
			TempDirectory dir;
			const CString strInput = dir.Path(_T("empty.bin"));
			const CString strOutput = dir.Path(_T("cipher.bin"));
			Assert::IsTrue(WriteBinaryFile(strInput, ByteVector()));
			Assert::AreEqual<ULONGLONG>(0, GetFileLength(strInput), L"the test file must be empty");

			Assert::IsFalse(RunEncryptFile(CALG_RC4, strOutput, strInput, Secret()));
			Assert::IsFalse(PathExists(strOutput), L"an output file was created");
		}

		TEST_METHOD(MissingInputFile_ReturnsFalseAndCreatesNoOutput)
		{
			TempDirectory dir;
			const CString strOutput = dir.Path(_T("cipher.bin"));

			Assert::IsFalse(RunEncryptFile(CALG_RC4, strOutput, dir.Path(_T("missing.bin")), Secret()));
			Assert::IsFalse(PathExists(strOutput), L"an output file was created");
		}

		TEST_METHOD(InputThatIsADirectory_ReturnsFalseAndCreatesNoOutput)
		{
			TempDirectory dir;
			const CString strOutput = dir.Path(_T("cipher.bin"));

			Assert::IsFalse(RunEncryptFile(CALG_RC4, strOutput, dir.CreateSubfolder(_T("folder")), Secret()));
			Assert::IsFalse(PathExists(strOutput), L"an output file was created");
		}

		TEST_METHOD(EmptyInputPath_ReturnsFalseAndCreatesNoOutput)
		{
			TempDirectory dir;
			const CString strOutput = dir.Path(_T("cipher.bin"));

			Assert::IsFalse(RunEncryptFile(CALG_RC4, strOutput, CString(), Secret()));
			Assert::IsFalse(PathExists(strOutput), L"an output file was created");
		}

		TEST_METHOD(MissingOutputFolder_ReturnsFalseAndLeavesTheInputAlone)
		{
			TempDirectory dir;
			const CString strInput = dir.Path(_T("plain.bin"));
			const ByteVector vPlain = AsciiBytes("Attack at dawn");
			Assert::IsTrue(WriteBinaryFile(strInput, vPlain));

			Assert::IsFalse(RunEncryptFile(CALG_RC4, dir.Path(_T("no such folder\\cipher.bin")), strInput, Secret()));

			AssertBytesEqual(vPlain, ReadBinaryFile(strInput), L"the input must not change and must be closed");
		}

		TEST_METHOD(OutputThatIsADirectory_ReturnsFalseAndLeavesTheInputAlone)
		{
			TempDirectory dir;
			const CString strInput = dir.Path(_T("plain.bin"));
			const ByteVector vPlain = AsciiBytes("Attack at dawn");
			Assert::IsTrue(WriteBinaryFile(strInput, vPlain));

			Assert::IsFalse(RunEncryptFile(CALG_RC4, dir.CreateSubfolder(_T("folder")), strInput, Secret()));

			AssertBytesEqual(vPlain, ReadBinaryFile(strInput), L"the input must not change and must be closed");
		}

		TEST_METHOD(UnsupportedAlgorithms_ReturnFalseAndCreateNoOutput)
		{
			TempDirectory dir;
			const CString strInput = dir.Path(_T("plain.bin"));
			const CString strOutput = dir.Path(_T("cipher.bin"));
			Assert::IsTrue(WriteBinaryFile(strInput, AsciiBytes("Attack at dawn")));

			for (const UnsupportedAlgorithm& algorithm : UNSUPPORTED_ALGORITHMS)
			{
				Assert::IsFalse(RunEncryptFile(algorithm.nAlgorithm, strOutput, strInput, Secret()), algorithm.lpszName);
				Assert::IsFalse(PathExists(strOutput), algorithm.lpszName);
			}
		}

		TEST_METHOD(UnsupportedAlgorithm_KeepsAnExistingOutputFile)
		{
			TempDirectory dir;
			const CString strInput = dir.Path(_T("plain.bin"));
			const CString strOutput = dir.Path(_T("cipher.bin"));
			const ByteVector vOld = AsciiBytes("existing content");
			Assert::IsTrue(WriteBinaryFile(strInput, AsciiBytes("Attack at dawn")));
			Assert::IsTrue(WriteBinaryFile(strOutput, vOld));

			Assert::IsFalse(RunEncryptFile(CALG_AES_128, strOutput, strInput, Secret()));

			AssertBytesEqual(vOld, ReadBinaryFile(strOutput), L"a failed call must not touch the output");
		}

		TEST_METHOD(InputOpenElsewhere_ReturnsFalseUntilItIsReleased)
		{
			TempDirectory dir;
			const CString strInput = dir.Path(_T("plain.bin"));
			const CString strOutput = dir.Path(_T("cipher.bin"));
			const ByteVector vPlain = AsciiBytes("Attack at dawn");
			Assert::IsTrue(WriteBinaryFile(strInput, vPlain));

			{
				// The file is opened with MFC's default sharing mode, which does not tolerate another open handle.
				OpenFileHandle handle(strInput);
				Assert::IsTrue(handle.IsOpen(), L"the test cannot open the file");

				Assert::IsFalse(RunEncryptFile(CALG_RC4, strOutput, strInput, Secret()));
				Assert::IsFalse(PathExists(strOutput), L"an output file was created");
			}

			Assert::IsTrue(RunEncryptFile(CALG_RC4, strOutput, strInput, Secret()));
			AssertBytesEqual(ReferenceRc4(Secret(), vPlain), ReadBinaryFile(strOutput));
		}

		TEST_METHOD(OutputOpenElsewhere_ReturnsFalseAndKeepsItsContentUntilItIsReleased)
		{
			TempDirectory dir;
			const CString strInput = dir.Path(_T("plain.bin"));
			const CString strOutput = dir.Path(_T("cipher.bin"));
			const ByteVector vPlain = AsciiBytes("Attack at dawn");
			const ByteVector vOld = AsciiBytes("existing content");
			Assert::IsTrue(WriteBinaryFile(strInput, vPlain));
			Assert::IsTrue(WriteBinaryFile(strOutput, vOld));

			{
				OpenFileHandle handle(strOutput);
				Assert::IsTrue(handle.IsOpen(), L"the test cannot open the file");

				Assert::IsFalse(RunEncryptFile(CALG_RC4, strOutput, strInput, Secret()));
			}

			AssertBytesEqual(vOld, ReadBinaryFile(strOutput), L"a failed call must not touch the output");
			Assert::IsTrue(RunEncryptFile(CALG_RC4, strOutput, strInput, Secret()));
			AssertBytesEqual(ReferenceRc4(Secret(), vPlain), ReadBinaryFile(strOutput));
		}

		TEST_METHOD(OutputSameAsInput_ReturnsFalseAndKeepsTheContent)
		{
			TempDirectory dir;
			const CString strPath = dir.Path(_T("data.bin"));
			const ByteVector vPlain = PseudoRandomBytes(1000, 2400);
			Assert::IsTrue(WriteBinaryFile(strPath, vPlain));

			// The input is still open, with exclusive access, when the output is created.
			Assert::IsFalse(RunEncryptFile(CALG_RC4, strPath, strPath, Secret()));

			AssertBytesEqual(vPlain, ReadBinaryFile(strPath), L"the file must not change");
		}

		TEST_METHOD(AfterAFailedCall_TheInputIsClosed)
		{
			TempDirectory dir;
			const CString strInput = dir.Path(_T("plain.bin"));
			Assert::IsTrue(WriteBinaryFile(strInput, AsciiBytes("Attack at dawn")));

			Assert::IsFalse(RunEncryptFile(CALG_AES_128, dir.Path(_T("cipher.bin")), strInput, Secret()));

			Assert::IsTrue(::DeleteFile(strInput) != FALSE, L"a handle to the input file was left open");
		}

		// ------------------------------------------------------------------
		// Diagnostics
		// ------------------------------------------------------------------

		TEST_METHOD(MissingInputFile_WritesTheFileErrorToTheDebugOutput)
		{
			if (!DebugOutputCapture::IsSupported())
			{
				Logger::WriteMessage(L"Skipped: a debugger is attached and consumes the debug output.");
				return;
			}

			TempDirectory dir;
			const CString strInput = dir.Path(_T("missing.bin"));

			DebugOutputCapture capture;
			Assert::IsFalse(RunEncryptFile(CALG_RC4, dir.Path(_T("cipher.bin")), strInput, Secret()));

			const CString strOutput = capture.Text();
			Assert::IsTrue(strOutput.Find(strInput) >= 0, strOutput);
		}

		TEST_METHOD(UnsupportedAlgorithm_ReportsTheFailedStepOnTheDebugOutput)
		{
			if (!DebugOutputCapture::IsSupported())
			{
				Logger::WriteMessage(L"Skipped: a debugger is attached and consumes the debug output.");
				return;
			}

			TempDirectory dir;
			const CString strInput = dir.Path(_T("plain.bin"));
			Assert::IsTrue(WriteBinaryFile(strInput, AsciiBytes("Attack at dawn")));

			DebugOutputCapture capture;
			Assert::IsFalse(RunEncryptFile(CALG_AES_128, dir.Path(_T("cipher.bin")), strInput, Secret()));

			const CString strOutput = capture.Text();
			Assert::IsTrue(strOutput.Find(_T("[Crypt] CryptDeriveKey: ")) >= 0, strOutput);
		}

		TEST_METHOD(SuccessfulCall_WritesNothingToTheDebugOutput)
		{
			if (!DebugOutputCapture::IsSupported())
			{
				Logger::WriteMessage(L"Skipped: a debugger is attached and consumes the debug output.");
				return;
			}

			TempDirectory dir;
			const CString strInput = dir.Path(_T("plain.bin"));
			Assert::IsTrue(WriteBinaryFile(strInput, AsciiBytes("Attack at dawn")));

			DebugOutputCapture capture;
			Assert::IsTrue(RunEncryptFile(CALG_RC4, dir.Path(_T("cipher.bin")), strInput, Secret()));

			const CString strOutput = capture.Text();
			Assert::IsTrue(strOutput.Find(_T("[Crypt]")) < 0 && strOutput.Find(strInput) < 0, strOutput);
		}
	};

	// ----------------------------------------------------------------------
	// DecryptFile
	// ----------------------------------------------------------------------

	TEST_CLASS(DecryptFileTests)
	{
	public:
		TEST_ASSERTION_GUARD()

		// ------------------------------------------------------------------
		// Content of the output file
		// ------------------------------------------------------------------

		TEST_METHOD(EveryCipher_WritesTheKnownPlaintexts)
		{
			TempDirectory dir;

			size_t nChecked = 0;
			for (const KnownAnswer& answer : KNOWN_ANSWERS)
			{
				const ByteVector vCipher = FromHex(answer.lpszCiphertext);
				AssertBytesEqual(AsciiBytes(answer.lpszPlaintext), DecryptedContent(answer.nAlgorithm, dir, vCipher, Secret()), DescribeCase(answer.nAlgorithm, vCipher.size()));
				nChecked++;
			}
			Assert::AreEqual(_countof(KNOWN_ANSWERS), nChecked, L"number of known answers");
		}

		TEST_METHOD(Rc4_WritesTheReferencePlaintext)
		{
			TempDirectory dir;

			for (size_t nSize : SIZES)
			{
				const ByteVector vCipher = PseudoRandomBytes(nSize, static_cast<unsigned int>(nSize) + 3000);

				AssertBytesEqual(ReferenceRc4(Secret(), vCipher), DecryptedContent(CALG_RC4, dir, vCipher, Secret()), DescribeCase(CALG_RC4, nSize));
			}
		}

		TEST_METHOD(Rc4_WithADialogStyleSecret_WritesTheReferencePlaintext)
		{
			TempDirectory dir;
			const ByteVector vSecret = Utf16Bytes(GetComputerID());
			const ByteVector vCipher = PseudoRandomBytes(5000, 3001);

			AssertBytesEqual(ReferenceRc4(vSecret, vCipher), DecryptedContent(CALG_RC4, dir, vCipher, vSecret));
		}

		TEST_METHOD(EveryCipher_RestoresThePlaintextOfEncryptBuffer)
		{
			TempDirectory dir;

			for (const Cipher& cipher : CIPHERS)
			{
				for (size_t nSize : SIZES)
				{
					const ByteVector vPlain = PseudoRandomBytes(nSize, static_cast<unsigned int>(nSize) + 3100);

					AssertBytesEqual(vPlain, DecryptedContent(cipher.nAlgorithm, dir, BufferCiphertext(cipher.nAlgorithm, vPlain, Secret()), Secret()), DescribeCase(cipher.nAlgorithm, nSize));
				}
			}
		}

		TEST_METHOD(LargeFile_IsDecrypted)
		{
			TempDirectory dir;
			const ByteVector vPlain = PseudoRandomBytes(3000000, 3200);

			AssertBytesEqual(vPlain, DecryptedContent(CALG_3DES, dir, BufferCiphertext(CALG_3DES, vPlain, Secret()), Secret()));
		}

		// ------------------------------------------------------------------
		// Files and paths
		// ------------------------------------------------------------------

		TEST_METHOD(AfterASuccessfulCall_TheInputIsUnchangedAndBothFilesAreClosed)
		{
			TempDirectory dir;
			const CString strInput = dir.Path(_T("cipher.bin"));
			const CString strOutput = FreshPath(dir, _T("plain.bin"));
			const ByteVector vCipher = BufferCiphertext(CALG_3DES, PseudoRandomBytes(3000, 3300), Secret());
			Assert::IsTrue(WriteBinaryFile(strInput, vCipher));

			Assert::IsTrue(RunDecryptFile(CALG_3DES, strOutput, strInput, Secret()));

			AssertBytesEqual(vCipher, ReadBinaryFile(strInput), L"the input must not change");
			Assert::IsTrue(::DeleteFile(strOutput) != FALSE, L"a handle to the output file was left open");
			Assert::IsTrue(::DeleteFile(strInput) != FALSE, L"a handle to the input file was left open");
		}

		TEST_METHOD(ExistingOutputFile_IsReplacedCompletely)
		{
			TempDirectory dir;
			const CString strInput = dir.Path(_T("cipher.bin"));
			const CString strOutput = dir.Path(_T("plain.bin"));
			const ByteVector vPlain = AsciiBytes("Attack at dawn");
			Assert::IsTrue(WriteBinaryFile(strInput, BufferCiphertext(CALG_RC4, vPlain, Secret())));
			Assert::IsTrue(WriteBinaryFile(strOutput, Repeat(0xEE, 10000)), L"the old output cannot be written");

			Assert::IsTrue(RunDecryptFile(CALG_RC4, strOutput, strInput, Secret()));

			AssertBytesEqual(vPlain, ReadBinaryFile(strOutput), L"nothing of the old output may remain");
		}

		TEST_METHOD(PathsWithSpacesAndUnicodeCharacters_AreSupported)
		{
			TempDirectory dir;
			const CString strFolder = dir.CreateSubfolder(_T("sub folder \u00e9"));
			const CString strInput = strFolder + _T("\\my cipher \u4e2d\u6587.enc");
			const CString strOutput = strFolder + _T("\\my plain \u00fc\u00df.txt");
			const ByteVector vPlain = AsciiBytes("Attack at dawn");
			Assert::IsTrue(WriteBinaryFile(strInput, BufferCiphertext(CALG_3DES, vPlain, Secret())));

			Assert::IsTrue(RunDecryptFile(CALG_3DES, strOutput, strInput, Secret()));

			AssertBytesEqual(vPlain, ContentOf(strOutput));
		}

		// ------------------------------------------------------------------
		// Failures
		// ------------------------------------------------------------------

		TEST_METHOD(EmptyInputFile_ReturnsFalseAndCreatesNoOutput)
		{
			TempDirectory dir;
			const CString strInput = dir.Path(_T("empty.bin"));
			const CString strOutput = dir.Path(_T("plain.bin"));
			Assert::IsTrue(WriteBinaryFile(strInput, ByteVector()));
			Assert::AreEqual<ULONGLONG>(0, GetFileLength(strInput), L"the test file must be empty");

			Assert::IsFalse(RunDecryptFile(CALG_RC4, strOutput, strInput, Secret()));
			Assert::IsFalse(PathExists(strOutput), L"an output file was created");
		}

		TEST_METHOD(MissingInputFile_ReturnsFalseAndCreatesNoOutput)
		{
			TempDirectory dir;
			const CString strOutput = dir.Path(_T("plain.bin"));

			Assert::IsFalse(RunDecryptFile(CALG_RC4, strOutput, dir.Path(_T("missing.bin")), Secret()));
			Assert::IsFalse(PathExists(strOutput), L"an output file was created");
		}

		TEST_METHOD(InputThatIsADirectory_ReturnsFalseAndCreatesNoOutput)
		{
			TempDirectory dir;
			const CString strOutput = dir.Path(_T("plain.bin"));

			Assert::IsFalse(RunDecryptFile(CALG_RC4, strOutput, dir.CreateSubfolder(_T("folder")), Secret()));
			Assert::IsFalse(PathExists(strOutput), L"an output file was created");
		}

		TEST_METHOD(EmptyInputPath_ReturnsFalseAndCreatesNoOutput)
		{
			TempDirectory dir;
			const CString strOutput = dir.Path(_T("plain.bin"));

			Assert::IsFalse(RunDecryptFile(CALG_RC4, strOutput, CString(), Secret()));
			Assert::IsFalse(PathExists(strOutput), L"an output file was created");
		}

		TEST_METHOD(MissingOutputFolder_ReturnsFalseAndLeavesTheInputAlone)
		{
			TempDirectory dir;
			const CString strInput = dir.Path(_T("cipher.bin"));
			const ByteVector vCipher = BufferCiphertext(CALG_RC4, AsciiBytes("Attack at dawn"), Secret());
			Assert::IsTrue(WriteBinaryFile(strInput, vCipher));

			Assert::IsFalse(RunDecryptFile(CALG_RC4, dir.Path(_T("no such folder\\plain.bin")), strInput, Secret()));

			AssertBytesEqual(vCipher, ReadBinaryFile(strInput), L"the input must not change and must be closed");
		}

		TEST_METHOD(OutputThatIsADirectory_ReturnsFalseAndLeavesTheInputAlone)
		{
			TempDirectory dir;
			const CString strInput = dir.Path(_T("cipher.bin"));
			const ByteVector vCipher = BufferCiphertext(CALG_RC4, AsciiBytes("Attack at dawn"), Secret());
			Assert::IsTrue(WriteBinaryFile(strInput, vCipher));

			Assert::IsFalse(RunDecryptFile(CALG_RC4, dir.CreateSubfolder(_T("folder")), strInput, Secret()));

			AssertBytesEqual(vCipher, ReadBinaryFile(strInput), L"the input must not change and must be closed");
		}

		TEST_METHOD(CiphertextThatIsNotAMultipleOfTheBlockSize_ReturnsFalseAndCreatesNoOutput)
		{
			TempDirectory dir;
			const CString strInput = dir.Path(_T("cipher.bin"));
			const CString strOutput = dir.Path(_T("plain.bin"));
			Assert::IsTrue(WriteBinaryFile(strInput, PseudoRandomBytes(13, 3400)));

			for (const Cipher& cipher : CIPHERS)
			{
				if (cipher.nBlockSize == 0)
					continue;

				Assert::IsFalse(RunDecryptFile(cipher.nAlgorithm, strOutput, strInput, Secret()), cipher.lpszName);
				Assert::IsFalse(PathExists(strOutput), cipher.lpszName);
			}
		}

		TEST_METHOD(WrongSecret_DoesNotRestoreThePlaintext)
		{
			TempDirectory dir;
			const ByteVector vPlain = PseudoRandomBytes(500, 3500);

			for (const Cipher& cipher : CIPHERS)
			{
				const CString strInput = dir.Path(_T("cipher.bin"));
				const CString strOutput = FreshPath(dir, _T("plain.bin"));
				Assert::IsTrue(WriteBinaryFile(strInput, BufferCiphertext(cipher.nAlgorithm, vPlain, Secret())));

				// A wrong key either fails the padding check or produces other bytes.
				if (RunDecryptFile(cipher.nAlgorithm, strOutput, strInput, AsciiBytes("Another secret")))
					AssertBytesNotEqual(vPlain, ReadBinaryFile(strOutput), cipher.lpszName);
				else
					Assert::IsFalse(PathExists(strOutput), cipher.lpszName);
			}
		}

		TEST_METHOD(WrongAlgorithm_DoesNotRestoreThePlaintext)
		{
			TempDirectory dir;
			const ByteVector vPlain = PseudoRandomBytes(500, 3600);
			const CString strInput = dir.Path(_T("cipher.bin"));
			Assert::IsTrue(WriteBinaryFile(strInput, BufferCiphertext(CALG_3DES, vPlain, Secret())));

			for (const Cipher& cipher : CIPHERS)
			{
				if (cipher.nAlgorithm == CALG_3DES)
					continue;

				const CString strOutput = FreshPath(dir, _T("plain.bin"));
				if (RunDecryptFile(cipher.nAlgorithm, strOutput, strInput, Secret()))
					AssertBytesNotEqual(vPlain, ReadBinaryFile(strOutput), cipher.lpszName);
				else
					Assert::IsFalse(PathExists(strOutput), cipher.lpszName);
			}
		}

		TEST_METHOD(UnsupportedAlgorithms_ReturnFalseAndCreateNoOutput)
		{
			TempDirectory dir;
			const CString strInput = dir.Path(_T("cipher.bin"));
			const CString strOutput = dir.Path(_T("plain.bin"));
			Assert::IsTrue(WriteBinaryFile(strInput, FromHex("A2339DCA1F111C3DAF846F4B553DC896")));

			for (const UnsupportedAlgorithm& algorithm : UNSUPPORTED_ALGORITHMS)
			{
				Assert::IsFalse(RunDecryptFile(algorithm.nAlgorithm, strOutput, strInput, Secret()), algorithm.lpszName);
				Assert::IsFalse(PathExists(strOutput), algorithm.lpszName);
			}
		}

		TEST_METHOD(UnsupportedAlgorithm_KeepsAnExistingOutputFile)
		{
			TempDirectory dir;
			const CString strInput = dir.Path(_T("cipher.bin"));
			const CString strOutput = dir.Path(_T("plain.bin"));
			const ByteVector vOld = AsciiBytes("existing content");
			Assert::IsTrue(WriteBinaryFile(strInput, FromHex("A2339DCA1F111C3DAF846F4B553DC896")));
			Assert::IsTrue(WriteBinaryFile(strOutput, vOld));

			Assert::IsFalse(RunDecryptFile(CALG_AES_128, strOutput, strInput, Secret()));

			AssertBytesEqual(vOld, ReadBinaryFile(strOutput), L"a failed call must not touch the output");
		}

		TEST_METHOD(InputOpenElsewhere_ReturnsFalseUntilItIsReleased)
		{
			TempDirectory dir;
			const CString strInput = dir.Path(_T("cipher.bin"));
			const CString strOutput = dir.Path(_T("plain.bin"));
			const ByteVector vPlain = AsciiBytes("Attack at dawn");
			Assert::IsTrue(WriteBinaryFile(strInput, BufferCiphertext(CALG_RC4, vPlain, Secret())));

			{
				// The file is opened with MFC's default sharing mode, which does not tolerate another open handle.
				OpenFileHandle handle(strInput);
				Assert::IsTrue(handle.IsOpen(), L"the test cannot open the file");

				Assert::IsFalse(RunDecryptFile(CALG_RC4, strOutput, strInput, Secret()));
				Assert::IsFalse(PathExists(strOutput), L"an output file was created");
			}

			Assert::IsTrue(RunDecryptFile(CALG_RC4, strOutput, strInput, Secret()));
			AssertBytesEqual(vPlain, ReadBinaryFile(strOutput));
		}

		TEST_METHOD(OutputOpenElsewhere_ReturnsFalseAndKeepsItsContentUntilItIsReleased)
		{
			TempDirectory dir;
			const CString strInput = dir.Path(_T("cipher.bin"));
			const CString strOutput = dir.Path(_T("plain.bin"));
			const ByteVector vPlain = AsciiBytes("Attack at dawn");
			const ByteVector vOld = AsciiBytes("existing content");
			Assert::IsTrue(WriteBinaryFile(strInput, BufferCiphertext(CALG_RC4, vPlain, Secret())));
			Assert::IsTrue(WriteBinaryFile(strOutput, vOld));

			{
				OpenFileHandle handle(strOutput);
				Assert::IsTrue(handle.IsOpen(), L"the test cannot open the file");

				Assert::IsFalse(RunDecryptFile(CALG_RC4, strOutput, strInput, Secret()));
			}

			AssertBytesEqual(vOld, ReadBinaryFile(strOutput), L"a failed call must not touch the output");
			Assert::IsTrue(RunDecryptFile(CALG_RC4, strOutput, strInput, Secret()));
			AssertBytesEqual(vPlain, ReadBinaryFile(strOutput));
		}

		TEST_METHOD(OutputSameAsInput_ReturnsFalseAndKeepsTheContent)
		{
			TempDirectory dir;
			const CString strPath = dir.Path(_T("data.bin"));
			const ByteVector vCipher = BufferCiphertext(CALG_3DES, PseudoRandomBytes(1000, 3700), Secret());
			Assert::IsTrue(WriteBinaryFile(strPath, vCipher));

			// The input is still open, with exclusive access, when the output is created.
			Assert::IsFalse(RunDecryptFile(CALG_3DES, strPath, strPath, Secret()));

			AssertBytesEqual(vCipher, ReadBinaryFile(strPath), L"the file must not change");
		}

		TEST_METHOD(AfterAFailedCall_TheInputIsClosed)
		{
			TempDirectory dir;
			const CString strInput = dir.Path(_T("cipher.bin"));
			Assert::IsTrue(WriteBinaryFile(strInput, PseudoRandomBytes(13, 3800)));

			Assert::IsFalse(RunDecryptFile(CALG_DES, dir.Path(_T("plain.bin")), strInput, Secret()));

			Assert::IsTrue(::DeleteFile(strInput) != FALSE, L"a handle to the input file was left open");
		}

		// ------------------------------------------------------------------
		// Diagnostics
		// ------------------------------------------------------------------

		TEST_METHOD(MissingInputFile_WritesTheFileErrorToTheDebugOutput)
		{
			if (!DebugOutputCapture::IsSupported())
			{
				Logger::WriteMessage(L"Skipped: a debugger is attached and consumes the debug output.");
				return;
			}

			TempDirectory dir;
			const CString strInput = dir.Path(_T("missing.bin"));

			DebugOutputCapture capture;
			Assert::IsFalse(RunDecryptFile(CALG_RC4, dir.Path(_T("plain.bin")), strInput, Secret()));

			const CString strOutput = capture.Text();
			Assert::IsTrue(strOutput.Find(strInput) >= 0, strOutput);
		}

		TEST_METHOD(DamagedCiphertext_ReportsTheFailedStepOnTheDebugOutput)
		{
			if (!DebugOutputCapture::IsSupported())
			{
				Logger::WriteMessage(L"Skipped: a debugger is attached and consumes the debug output.");
				return;
			}

			TempDirectory dir;
			const CString strInput = dir.Path(_T("cipher.bin"));
			Assert::IsTrue(WriteBinaryFile(strInput, PseudoRandomBytes(13, 3900)));

			DebugOutputCapture capture;
			Assert::IsFalse(RunDecryptFile(CALG_DES, dir.Path(_T("plain.bin")), strInput, Secret()));

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

			TempDirectory dir;
			const CString strInput = dir.Path(_T("cipher.bin"));
			Assert::IsTrue(WriteBinaryFile(strInput, BufferCiphertext(CALG_RC4, AsciiBytes("Attack at dawn"), Secret())));

			DebugOutputCapture capture;
			Assert::IsTrue(RunDecryptFile(CALG_RC4, dir.Path(_T("plain.bin")), strInput, Secret()));

			const CString strOutput = capture.Text();
			Assert::IsTrue(strOutput.Find(_T("[Crypt]")) < 0 && strOutput.Find(strInput) < 0, strOutput);
		}
	};

	// ----------------------------------------------------------------------
	// EncryptFile followed by DecryptFile
	// ----------------------------------------------------------------------

	TEST_CLASS(EncryptionFileRoundTripTests)
	{
	public:
		TEST_ASSERTION_GUARD()

		TEST_METHOD(EveryCipher_RestoresTheFile)
		{
			TempDirectory dir;

			for (const Cipher& cipher : CIPHERS)
			{
				for (size_t nSize : SIZES)
				{
					const ByteVector vPlain = PseudoRandomBytes(nSize, static_cast<unsigned int>(nSize) + 4000);

					AssertBytesEqual(vPlain, RoundTrip(cipher.nAlgorithm, dir, vPlain, Secret()), DescribeCase(cipher.nAlgorithm, nSize));
				}
			}
		}

		TEST_METHOD(EveryCipher_RestoresBinaryContent)
		{
			TempDirectory dir;
			const ByteVector arrData[] = { AllByteValues(), Repeat(0x00, 300), Repeat(0xFF, 300) };

			for (const Cipher& cipher : CIPHERS)
			{
				for (const ByteVector& vPlain : arrData)
					AssertBytesEqual(vPlain, RoundTrip(cipher.nAlgorithm, dir, vPlain, Secret()), DescribeCase(cipher.nAlgorithm, vPlain.size()));
			}
		}

		TEST_METHOD(EveryCipher_RestoresTheFileWithADialogStyleSecret)
		{
			TempDirectory dir;
			const ByteVector vSecret = Utf16Bytes(GetComputerID());
			const ByteVector vPlain = PseudoRandomBytes(5000, 4001);

			for (const Cipher& cipher : CIPHERS)
				AssertBytesEqual(vPlain, RoundTrip(cipher.nAlgorithm, dir, vPlain, vSecret), cipher.lpszName);
		}

		TEST_METHOD(EveryCipher_RestoresTheFileWithSecretsOfAnyLength)
		{
			TempDirectory dir;
			const ByteVector vPlain = PseudoRandomBytes(777, 4002);

			for (const Cipher& cipher : CIPHERS)
			{
				for (size_t nLength : { 1, 5, 64, 1000 })
					AssertBytesEqual(vPlain, RoundTrip(cipher.nAlgorithm, dir, vPlain, PseudoRandomBytes(nLength, 4003)), DescribeCase(cipher.nAlgorithm, nLength));
			}
		}

		TEST_METHOD(Rc4_AppliedTwice_RestoresTheFile)
		{
			// The dialog calls the same operation to encrypt and to decrypt a file.
			TempDirectory dir;
			const CString strPlain = dir.Path(_T("plain.txt"));
			const CString strCipher = dir.Path(_T("plain.enc"));
			const CString strRestored = dir.Path(_T("plain.dec"));
			const ByteVector vSecret = Utf16Bytes(GetComputerID());
			const ByteVector vPlain = PseudoRandomBytes(1234, 4004);
			Assert::IsTrue(WriteBinaryFile(strPlain, vPlain));

			Assert::IsTrue(RunEncryptFile(CALG_RC4, strCipher, strPlain, vSecret));
			Assert::IsTrue(RunEncryptFile(CALG_RC4, strRestored, strCipher, vSecret));

			AssertBytesNotEqual(vPlain, ContentOf(strCipher), L"the encrypted file");
			AssertBytesEqual(vPlain, ContentOf(strRestored), L"the file encrypted twice");
		}

		TEST_METHOD(EncryptedFile_CannotBeDecryptedWithAnotherSecretOrCipher)
		{
			TempDirectory dir;
			const ByteVector vPlain = PseudoRandomBytes(1000, 4005);
			const CString strPlain = dir.Path(_T("plain.bin"));
			const CString strCipher = dir.Path(_T("cipher.bin"));
			Assert::IsTrue(WriteBinaryFile(strPlain, vPlain));
			Assert::IsTrue(RunEncryptFile(CALG_RC4, strCipher, strPlain, Secret()));

			const CString strOther = FreshPath(dir, _T("other.bin"));
			Assert::IsTrue(RunDecryptFile(CALG_RC4, strOther, strCipher, AsciiBytes("Another secret")));
			AssertBytesNotEqual(vPlain, ContentOf(strOther), L"another secret");

			const CString strRestored = FreshPath(dir, _T("restored.bin"));
			Assert::IsTrue(RunDecryptFile(CALG_RC4, strRestored, strCipher, Secret()));
			AssertBytesEqual(vPlain, ContentOf(strRestored), L"the right secret");
		}

		TEST_METHOD(LargeFile_IsRestored)
		{
			TempDirectory dir;
			const ByteVector vPlain = PseudoRandomBytes(3000000, 4006);

			for (ALG_ID nAlgorithm : { CALG_RC4, CALG_3DES })
				AssertBytesEqual(vPlain, RoundTrip(nAlgorithm, dir, vPlain, Secret()), NameOf(nAlgorithm));
		}

		TEST_METHOD(ConcurrentCalls_ReturnCorrectResults)
		{
			TempDirectory dir;

			// The threads must not assert, so they only use helpers that report with a return value.
			RunConcurrently(CONCURRENT_THREADS, [&dir](unsigned int nThread, WorkerFailures& failures)
			{
				for (unsigned int nIteration = 0; nIteration < CONCURRENT_ITERATIONS; nIteration++)
				{
					CString strName;
					strName.Format(_T("t%u_i%u"), nThread, nIteration);
					const CString strPlain = dir.Path(strName + _T(".bin"));
					const CString strCipher = dir.Path(strName + _T(".enc"));
					const CString strRestored = dir.Path(strName + _T(".dec"));

					const Cipher& cipher = CIPHERS[(nThread + nIteration) % _countof(CIPHERS)];
					const ByteVector vPlain = PseudoRandomBytes(1 + nIteration * 401, nThread * 1000 + nIteration + 1);
					ByteVector vSecret = PseudoRandomBytes(1 + nThread * 7 + nIteration, nIteration + 1);

					CString strProblem;
					if (!WriteBinaryFile(strPlain, vPlain))
						strProblem = _T("the plaintext file could not be written");
					else if (!EncryptFile(cipher.nAlgorithm, strCipher, strPlain, vSecret.data(), static_cast<DWORD>(vSecret.size())))
						strProblem = _T("EncryptFile failed");
					else if (!DecryptFile(cipher.nAlgorithm, strRestored, strCipher, vSecret.data(), static_cast<DWORD>(vSecret.size())))
						strProblem = _T("DecryptFile failed");
					else if (ReadBinaryFile(strRestored) != vPlain)
						strProblem = _T("the restored file differs from the plaintext");

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
