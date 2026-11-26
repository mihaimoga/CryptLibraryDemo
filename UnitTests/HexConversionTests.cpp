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

// HexConversionTests.cpp : unit tests for ConvertBinaryToHexa and ConvertHexaToBinary.

#include "stdafx.h"
#include "CryptographyExt.h"
#include "TestHelpers.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;
using namespace TestHelpers;

namespace CryptLibraryDemoTests
{
	namespace
	{
		/** Content of every output element the code under test must not touch. */
		const TCHAR TEXT_SENTINEL = _T('#');
		const BYTE BYTE_SENTINEL = 0x5A;

		/** Elements placed behind an output buffer to detect a write past its end. */
		const size_t GUARD_LENGTH = 4;

		const size_t ROUND_TRIP_SIZES[] = { 1, 2, 3, 15, 16, 17, 255, 256, 1000 };

		CString Describe(size_t nLength)
		{
			CString strText;
			strText.Format(_T("%I64u byte(s)"), static_cast<ULONGLONG>(nLength));
			return strText;
		}

		/**
		 * ConvertBinaryToHexa into a buffer that has exactly the size the function needs: two
		 * digits per byte and the terminator. The function must not write behind it.
		 */
		CString Encode(const ByteVector& vData)
		{
			ByteVector vInput(vData);
			const DWORD dwLength = static_cast<DWORD>(vInput.size());
			if (vInput.empty())
				vInput.push_back(0); // a null pointer is rejected even when there is nothing to convert

			const size_t nCapacity = 2 * static_cast<size_t>(dwLength) + 1;
			std::vector<TCHAR> vText(nCapacity + GUARD_LENGTH, TEXT_SENTINEL);
			Assert::IsTrue(ConvertBinaryToHexa(vText.data(), static_cast<DWORD>(nCapacity), vInput.data(), dwLength), L"ConvertBinaryToHexa failed");

			for (size_t nIndex = nCapacity; nIndex < vText.size(); nIndex++)
				Assert::IsTrue(vText[nIndex] == TEXT_SENTINEL, L"ConvertBinaryToHexa wrote behind the output buffer");
			Assert::IsTrue(vText[2 * static_cast<size_t>(dwLength)] == _T('\0'), L"The text is not terminated");
			return CString(vText.data());
		}

		/**
		 * ConvertHexaToBinary into a buffer that has exactly the size the function needs. The
		 * function must not write behind the decoded bytes; an odd last digit is not decoded.
		 */
		ByteVector Decode(const CString& strHexa)
		{
			const DWORD dwLength = static_cast<DWORD>(strHexa.GetLength());
			const size_t nCapacity = (static_cast<size_t>(dwLength) + 1) / 2;
			const size_t nDecoded = dwLength / 2;

			ByteVector vOutput(nCapacity + GUARD_LENGTH, BYTE_SENTINEL);
			Assert::IsTrue(ConvertHexaToBinary(vOutput.data(), static_cast<DWORD>(nCapacity), (LPCTSTR)strHexa, dwLength), L"ConvertHexaToBinary failed");

			for (size_t nIndex = nDecoded; nIndex < vOutput.size(); nIndex++)
				Assert::IsTrue(vOutput[nIndex] == BYTE_SENTINEL, L"ConvertHexaToBinary wrote more than the decoded bytes");
			vOutput.resize(nDecoded);
			return vOutput;
		}

		/** Gives the CLongBinary a block of fixed global memory that holds a copy of the bytes. */
		void SetData(CLongBinary& binary, const ByteVector& vData)
		{
			binary.m_hData = ::GlobalAlloc(GPTR, vData.size() + sizeof(TCHAR));
			Assert::IsTrue(binary.m_hData != nullptr, L"GlobalAlloc failed");

			void* pData = ::GlobalLock(binary.m_hData);
			Assert::IsTrue(pData != nullptr, L"GlobalLock failed");
			if (!vData.empty())
				memcpy(pData, vData.data(), vData.size());
			::GlobalUnlock(binary.m_hData);

			binary.m_dwDataLength = vData.size();
		}

		void SetText(CLongBinary& binary, const CString& strText)
		{
			ByteVector vData(static_cast<size_t>(strText.GetLength()) * sizeof(TCHAR));
			if (!vData.empty())
				memcpy(vData.data(), (LPCTSTR)strText, vData.size());
			SetData(binary, vData);
		}

		ByteVector GetData(const CLongBinary& binary)
		{
			ByteVector vData(static_cast<size_t>(binary.m_dwDataLength));
			if (vData.empty())
				return vData;

			Assert::IsTrue(binary.m_hData != nullptr, L"The CLongBinary has a length but no data");
			const void* pData = ::GlobalLock(binary.m_hData);
			Assert::IsTrue(pData != nullptr, L"GlobalLock failed");
			memcpy(vData.data(), pData, vData.size());
			::GlobalUnlock(binary.m_hData);
			return vData;
		}

		CString GetText(const CLongBinary& binary)
		{
			const ByteVector vData = GetData(binary);
			if (vData.empty())
				return CString();
			return CString(reinterpret_cast<LPCTSTR>(vData.data()), static_cast<int>(vData.size() / sizeof(TCHAR)));
		}

		/** The character behind the text of a CLongBinary; the code under test must terminate the text. */
		TCHAR GetTerminator(const CLongBinary& binary)
		{
			Assert::IsTrue(binary.m_hData != nullptr, L"The CLongBinary has no data");
			const TCHAR* lpszText = static_cast<const TCHAR*>(::GlobalLock(binary.m_hData));
			Assert::IsTrue(lpszText != nullptr, L"GlobalLock failed");
			const TCHAR chTerminator = lpszText[binary.m_dwDataLength / sizeof(TCHAR)];
			::GlobalUnlock(binary.m_hData);
			return chTerminator;
		}

		void AssertLength(size_t nExpected, const CLongBinary& binary, LPCWSTR lpszMessage)
		{
			Assert::AreEqual(static_cast<ULONGLONG>(nExpected), static_cast<ULONGLONG>(binary.m_dwDataLength), lpszMessage);
		}

		bool ToHexa(CLongBinary& target, CLongBinary& source)
		{
			return ConvertBinaryToHexa(&target, &source);
		}

		bool ToBinary(CLongBinary& target, CLongBinary& source)
		{
			return ConvertHexaToBinary(&target, &source);
		}
	}

	// ----------------------------------------------------------------------
	// ConvertBinaryToHexa(LPTSTR, DWORD, LPBYTE, DWORD)
	// ----------------------------------------------------------------------

	TEST_CLASS(ConvertBinaryToHexaBufferTests)
	{
	public:
		TEST_ASSERTION_GUARD()

		TEST_METHOD(KnownBytes_ReturnUppercaseHexa)
		{
			AssertStringsEqual(_T("00010F107F80ABCDEFFF"), Encode(FromHex("00 01 0F 10 7F 80 AB CD EF FF")));
		}

		TEST_METHOD(EveryDigit_IsProduced)
		{
			AssertStringsEqual(_T("0123456789ABCDEF"), Encode(FromHex("01 23 45 67 89 AB CD EF")));
		}

		TEST_METHOD(LettersAreUppercase)
		{
			AssertStringsEqual(_T("ABCDEF"), Encode(FromHex("abcdef")));
		}

		TEST_METHOD(EveryByteValue_BecomesTwoDigits)
		{
			const CString strResult = Encode(AllByteValues());

			Assert::AreEqual(512, strResult.GetLength());
			AssertStringsEqual(_T("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"), strResult.Left(64));
			AssertStringsEqual(_T("E0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF"), strResult.Right(64));
			AssertStringsEqual(ToHex(AllByteValues()), strResult);
		}

		TEST_METHOD(ResultLength_IsTwiceTheInputLength)
		{
			for (size_t nSize : ROUND_TRIP_SIZES)
				Assert::AreEqual(static_cast<int>(2 * nSize), Encode(PseudoRandomBytes(nSize, 5)).GetLength(), Describe(nSize));
		}

		TEST_METHOD(LeadingAndTrailingZeroBytes_KeepTheirDigits)
		{
			AssertStringsEqual(_T("0000FF0000"), Encode(FromHex("00 00 FF 00 00")));
		}

		TEST_METHOD(EmptyInput_ProducesAnEmptyString)
		{
			Assert::AreEqual(0, Encode(ByteVector()).GetLength());
		}

		TEST_METHOD(OutputBufferLargerThanNeeded_IsWrittenOnlyUpToTheTerminator)
		{
			ByteVector vInput = FromHex("1234ABCD");
			std::vector<TCHAR> vText(32, TEXT_SENTINEL);

			Assert::IsTrue(ConvertBinaryToHexa(vText.data(), static_cast<DWORD>(vText.size()), vInput.data(), static_cast<DWORD>(vInput.size())));

			AssertStringsEqual(_T("1234ABCD"), CString(vText.data()));
			for (size_t nIndex = 9; nIndex < vText.size(); nIndex++)
				Assert::IsTrue(vText[nIndex] == TEXT_SENTINEL, Describe(nIndex));
		}

		TEST_METHOD(ShorterLengthArgument_ConvertsOnlyThatPrefix)
		{
			ByteVector vInput = FromHex("12 34 56 78");
			std::vector<TCHAR> vText(16, TEXT_SENTINEL);

			Assert::IsTrue(ConvertBinaryToHexa(vText.data(), static_cast<DWORD>(vText.size()), vInput.data(), 2));

			AssertStringsEqual(_T("1234"), CString(vText.data()));
		}

		TEST_METHOD(PreviousContentOfTheOutput_IsOverwritten)
		{
			ByteVector vInput = FromHex("AB");
			std::vector<TCHAR> vText(8, _T('Z'));

			Assert::IsTrue(ConvertBinaryToHexa(vText.data(), static_cast<DWORD>(vText.size()), vInput.data(), 1));

			AssertStringsEqual(_T("AB"), CString(vText.data()));
		}

		TEST_METHOD(InputBuffer_IsNotModified)
		{
			const ByteVector vOriginal = PseudoRandomBytes(100, 7);
			ByteVector vInput(vOriginal);
			std::vector<TCHAR> vText(201);

			Assert::IsTrue(ConvertBinaryToHexa(vText.data(), static_cast<DWORD>(vText.size()), vInput.data(), static_cast<DWORD>(vInput.size())));

			AssertBytesEqual(vOriginal, vInput);
		}

		TEST_METHOD(LargeInput_IsConverted)
		{
			const ByteVector vInput = PseudoRandomBytes(1000000, 42);

			AssertStringsEqual(ToHex(vInput), Encode(vInput));
		}
	};

	// ----------------------------------------------------------------------
	// ConvertHexaToBinary(LPBYTE, DWORD, LPCTSTR, DWORD)
	// ----------------------------------------------------------------------

	TEST_CLASS(ConvertHexaToBinaryBufferTests)
	{
	public:
		TEST_ASSERTION_GUARD()

		TEST_METHOD(KnownDigits_ReturnTheBytes)
		{
			AssertBytesEqual(FromHex("00 01 0F 10 7F 80 AB CD EF FF"), Decode(_T("00010F107F80ABCDEFFF")));
		}

		TEST_METHOD(EveryDigit_IsDecoded)
		{
			AssertBytesEqual(FromHex("01 23 45 67 89 AB CD EF"), Decode(_T("0123456789ABCDEF")));
		}

		TEST_METHOD(EveryByteValue_IsDecoded)
		{
			AssertBytesEqual(AllByteValues(), Decode(ToHex(AllByteValues())));
		}

		TEST_METHOD(DigitOrder_HighNibbleComesFirst)
		{
			AssertBytesEqual(FromHex("10"), Decode(_T("10")));
			AssertBytesEqual(FromHex("01"), Decode(_T("01")));
			AssertBytesEqual(FromHex("A5 5A"), Decode(_T("A55A")));
		}

		TEST_METHOD(LeadingZeroDigits_ArePreserved)
		{
			AssertBytesEqual(FromHex("00 00 01"), Decode(_T("000001")));
		}

		TEST_METHOD(EmptyInput_DecodesNothing)
		{
			Assert::AreEqual(static_cast<size_t>(0), Decode(CString()).size());
		}

		TEST_METHOD(OddNumberOfDigits_IgnoresTheTrailingDigit)
		{
			AssertBytesEqual(FromHex("AB"), Decode(_T("ABC")));
			Assert::AreEqual(static_cast<size_t>(0), Decode(_T("A")).size());
		}

		TEST_METHOD(ShorterLengthArgument_DecodesOnlyThatPrefix)
		{
			ByteVector vOutput(3, BYTE_SENTINEL);

			Assert::IsTrue(ConvertHexaToBinary(vOutput.data(), static_cast<DWORD>(vOutput.size()), _T("AABBCC"), 4));

			AssertBytesEqual(FromHex("AA BB 5A"), vOutput);
		}

		TEST_METHOD(InputLength_DecidesWhereDecodingStops)
		{
			// The text is not terminated, so only the length argument tells where it ends.
			const std::vector<TCHAR> vText = { _T('1'), _T('2'), _T('3'), _T('4') };
			ByteVector vOutput(4, BYTE_SENTINEL);

			Assert::IsTrue(ConvertHexaToBinary(vOutput.data(), static_cast<DWORD>(vOutput.size()), vText.data(), static_cast<DWORD>(vText.size())));

			AssertBytesEqual(FromHex("12 34 5A 5A"), vOutput);
		}

		TEST_METHOD(OutputBufferLargerThanNeeded_IsWrittenOnlyForTheDecodedBytes)
		{
			ByteVector vOutput(16, BYTE_SENTINEL);

			Assert::IsTrue(ConvertHexaToBinary(vOutput.data(), static_cast<DWORD>(vOutput.size()), _T("CAFE"), 4));

			ByteVector vExpected(16, BYTE_SENTINEL);
			vExpected[0] = 0xCA;
			vExpected[1] = 0xFE;
			AssertBytesEqual(vExpected, vOutput);
		}

		TEST_METHOD(InputText_IsNotModified)
		{
			const CString strOriginal = ToHex(PseudoRandomBytes(64, 3));
			CString strInput(strOriginal);

			Decode(strInput);

			AssertStringsEqual(strOriginal, strInput);
		}

		TEST_METHOD(LargeInput_IsDecoded)
		{
			const ByteVector vData = PseudoRandomBytes(1000000, 43);

			AssertBytesEqual(vData, Decode(ToHex(vData)));
		}
	};

	// ----------------------------------------------------------------------
	// ConvertBinaryToHexa(CLongBinary*, CLongBinary*)
	// ----------------------------------------------------------------------

	TEST_CLASS(ConvertBinaryToHexaLongBinaryTests)
	{
	public:
		TEST_ASSERTION_GUARD()

		TEST_METHOD(NullTarget_ReturnsFalse)
		{
			CLongBinary source;
			SetData(source, FromHex("AB"));

			Assert::IsFalse(ConvertBinaryToHexa(nullptr, &source));
		}

		TEST_METHOD(NullSource_ReturnsFalse)
		{
			CLongBinary target;

			Assert::IsFalse(ConvertBinaryToHexa(&target, nullptr));
		}

		TEST_METHOD(NullTargetAndSource_ReturnsFalse)
		{
			Assert::IsFalse(ConvertBinaryToHexa(static_cast<CLongBinary*>(nullptr), static_cast<CLongBinary*>(nullptr)));
		}

		TEST_METHOD(EmptySource_ReturnsTrueWithAnEmptyTarget)
		{
			CLongBinary source;
			CLongBinary target;
			target.m_dwDataLength = 123; // must be replaced

			Assert::IsTrue(ToHexa(target, source));

			Assert::IsTrue(target.m_hData == nullptr);
			AssertLength(0, target, L"target length");
		}

		TEST_METHOD(KnownBytes_ProduceUppercaseText)
		{
			CLongBinary source;
			CLongBinary target;
			SetData(source, FromHex("00 01 0F 10 7F 80 AB CD EF FF"));

			Assert::IsTrue(ToHexa(target, source));

			AssertStringsEqual(_T("00010F107F80ABCDEFFF"), GetText(target));
		}

		TEST_METHOD(TargetLength_CountsTheBytesOfTheText)
		{
			CLongBinary source;
			CLongBinary target;
			SetData(source, FromHex("01 02 03"));

			Assert::IsTrue(ToHexa(target, source));

			// Two characters per source byte, whatever the size of a character is.
			AssertLength(3 * 2 * sizeof(TCHAR), target, L"target length");
		}

		TEST_METHOD(TargetText_IsTerminated)
		{
			CLongBinary source;
			CLongBinary target;
			SetData(source, FromHex("12 34"));

			Assert::IsTrue(ToHexa(target, source));

			Assert::IsTrue(GetTerminator(target) == _T('\0'));
		}

		TEST_METHOD(EveryByteValue_BecomesTwoDigits)
		{
			CLongBinary source;
			CLongBinary target;
			SetData(source, AllByteValues());

			Assert::IsTrue(ToHexa(target, source));

			AssertStringsEqual(ToHex(AllByteValues()), GetText(target));
		}

		TEST_METHOD(Source_IsNotModified)
		{
			const ByteVector vOriginal = PseudoRandomBytes(100, 11);
			CLongBinary source;
			CLongBinary target;
			SetData(source, vOriginal);
			const HGLOBAL hSource = source.m_hData;

			Assert::IsTrue(ToHexa(target, source));

			Assert::IsTrue(source.m_hData == hSource);
			AssertLength(vOriginal.size(), source, L"source length");
			AssertBytesEqual(vOriginal, GetData(source));
			Assert::IsTrue(target.m_hData != hSource);
		}

		TEST_METHOD(SourceLengthWithoutData_ReturnsFalse)
		{
			CLongBinary source;
			CLongBinary target;
			source.m_dwDataLength = 4;

			Assert::IsFalse(ToHexa(target, source));
		}

		TEST_METHOD(LargeSource_IsConverted)
		{
			const ByteVector vData = PseudoRandomBytes(70000, 12);
			CLongBinary source;
			CLongBinary target;
			SetData(source, vData);

			Assert::IsTrue(ToHexa(target, source));

			AssertStringsEqual(ToHex(vData), GetText(target));
		}
	};

	// ----------------------------------------------------------------------
	// ConvertHexaToBinary(CLongBinary*, CLongBinary*)
	// ----------------------------------------------------------------------

	TEST_CLASS(ConvertHexaToBinaryLongBinaryTests)
	{
	public:
		TEST_ASSERTION_GUARD()

		TEST_METHOD(NullTarget_ReturnsFalse)
		{
			CLongBinary source;
			SetText(source, _T("AB"));

			Assert::IsFalse(ConvertHexaToBinary(nullptr, &source));
		}

		TEST_METHOD(NullSource_ReturnsFalse)
		{
			CLongBinary target;

			Assert::IsFalse(ConvertHexaToBinary(&target, nullptr));
		}

		TEST_METHOD(NullTargetAndSource_ReturnsFalse)
		{
			Assert::IsFalse(ConvertHexaToBinary(static_cast<CLongBinary*>(nullptr), static_cast<CLongBinary*>(nullptr)));
		}

		TEST_METHOD(EmptySource_ReturnsTrueWithAnEmptyTarget)
		{
			CLongBinary source;
			CLongBinary target;
			target.m_dwDataLength = 123; // must be replaced

			Assert::IsTrue(ToBinary(target, source));

			Assert::IsTrue(target.m_hData == nullptr);
			AssertLength(0, target, L"target length");
		}

		TEST_METHOD(KnownText_ProducesTheBytes)
		{
			CLongBinary source;
			CLongBinary target;
			SetText(source, _T("00010F107F80ABCDEFFF"));

			Assert::IsTrue(ToBinary(target, source));

			AssertBytesEqual(FromHex("00 01 0F 10 7F 80 AB CD EF FF"), GetData(target));
		}

		TEST_METHOD(TargetLength_IsHalfTheNumberOfDigits)
		{
			CLongBinary source;
			CLongBinary target;
			SetText(source, _T("010203"));

			Assert::IsTrue(ToBinary(target, source));

			AssertLength(3, target, L"target length");
		}

		TEST_METHOD(EveryByteValue_IsDecoded)
		{
			CLongBinary source;
			CLongBinary target;
			SetText(source, ToHex(AllByteValues()));

			Assert::IsTrue(ToBinary(target, source));

			AssertBytesEqual(AllByteValues(), GetData(target));
		}

		TEST_METHOD(OddNumberOfDigits_IgnoresTheTrailingDigit)
		{
			CLongBinary source;
			CLongBinary target;
			SetText(source, _T("ABC"));

			Assert::IsTrue(ToBinary(target, source));

			AssertBytesEqual(FromHex("AB"), GetData(target));
		}

		TEST_METHOD(SingleDigit_ProducesAnEmptyTarget)
		{
			CLongBinary source;
			CLongBinary target;
			SetText(source, _T("A"));

			Assert::IsTrue(ToBinary(target, source));

			AssertLength(0, target, L"target length");
		}

		TEST_METHOD(Source_IsNotModified)
		{
			const CString strOriginal = ToHex(PseudoRandomBytes(100, 13));
			CLongBinary source;
			CLongBinary target;
			SetText(source, strOriginal);
			const HGLOBAL hSource = source.m_hData;

			Assert::IsTrue(ToBinary(target, source));

			Assert::IsTrue(source.m_hData == hSource);
			AssertLength(strOriginal.GetLength() * sizeof(TCHAR), source, L"source length");
			AssertStringsEqual(strOriginal, GetText(source));
			Assert::IsTrue(target.m_hData != hSource);
		}

		TEST_METHOD(SourceLengthWithoutData_ReturnsFalse)
		{
			CLongBinary source;
			CLongBinary target;
			source.m_dwDataLength = 8 * sizeof(TCHAR);

			Assert::IsFalse(ToBinary(target, source));
		}

		TEST_METHOD(LargeSource_IsDecoded)
		{
			const ByteVector vData = PseudoRandomBytes(70000, 14);
			CLongBinary source;
			CLongBinary target;
			SetText(source, ToHex(vData));

			Assert::IsTrue(ToBinary(target, source));

			AssertBytesEqual(vData, GetData(target));
		}
	};

	// ----------------------------------------------------------------------
	// Round trips and agreement between the overloads
	// ----------------------------------------------------------------------

	TEST_CLASS(HexaConversionRoundTripTests)
	{
	public:
		TEST_ASSERTION_GUARD()

		TEST_METHOD(BufferOverloads_RestoreTheBytes)
		{
			for (size_t nSize : ROUND_TRIP_SIZES)
			{
				const ByteVector vData = PseudoRandomBytes(nSize, static_cast<unsigned int>(nSize));

				AssertBytesEqual(vData, Decode(Encode(vData)), Describe(nSize));
			}
		}

		TEST_METHOD(BufferOverloads_RestoreTheText)
		{
			const CString arrText[] = { _T("00"), _T("FF"), _T("0123456789ABCDEF"), _T("DEADBEEFCAFEBABE0123") };

			for (const CString& strText : arrText)
				AssertStringsEqual(strText, Encode(Decode(strText)), strText);
		}

		TEST_METHOD(LongBinaryOverloads_RestoreTheBytes)
		{
			for (size_t nSize : ROUND_TRIP_SIZES)
			{
				const ByteVector vData = PseudoRandomBytes(nSize, static_cast<unsigned int>(nSize) + 100);
				CLongBinary binary;
				CLongBinary hexa;
				CLongBinary restored;
				SetData(binary, vData);

				Assert::IsTrue(ToHexa(hexa, binary), Describe(nSize));
				Assert::IsTrue(ToBinary(restored, hexa), Describe(nSize));

				AssertBytesEqual(vData, GetData(restored), Describe(nSize));
			}
		}

		TEST_METHOD(BufferAndLongBinaryOverloads_ProduceTheSameText)
		{
			const ByteVector vData = PseudoRandomBytes(300, 99);
			CLongBinary binary;
			CLongBinary hexa;
			SetData(binary, vData);

			Assert::IsTrue(ToHexa(hexa, binary));

			AssertStringsEqual(Encode(vData), GetText(hexa));
		}

		TEST_METHOD(BufferAndLongBinaryOverloads_ProduceTheSameBytes)
		{
			const CString strHexa = ToHex(PseudoRandomBytes(300, 98));
			CLongBinary text;
			CLongBinary binary;
			SetText(text, strHexa);

			Assert::IsTrue(ToBinary(binary, text));

			AssertBytesEqual(Decode(strHexa), GetData(binary));
		}

		TEST_METHOD(TextFromTheLongBinaryOverload_IsAcceptedByTheBufferOverload)
		{
			const ByteVector vData = PseudoRandomBytes(64, 97);
			CLongBinary binary;
			CLongBinary hexa;
			SetData(binary, vData);
			Assert::IsTrue(ToHexa(hexa, binary));

			AssertBytesEqual(vData, Decode(GetText(hexa)));
		}
	};
}
