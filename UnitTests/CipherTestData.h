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

// CipherTestData.h : the ciphers and the known answers shared by the encryption tests.
// Include stdafx.h before this header.

#pragma once

#include "TestHelpers.h"

namespace TestHelpers
{
	/** A cipher that the PROV_RSA_FULL provider offers and that EncryptBuffer and DecryptBuffer can use. */
	struct Cipher
	{
		ALG_ID nAlgorithm;
		LPCTSTR lpszName;
		size_t nBlockSize; // 0 for a stream cipher
	};

	inline const Cipher CIPHERS[] =
	{
		{ CALG_RC4, _T("RC4"), 0 },
		{ CALG_RC2, _T("RC2"), 8 },
		{ CALG_DES, _T("DES"), 8 },
		{ CALG_3DES, _T("3DES"), 8 },
		{ CALG_3DES_112, _T("3DES-112"), 8 },
	};

	inline LPCTSTR NameOf(ALG_ID nAlgorithm)
	{
		for (const Cipher& cipher : CIPHERS)
		{
			if (cipher.nAlgorithm == nAlgorithm)
				return cipher.lpszName;
		}
		return _T("unknown algorithm");
	}

	/** Length of the ciphertext: a block cipher pads the plaintext with 1 to nBlockSize bytes. */
	inline size_t CiphertextLength(const Cipher& cipher, size_t nPlaintextLength)
	{
		if (cipher.nBlockSize == 0)
			return nPlaintextLength;
		return (nPlaintextLength / cipher.nBlockSize + 1) * cipher.nBlockSize;
	}

	/** The secret of the known answers. */
	inline ByteVector Secret()
	{
		return AsciiBytes("Secret");
	}

	struct KnownAnswer
	{
		ALG_ID nAlgorithm;
		LPCSTR lpszPlaintext;
		LPCSTR lpszCiphertext;
	};

	// Computed with an independent implementation (PyCryptodome) for the secret "Secret":
	// the key is derived from MD5(secret) like CryptDeriveKey does, the block ciphers run
	// in CBC mode with a zero IV and PKCS#7 padding.
	inline const KnownAnswer KNOWN_ANSWERS[] =
	{
		{ CALG_RC4, "A", "4D" },
		{ CALG_RC4, "Attack at dawn", "4D92DFD6CFFFDD3EE09F643A66F5" },
		{ CALG_RC4, "12345678", "3DD4988399A2CA67" },
		{ CALG_RC4, "Hello, CryptoAPI!", "4483C7DBC3B8DD1CE6C6702F7EDACCBCCF" },

		{ CALG_RC2, "A", "C045F0F7C4EC651D" },
		{ CALG_RC2, "Attack at dawn", "A2339DCA1F111C3DAF846F4B553DC896" },
		{ CALG_RC2, "12345678", "AD719EEF64CE0C04FB3B20C22F27841B" },
		{ CALG_RC2, "Hello, CryptoAPI!", "6DD8EFECD8B8193B4592DA08D779C43A0BB97DF4D398F50E" },

		{ CALG_DES, "A", "0A9CB0ECC04AE09D" },
		{ CALG_DES, "Attack at dawn", "4B126B2A0BEBA7BD50063FCC4B73FD47" },
		{ CALG_DES, "12345678", "C45D643FB09D70DEEB8BA7AC5C7D79AA" },
		{ CALG_DES, "Hello, CryptoAPI!", "F9AFE90CBD6FFF1CAEC7B94D3B0EA15AFE086D22664FE946" },

		{ CALG_3DES, "A", "B713A0EAE5A109AC" },
		{ CALG_3DES, "Attack at dawn", "AF563915CC7A3BA8C7347D149934F3DC" },
		{ CALG_3DES, "12345678", "82C2BC2553117904D9D87F22BB8E4D66" },
		{ CALG_3DES, "Hello, CryptoAPI!", "D06D459BA0B437CBB26C3429C502A400C691AEBD16C32588" },

		{ CALG_3DES_112, "A", "7576A4F3EE14B0C6" },
		{ CALG_3DES_112, "Attack at dawn", "FDFA0EF3710000568E8F872A7D1DFFFD" },
		{ CALG_3DES_112, "12345678", "E378240EDC712CA80DA5E1509C54B296" },
		{ CALG_3DES_112, "Hello, CryptoAPI!", "06923171E171C60D8D35F1BFC70F845216F192C484358DCD" },
	};

	/** An algorithm that PROV_RSA_FULL does not offer as a cipher. */
	struct UnsupportedAlgorithm
	{
		ALG_ID nAlgorithm;
		LPCTSTR lpszName;
	};

	inline const UnsupportedAlgorithm UNSUPPORTED_ALGORITHMS[] =
	{
		{ CALG_MD5, _T("MD5") },
		{ CALG_SHA1, _T("SHA-1") },
		{ CALG_SHA_256, _T("SHA-256") },
		{ CALG_AES_128, _T("AES-128") },
		{ CALG_AES_192, _T("AES-192") },
		{ CALG_AES_256, _T("AES-256") },
		{ 0x00FF, _T("not an algorithm") },
	};
}
