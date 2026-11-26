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

// TestModule.cpp : module level setup of the CryptLibraryDemo unit tests.

#include "stdafx.h"
#include "TestHelpers.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace CryptLibraryDemoTests
{
	namespace
	{
		/** The module that holds the test code and its resources. */
		HMODULE GetTestModule()
		{
			HMODULE hModule = nullptr;
			::GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
				reinterpret_cast<LPCTSTR>(&GetTestModule), &hModule);
			return hModule;
		}
	}

	TEST_MODULE_INITIALIZE(InitializeModule)
	{
		// MFC loads its standard strings, such as the text of a CFileException, from the
		// current resource module. That is the test host unless it is changed here.
		AfxSetResourceHandle(GetTestModule());

		// Debug builds of the code under test use ASSERT/VERIFY, which would otherwise
		// block the test run with a modal dialog.
		TestHelpers::AssertionMonitor::Install();
	}

	TEST_MODULE_CLEANUP(CleanupModule)
	{
		TestHelpers::AssertionMonitor::Uninstall();
	}
}
