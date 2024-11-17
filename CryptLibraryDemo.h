/* Copyright (C) 2014-2025 Stefan-Mihai MOGA
This file is part of CryptLibraryDemo application developed by Stefan-Mihai MOGA.

CryptLibraryDemo is free software: you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the Open
Source Initiative, either version 3 of the License, or any later version.

CryptLibraryDemo is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with
CryptLibraryDemo. If not, see <http://www.opensource.org/licenses/gpl-3.0.html>*/

// CryptLibraryDemo.h : main header file for the PROJECT_NAME application
//

#pragma once

#ifndef __AFXWIN_H__
	#error "include 'stdafx.h' before including this file for PCH"
#endif

#include "resource.h"		// main symbols

// CCryptLibraryDemoApp:
// See CryptLibraryDemo.cpp for the implementation of this class
//

class CCryptLibraryDemoApp : public CWinAppEx
{
public:
	CCryptLibraryDemoApp();

// Overrides
public:
	virtual BOOL InitInstance();

// Implementation

	DECLARE_MESSAGE_MAP()
};

extern CCryptLibraryDemoApp theApp;
