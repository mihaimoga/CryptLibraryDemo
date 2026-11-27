# AGENTS.md

## Project overview

CryptLibraryDemo is a Windows desktop demonstration application built with MFC and the Windows CryptoAPI. The reusable cryptographic helpers are implemented in `CryptographyExt.h` and `CryptographyExt.cpp`; the dialog UI is implemented in `CryptLibraryDemoDlg.h`, `CryptLibraryDemoDlg.cpp`, and `CryptLibraryDemo.rc`. The unit tests for the helpers are in `UnitTests/` (see "Testing").

## Toolchain and build

- Build on Windows with Visual Studio 2022 or compatible Build Tools that provide the MSVC v145 toolset, Windows 10 SDK, and static MFC support.
- The project file is `CryptLibraryDemo.vcxproj`; it supports `Debug` and `Release` configurations for `Win32` and `x64`.
- Build from a Developer PowerShell for Visual Studio, for example:
  - `msbuild CryptLibraryDemo.vcxproj /p:Configuration=Debug /p:Platform=x64`
  - `msbuild CryptLibraryDemo.vcxproj /p:Configuration=Release /p:Platform=Win32`
- The project uses warning level 4 and C++ latest language mode. Resolve warnings introduced by a change.
- Validate functional changes to `CryptographyExt.*` with the unit tests described under "Testing"; validate dialog changes by building the affected configuration and manually exercising the relevant dialog workflow.

## Testing

- `UnitTests/` is a native unit test project (`UnitTests.vcxproj`, Microsoft Unit Testing Framework for C++) in `CryptLibraryDemo.sln`. It compiles `CryptographyExt.cpp` directly, links MFC statically, and covers every function declared in `CryptographyExt.h`.
- Build only the test project: a post-build event in `UnitTests.vcxproj` runs `vstest.console.exe` on the new `UnitTests.dll`, so the build itself runs all the tests, for example:
  - `msbuild UnitTests\UnitTests.vcxproj /p:Configuration=Debug /p:Platform=x64`
  - `msbuild UnitTests\UnitTests.vcxproj /p:Configuration=Release /p:Platform=Win32`
- The event is defined for all four configurations and runs on every build, even when nothing was recompiled, so there is no need to run `vstest.console.exe` after `msbuild`. The log lists every test and ends with the `Total tests`, `Passed` and `Failed` counts. A failing test fails the build (`error MSB3073`, exit code 1) and is printed, with its message and source line, above that error. The event starts `$(VSInstallDir)Common7\IDE\Extensions\TestPlatform\vstest.console.exe`, so the Visual Studio installation that builds the project must include the Test Platform.
- To run the tests again without building, or only some of them, run `vstest.console.exe` on the DLL, for example `vstest.console.exe UnitTests\x64\Debug\UnitTests.dll /TestCaseFilter:"Name=Md5_OfAbc_ReturnsRfc1321Digest"`. It takes the platform from the DLL, so the Win32 DLLs need no `/Platform` option.
- Do not build `CryptLibraryDemo.vcxproj` or the whole solution just to run the tests: its custom build step regenerates `hlp/HTMLDefines.h`. `CryptLibraryDemo.sln` builds `UnitTests` before the application, so a solution build runs the tests too and a failing test stops it before the application is built; building `CryptLibraryDemo.vcxproj` alone does not run them.
- After changing `CryptographyExt.*`, run the tests in `Debug` and `Release`, and add or update tests for the changed behavior. A failed MFC `ASSERT` or `VERIFY` in the code under test fails a test only in `Debug`; `Release` compiles them out.
- Take expected values from an independent oracle (a published test vector, CNG, or another OS API), not from the code under test.
- Never call `Assert` or the asserting helpers of `TestHelpers.h` on a worker thread: a failed `Assert` off the test thread terminates the test host and hides the other results. Use `RunConcurrently` and `WorkerFailures`, which report the problems on the test thread.
- Add new test files to both `UnitTests.vcxproj` and `UnitTests.vcxproj.filters`. The `Release` configurations use warning level 3, like the application, because the `ASSERT`-only parameters of `CryptographyExt.cpp` raise C4100 at level 4.

## Source conventions

- Keep the existing tab-based indentation and MFC/Win32 naming conventions (`CString`, `DWORD`, `LPBYTE`, `m_` member prefixes).
- Include `stdafx.h` first in every `.cpp` file that participates in the project's precompiled-header build.
- Preserve the GPL license header in existing source files.
- Match the established Doxygen-style documentation for public or non-obvious functions; avoid redundant comments.
- Add new source or header files to both `CryptLibraryDemo.vcxproj` and `CryptLibraryDemo.vcxproj.filters`.

## Crypto and Windows API changes

- Keep cryptographic operations and buffer-size handling in `CryptographyExt.*`; keep UI event handling in the dialog classes.
- Check every Win32/CryptoAPI return value, clean up acquired handles on all paths, and report failures using the existing error-reporting conventions.
- Do not log plaintext, keys, passwords, or other sensitive material. Avoid weakening algorithm choices or error handling for compatibility.

## Resources and generated files

- Update `Resource.h` and `CryptLibraryDemo.rc` together when adding controls, dialogs, commands, or string resources.
- Treat `hlp/HTMLDefines.h` as generated by the project's custom build step; do not hand-edit it.
- Keep changes focused and avoid modifying generated build output such as `Debug/`, `Release/`, `x64/`, `.obj`, `.pdb`, `.exe`, or `.chm` files.

## Documentation

- Keep `CryptLibraryDemo.html` in step with `README.md`: the HTML page has the same content as the README, so change both together and keep its tab indentation.
- Record each user-visible change (a feature, a fix, or new tests) in the latest entry of the History list in `ReleaseNotes.html`, and start a new entry for a new version.
- When a change completes an item of the Roadmap, remove the item from `README.md` and `CryptLibraryDemo.html`.
