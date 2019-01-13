#include <windows.h>
#include <stdio.h>
#include <assert.h>
#include <time.h>
#include <tchar.h>
#include <dbghelp.h>
#include "MiniDump.h"

#ifdef UNICODE
    #define _tcssprintf wsprintf
    #define tcsplitpath _wsplitpath
#else
    #define _tcssprintf sprintf
    #define tcsplitpath _splitpath
#endif

//-----------------------------------------------------------------------------
// GLOBALS
//-----------------------------------------------------------------------------
CMiniDumper* CMiniDumper::G_pMiniDumper = NULL;
LPCRITICAL_SECTION CMiniDumper::G_pCriticalSection = NULL;

// Based on dbghelp.h
typedef BOOL (WINAPI *MINIDUMPWRITEDUMP)(HANDLE hProcess,
                                         DWORD dwPid,
                                         HANDLE hFile,
                                         MINIDUMP_TYPE DumpType,
                                         CONST PMINIDUMP_EXCEPTION_INFORMATION ExceptionParam,
                                         CONST PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam,
                                         CONST PMINIDUMP_CALLBACK_INFORMATION CallbackParam);

//-----------------------------------------------------------------------------
// Name: CMiniDumper()
// Desc: Constructor
//-----------------------------------------------------------------------------
CMiniDumper::CMiniDumper(bool bPromptUserForMiniDump/* = false*/)
{
	// Our CMiniDumper should act alone as a singleton.
	assert(!G_pMiniDumper);

	G_pMiniDumper = this;
	m_bPromptUserForMiniDump = bPromptUserForMiniDump;

	// The SetUnhandledExceptionFilter function enables an application to 
	// supersede the top-level exception handler of each thread and process.
	// After calling this function, if an exception occurs in a process 
	// that is not being debugged, and the exception makes it to the 
	// unhandled exception filter, that filter will call the exception 
	// filter function specified by the lpTopLevelExceptionFilter parameter.
	::SetUnhandledExceptionFilter(UnhandledExceptionHandler);

	// Since DBGHELP.dll is not inherently thread-safe, making calls into it 
	// from more than one thread simultaneously may yield undefined behavior. 
	// This means that if your application has multiple threads, or is 
	// called by multiple threads in a non-synchronized manner, you need to  
	// make sure that all calls into DBGHELP.dll are isolated via a global
	// critical section.
	G_pCriticalSection = new CRITICAL_SECTION;

	if (G_pCriticalSection)
	{
		InitializeCriticalSection(G_pCriticalSection);
	}
}

//-----------------------------------------------------------------------------
// Name: ~CMiniDumper()
// Desc: Destructor
//-----------------------------------------------------------------------------
CMiniDumper::~CMiniDumper( void )
{
    if( G_pCriticalSection )
    {
		DeleteCriticalSection(G_pCriticalSection);
        delete G_pCriticalSection;
    }
}

//-----------------------------------------------------------------------------
// Name: UnhandledExceptionHandler()
// Desc: Call-back filter function for unhandled exceptions
//-----------------------------------------------------------------------------
LONG CMiniDumper::UnhandledExceptionHandler( _EXCEPTION_POINTERS *pExceptionInfo )
{
	if (!G_pMiniDumper)
	{
		return EXCEPTION_CONTINUE_SEARCH;
	}
	return G_pMiniDumper->WriteMiniDump(pExceptionInfo);
}

//-----------------------------------------------------------------------------
// Name: SetMiniDumpFileName()
// Desc: 
//-----------------------------------------------------------------------------
void CMiniDumper::SetMiniDumpFileName(time_t tt/* = time(0)*/)
{
	_tcssprintf(m_szMiniDumpPath,_T("%s%s.%ld.dmp"),m_szAppPath,m_szAppBaseName,tt);
}

//-----------------------------------------------------------------------------
// Name: GetImpersonationToken()
// Desc: The method acts as a potential workaround for the fact that the 
//       current thread may not have a token assigned to it, and if not, the 
//       process token is received.
//-----------------------------------------------------------------------------
bool CMiniDumper::GetImpersonationToken(HANDLE * phToken)
{
	*phToken = NULL;
	// No impersonation token for the current thread is available. 
	// Let's go for the process token instead.
	return (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, TRUE, phToken) ||
		((GetLastError() == ERROR_NO_TOKEN) &&
		OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, phToken)));
}

//-----------------------------------------------------------------------------
// Name: EnablePrivilege()
// Desc: Since a MiniDump contains a lot of meta-data about the OS and 
//       application state at the time of the dump, it is a rather privileged 
//       operation. This means we need to set the SeDebugPrivilege to be able 
//       to call MiniDumpWriteDump.
//-----------------------------------------------------------------------------
BOOL CMiniDumper::EnablePrivilege(LPCTSTR pszPriv, HANDLE hToken, TOKEN_PRIVILEGES* ptpOld)
{
	BOOL bResult = FALSE;
	DWORD cbOld = (0L);
	TOKEN_PRIVILEGES tp = { 0 };

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	bResult = ::LookupPrivilegeValue(0, pszPriv, &tp.Privileges[0].Luid);

	if (bResult)
	{
		cbOld = sizeof(*ptpOld);
		bResult = ::AdjustTokenPrivileges(hToken, FALSE, &tp, cbOld, ptpOld, &cbOld);
	}

	return (bResult && (ERROR_NOT_ALL_ASSIGNED != GetLastError()));
}

//-----------------------------------------------------------------------------
// Name: RestorePrivilege()
// Desc: 
//-----------------------------------------------------------------------------
BOOL CMiniDumper::RestorePrivilege(HANDLE hToken, TOKEN_PRIVILEGES* ptpOld)
{
	return (AdjustTokenPrivileges(hToken, FALSE, ptpOld, 0, NULL, NULL) && (ERROR_NOT_ALL_ASSIGNED != GetLastError()));
}

//-----------------------------------------------------------------------------
// Name: WriteMiniDump()
// Desc: 
//-----------------------------------------------------------------------------
LONG CMiniDumper::WriteMiniDump(_EXCEPTION_POINTERS *pExceptionInfo)
{
	LONG retval = EXCEPTION_CONTINUE_SEARCH;
	m_pExceptionInfo = pExceptionInfo;

	HANDLE hImpersonationToken = NULL;
	if (!GetImpersonationToken(&hImpersonationToken))
	{
		return FALSE;
	}
	// You have to find the right dbghelp.dll. 
	// Look next to the EXE first since the one in System32 might be old (Win2k)

	HMODULE hDll = NULL;
	_TCHAR szDbgHelpPath[MAX_PATH] = { 0 };

	if (GetModuleFileName(NULL, m_szAppPath, _MAX_PATH))
	{
		TCHAR *pSlash = _tcsrchr(m_szAppPath, '\\');

		if (pSlash)
		{
			_tcscpy_s(m_szAppBaseName, pSlash + 1);
			*(pSlash + 1) = 0;
		}

		_tcscpy_s(szDbgHelpPath, m_szAppPath);
		_tcscat_s(szDbgHelpPath, _T("DBGHELP.DLL"));
		hDll = ::LoadLibrary(szDbgHelpPath);
	}

	if (hDll == NULL)
	{
		// If we haven't found it yet - try one more time.
		hDll = ::LoadLibrary(_T("DBGHELP.DLL"));
	}

	LPCTSTR szResult = NULL;

	if (hDll)
	{
		// Get the address of the MiniDumpWriteDump function, which writes 
		// user-mode mini-dump information to a specified file.
		MINIDUMPWRITEDUMP MiniDumpWriteDump =
			(MINIDUMPWRITEDUMP)::GetProcAddress(hDll, "MiniDumpWriteDump");

		if (MiniDumpWriteDump != NULL)
		{
			_TCHAR szScratch[MAX_REASON_COMMENT_LEN] = { 0 };

			SetMiniDumpFileName();

			// Ask the user if he or she wants to save a mini-dump file...
			_tcssprintf(szScratch,
				_T("There was an unexpected error:\n\nWould you ")
				_T("like to create a mini-dump file?\n\n%s "),
				m_szMiniDumpPath);

			// Create the mini-dump file...
			HANDLE hFile = ::CreateFile(m_szMiniDumpPath,
				GENERIC_WRITE,
				FILE_SHARE_WRITE,
				NULL,
				CREATE_ALWAYS,
				FILE_ATTRIBUTE_NORMAL,
				NULL);

			if (hFile != INVALID_HANDLE_VALUE)
			{
				_MINIDUMP_EXCEPTION_INFORMATION ExInfo = { 0 };
				ExInfo.ThreadId = ::GetCurrentThreadId();
				ExInfo.ExceptionPointers = pExceptionInfo;
				ExInfo.ClientPointers = NULL;

				// We need the SeDebugPrivilege to be able to run MiniDumpWriteDump
				TOKEN_PRIVILEGES tp = { 0 };
				BOOL bPrivilegeEnabled = EnablePrivilege(SE_DEBUG_NAME, hImpersonationToken, &tp);

				BOOL bOk = FALSE;

				// DBGHELP.dll is not thread-safe, so we need to restrict access...
				EnterCriticalSection(G_pCriticalSection);
				{
					// Write out the mini-dump data to the file...
					bOk = MiniDumpWriteDump(GetCurrentProcess(),
						GetCurrentProcessId(),
						hFile,
						MiniDumpNormal,
						&ExInfo,
						NULL,
						NULL);
				}
				LeaveCriticalSection(G_pCriticalSection);

				// Restore the privileges when done
				if (bPrivilegeEnabled)
				{
					RestorePrivilege(hImpersonationToken, &tp);
				}
				if (bOk)
				{
					szResult = NULL;
					retval = EXCEPTION_EXECUTE_HANDLER;
				}
				else
				{
					_tcssprintf(szScratch,
						_T("Failed to save the mini-dump file to '%s' (error %d)"),
						m_szMiniDumpPath,
						GetLastError());

					szResult = szScratch;
				}

				::CloseHandle(hFile);
			}
			else
			{
				_tcssprintf(szScratch,
					_T("Failed to create the mini-dump file '%s' (error %d)"),
					m_szMiniDumpPath,
					GetLastError());

				szResult = szScratch;
			}
		}
		else
		{
			szResult = _T("Call to GetProcAddress failed to find MiniDumpWriteDump. ")
				_T("The DBGHELP.DLL is possibly outdated.");
		}
	}
	else
	{
		szResult = _T("Call to LoadLibrary failed to find DBGHELP.DLL.");
	}

	if (szResult && m_bPromptUserForMiniDump)
	{
		::MessageBox(NULL, szResult, NULL, MB_OK);
	}

	::TerminateProcess(GetCurrentProcess(), 0);

	return retval;
}

