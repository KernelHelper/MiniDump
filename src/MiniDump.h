#ifndef __MINIDUMP_H_
#define __MINIDUMP_H_

#include <windows.h>
#include <time.h>

class CMiniDumper
{
public:

    CMiniDumper(bool bPromptUserForMiniDump = false);
    ~CMiniDumper(void);

private:

    static LONG WINAPI UnhandledExceptionHandler(struct _EXCEPTION_POINTERS *pExceptionInfo);
	void SetMiniDumpFileName(time_t tt = time(0));
    bool GetImpersonationToken(HANDLE* phToken);
    BOOL EnablePrivilege(LPCTSTR pszPriv, HANDLE hToken, TOKEN_PRIVILEGES* ptpOld);
    BOOL RestorePrivilege(HANDLE hToken, TOKEN_PRIVILEGES* ptpOld);
    LONG WriteMiniDump(_EXCEPTION_POINTERS *pExceptionInfo );

    _EXCEPTION_POINTERS *m_pExceptionInfo;
    _TCHAR m_szMiniDumpPath[MAX_PATH];
    _TCHAR m_szAppPath[MAX_PATH];
    _TCHAR m_szAppBaseName[MAX_PATH];
    bool m_bPromptUserForMiniDump;

    static CMiniDumper* G_pMiniDumper;
    static LPCRITICAL_SECTION G_pCriticalSection;
};

#endif // __MINIDUMP_H_
