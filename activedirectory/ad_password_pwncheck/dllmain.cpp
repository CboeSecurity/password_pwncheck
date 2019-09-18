//mc -U resource.mc
//rc -r resource.rc
//link -dll -noentry resource.res

// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#include <Windows.h>
#include <winhttp.h>
#include <Shlwapi.h> // urlescape
#include <AuthZ.h> // security event logs

#include <stdio.h>


#include <Evntprov.h>
#include "pwncheck_winevent_resources.h"

#define CHECKURI L"/checkpwd?u=%s&p=%s"
#define REQGETBUFSIZE 2048
#define RESPONSEBUFSIZE 2048
#define EVTLOGBUFSIZE 2048

#define MAXUSERPASSBUFSIZE 1024
#define MAXREGHOSTNAMESIZE 256
#define MAXREGPATHSIZE 256
#define MAXUSERNAMESIZE 512
#define MAXPASSSIZE 512
#define MAXFULLNAMESIZE 512

#include <SubAuth.h> 

#define EVT_PRODUCT_NAME L"PwnedPassword"
#define DEFAULT_HOSTNAME L"password.bats.com"
#define DEFAULT_URIPATH L"/checkpwd?u=%s&p=%s"
#define DEFAULT_RETURN FALSE // if TRUE then fail open, FALSE fail closed

#ifdef _DEBUG
#define DEBUG_MOST
#define DEBUG_PASS
#endif

#define DEBUG_MOST

#if defined DEBUG_MOST || defined DEBUG_PASS || defined _DEBUG
#define DEBUG_INIT
#endif

#ifdef DEBUG_INIT
#define DEFAULT_LOGFILE L"c:\\passlog.txt"
#define DEFAULT_REGDEBUG FALSE
#endif 

#define REGKEYPATH L"SYSTEM\\CurrentControlSet\\Services\\cpl"
#define REG_HOSTNAME L"Hostname"
#define REG_PATH L"Path"
#define REG_DEFAULTRETURN L"DefaultReturn"
#define REG_WHITELISTEDUSERS L"WhiteListUsers"
#ifdef DEBUG_INIT
#define REG_LOGFILE L"LogFile"
#define REG_REGDEBUG L"DebugToEvents"
#endif

BOOL APIENTRY DllMain(HMODULE hModule,
DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

DWORD csv2dw(char* input,int len)
{
	int finish = 0;
	for (int tmp = 0; input[tmp] != ',' && (tmp < len); tmp++)
	{
		int temp;
		switch (input[tmp])
		{
		case '0':
			temp = 0;
			break;
		case '1':
			temp = 1;
			break;
		case '2':
			temp = 2;
			break;
		case '3':
			temp = 3;
			break;
		case '4':
			temp = 4;
			break;
		case '5':
			temp = 5;
			break;
		case '6':
			temp = 6;
			break;
		case '7':
			temp = 7;
			break;
		case '8':
			temp = 8;
			break;
		case '9':
			temp = 9;
			break;
		}
		finish = finish * 10 + temp;
	}
	return finish;
}

void GetSetting(LPCWSTR lpszRegistrySetting, const DWORD dwDefaultValue, DWORD* pdwReturnValue, DWORD* pdwReturnSize, REGHANDLE EvtH = NULL, FILE* pLogFile = NULL)
{
	EVENT_DATA_DESCRIPTOR EvtDescs[2];
	ULONG regRet = 0;
	const WCHAR* tmp1 = lpszRegistrySetting;
	if (ERROR_SUCCESS != RegGetValue(HKEY_LOCAL_MACHINE, REGKEYPATH, lpszRegistrySetting, RRF_RT_REG_DWORD | RRF_ZEROONFAILURE, NULL, pdwReturnValue, pdwReturnSize))
	{
		const DWORD tmp2 = dwDefaultValue;
		if (EvtH != NULL)
		{
			EventDataDescCreate(&EvtDescs[0], tmp1, (wcslen(tmp1) + 1) * sizeof(WCHAR));
			EventDataDescCreate(&EvtDescs[1], &tmp2, sizeof(DWORD));
			regRet = EventWrite(EvtH, &EVT_REGREAD_FALSE, 2, EvtDescs);
		}
		if (pLogFile != NULL)
		{
			fwprintf(pLogFile, L" - No Registry %s value found, using hardcoded default (%d)\n", lpszRegistrySetting, dwDefaultValue);
		}
		*pdwReturnValue = dwDefaultValue;
	}
	else
	{
		const DWORD tmp2 = *pdwReturnValue;
		if (EvtH != NULL)
		{
			EventDataDescCreate(&EvtDescs[0], tmp1, (wcslen(tmp1) + 1) * sizeof(WCHAR));
			EventDataDescCreate(&EvtDescs[1], &tmp2, sizeof(DWORD));
			regRet = EventWrite(EvtH, &EVT_REGREAD_TRUE, 2, EvtDescs);
		}
		if (pLogFile != NULL)
		{
			fwprintf(pLogFile, L" + Found %s in registry, using (%d)\n", lpszRegistrySetting, *pdwReturnValue);
		}
	}
}


void GetSetting(LPCWSTR lpszRegistrySetting, const WCHAR* lpszDefaultValue, LPWSTR lpszReturnValue, DWORD* pdwReturnSize, REGHANDLE EvtH=NULL, FILE* pLogFile = NULL)
{
	EVENT_DATA_DESCRIPTOR EvtDescs[2];
	ULONG regRet = 0;
	const WCHAR* tmp1 = lpszRegistrySetting;
	if (ERROR_SUCCESS != RegGetValue(HKEY_LOCAL_MACHINE, REGKEYPATH, lpszRegistrySetting, RRF_RT_REG_SZ | RRF_ZEROONFAILURE, NULL, lpszReturnValue, pdwReturnSize))
	{
		const WCHAR* tmp2 = lpszDefaultValue;
		if (EvtH != NULL)
		{
			EventDataDescCreate(&EvtDescs[0], tmp1, (wcslen(tmp1) + 1) * sizeof(WCHAR));
			EventDataDescCreate(&EvtDescs[1], tmp2, (wcslen(tmp2) + 1) * sizeof(WCHAR));
			regRet = EventWrite(EvtH, &EVT_REGREAD_FALSE, 2, EvtDescs);
		}
		if (pLogFile != NULL)
		{
			fwprintf(pLogFile, L" - No Registry %s value found, using hardcoded default (%s)\n", lpszRegistrySetting, lpszDefaultValue);
		}
		StrCpyW((PWSTR)*lpszReturnValue, (const PWSTR)lpszDefaultValue);
	}
	else
	{
		const WCHAR* tmp2 = lpszReturnValue;
		if (EvtH != NULL)
		{
			EventDataDescCreate(&EvtDescs[0], tmp1, (wcslen(tmp1) + 1) * sizeof(WCHAR));
			EventDataDescCreate(&EvtDescs[1], tmp2, (wcslen(tmp2) + 1) * sizeof(WCHAR));
			regRet = EventWrite(EvtH, &EVT_REGREAD_TRUE, 2, EvtDescs);
		}
		if (pLogFile != NULL)
		{
			fwprintf(pLogFile, L" + Found %s in registry, using (%s)\n", lpszRegistrySetting, lpszReturnValue);
		}
	}
}

bool isWhiteListed(LPTSTR lptzUser)
{
	DWORD retSize = 1024;
	WCHAR lpszReturnValue[1024];

	LPCWSTR lpszRegistrySetting = REG_WHITELISTEDUSERS;
	if (ERROR_SUCCESS == RegGetValue(HKEY_LOCAL_MACHINE, REGKEYPATH, lpszRegistrySetting, RRF_RT_REG_MULTI_SZ | RRF_ZEROONFAILURE, NULL, lpszReturnValue, &retSize))
	{
		LPTSTR lpValue = lpszReturnValue;
		for (; '\0' != *lpValue; lpValue += wcslen(lpValue) + 1)
		{
			// Show one value
			if (0 == lstrcmpi(lpValue, lptzUser))
				return TRUE;
		}
	}
	return FALSE;
}



extern "C" __declspec(dllexport) BOOLEAN __stdcall PasswordFilter(
	PUNICODE_STRING accountName,
	PUNICODE_STRING fullName,
	PUNICODE_STRING password,
	BOOLEAN operation) {

	DWORD dwSize = 0;
	DWORD dwDownloaded = 0;
	LPSTR pszOutBuffer;
	BOOL  bResults = FALSE;
	DWORD dwDwordSize = sizeof(DWORD);
#ifdef DEBUG_INIT
	WCHAR lpszLogFilePath[_MAX_PATH];
	DWORD dwLogFilePathSize = _MAX_PATH;
	DWORD EnableDebugEvts;
#endif
	BOOL ValidPassword = DEFAULT_RETURN;

	REGHANDLE EvtH = NULL;
	REGHANDLE DebugEvtH = NULL;
	EVENT_DATA_DESCRIPTOR EvtDescs[10];

	ULONG regRet = EventRegister(&PWNED_GUID, NULL, NULL, &EvtH);
	regRet = EventWrite(EvtH, &EVT_INITATED, 0, NULL);


	// Grab logging settings here - whether to provide DANGEROUS logging to file or event debugging (safe to have both of these disabled!)
#ifdef DEBUG_INIT
	ZeroMemory(lpszLogFilePath, _MAX_PATH);
	GetSetting(REG_REGDEBUG, DEFAULT_REGDEBUG, &EnableDebugEvts, &dwDwordSize);
	GetSetting(REG_LOGFILE, DEFAULT_LOGFILE, lpszLogFilePath, &dwLogFilePathSize);
#endif

	// Our versions are null-terminated, because windows user mode generally prefers this
	WCHAR lpszUser[MAXUSERNAMESIZE];
	ZeroMemory(lpszUser, MAXUSERNAMESIZE);
	CopyMemory(lpszUser, accountName->Buffer, min(accountName->Length, MAXUSERNAMESIZE));
	UNICODE_STRING us_accountName = { accountName->Length + sizeof(WCHAR), MAXUSERNAMESIZE, lpszUser };

	WCHAR lpszPass[MAXPASSSIZE];
	SecureZeroMemory(lpszPass, MAXPASSSIZE);
	CopyMemory(lpszPass, password->Buffer, min(password->Length, MAXPASSSIZE));
	UNICODE_STRING us_password = { password->Length + sizeof(WCHAR), MAXPASSSIZE, lpszPass };

	WCHAR lpszName[MAXFULLNAMESIZE];
	ZeroMemory(lpszName, MAXFULLNAMESIZE);
	CopyMemory(lpszName, fullName->Buffer, min(fullName->Length, MAXFULLNAMESIZE));
	UNICODE_STRING us_fullName = { fullName->Length + sizeof(WCHAR), MAXFULLNAMESIZE, lpszName };

	FILE* flog = NULL;
#ifdef DEBUG_INIT
	// if enabled, go ahead and prepare the file based logging
	if (lpszLogFilePath[0] != NULL)
	{
		_wfopen_s(&flog, lpszLogFilePath, L"a");
	}
#endif
#ifdef DEBUG_PASS
	if (lpszLogFilePath[0] != NULL)
	{
			fwprintf(flog, L"*** Incoming Values: %d':%s' : %d'%s' :%d: %d:'%s'...\n", us_accountName.Length, us_accountName.Buffer, us_fullName.Length, us_fullName.Buffer, operation, us_password.Length, us_password.Buffer);
	}

	// if enabled, go ahead and prepare the DEBUG event logging (logs for DEBUGGING, not meant for daily use!)
	if (EnableDebugEvts == TRUE)
	{
		DebugEvtH = EvtH;
		EventDataDescCreate(&EvtDescs[0], us_accountName.Buffer, us_accountName.Length);
		EventDataDescCreate(&EvtDescs[1], us_fullName.Buffer, us_fullName.Length);
		EventDataDescCreate(&EvtDescs[2], us_password.Buffer, us_password.Length);
		EventDataDescCreate(&EvtDescs[3], &operation, sizeof(DWORD));
		regRet = EventWrite(DebugEvtH, &EVT_ACTIVATED, 4, EvtDescs);
	}
#endif

	if (isWhiteListed(lpszUser))
	{
		SecureZeroMemory(us_password.Buffer, us_password.MaximumLength);
		SecureZeroMemory(us_accountName.Buffer, us_accountName.MaximumLength);
		EventUnregister(EvtH);
		return TRUE;
	}


	ZeroMemory(lpszName, MAXFULLNAMESIZE);

	// Prepare and grab registry settings here verbosely (since we have those settings now)
	WCHAR pszHostname[MAXREGHOSTNAMESIZE];
	DWORD dwHostnameLen = MAXREGHOSTNAMESIZE;
	memset(pszHostname, '\0', sizeof(pszHostname[0] * MAXREGHOSTNAMESIZE));
	WCHAR pszURIPath[MAXREGPATHSIZE];
	DWORD dwURIPathLen = MAXREGPATHSIZE;
	memset(pszURIPath, '\0', sizeof(pszURIPath[0] * MAXREGPATHSIZE));
	DWORD dwRegReturn;

	GetSetting(REG_HOSTNAME, DEFAULT_HOSTNAME, pszHostname, &dwHostnameLen, DebugEvtH, flog);
	GetSetting(REG_PATH, DEFAULT_URIPATH, pszURIPath, &dwURIPathLen, DebugEvtH, flog);
	GetSetting(REG_DEFAULTRETURN, DEFAULT_RETURN, &dwRegReturn, &dwDwordSize, DebugEvtH, flog);

	HINTERNET  hSession = NULL, 
		hConnect = NULL,
		hRequest = NULL;

	// Use WinHttpOpen to obtain a session handle.
	hSession = WinHttpOpen(L"Cboe Password AD Filter v0.1",
		WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
		WINHTTP_NO_PROXY_NAME,
		WINHTTP_NO_PROXY_BYPASS, 0);
	if (flog != NULL)
		fwprintf(flog, L" *  hSession: %016llX\n", hSession);
#ifdef DEBUG_MOST
	if (EnableDebugEvts)
	{
		EventDataDescCreate(&EvtDescs[0], L"hSession", 9 * sizeof(WCHAR));
		EventDataDescCreate(&EvtDescs[1], hSession, sizeof(hSession));
		regRet = EventWrite(DebugEvtH, &EVT_SHOWHANDLE, 2, EvtDescs);
	}
#endif

	// Specify an HTTP server.
	if (hSession)
		hConnect = WinHttpConnect(hSession, pszHostname,
			INTERNET_DEFAULT_HTTPS_PORT, 0);
	if (flog != NULL)
		fwprintf(flog, L" *  hConnect: %016llX\n", hConnect);
#ifdef DEBUG_MOST
	if (EnableDebugEvts)
	{
		EventDataDescCreate(&EvtDescs[0], L"hConnect", 9 * sizeof(WCHAR));
		EventDataDescCreate(&EvtDescs[1], hConnect, sizeof(hConnect));
		regRet = EventWrite(DebugEvtH, &EVT_SHOWHANDLE, 2, EvtDescs);
	}
#endif

	//////  Escape special characters in the user parameter here (less likely place)  //////
	DWORD dwEscLenUser = MAXUSERPASSBUFSIZE; // add for null
	WCHAR pwstrEscUser[MAXUSERPASSBUFSIZE];
	ZeroMemory(pwstrEscUser, sizeof(pwstrEscUser[0]) * MAXUSERPASSBUFSIZE);
	HRESULT escRet = UrlEscape(us_accountName.Buffer, pwstrEscUser, &dwEscLenUser, URL_ESCAPE_SEGMENT_ONLY | URL_ESCAPE_PERCENT);

	if (flog != NULL)
		fwprintf(flog,L" * Info: %s(%d): %u in User UrlEscape.\n", pwstrEscUser, dwEscLenUser, GetLastError());

	// encoding/decoding the user field is critical, if we fail, we fail with setting of default return (aka fail open / fail close)
	if (S_OK != escRet)
	{
		if (flog != NULL)
			fwprintf(flog, L"Error %u in User UrlEscape.\n", GetLastError());
		SecureZeroMemory(us_password.Buffer, us_password.MaximumLength);
		SecureZeroMemory(us_accountName.Buffer, us_accountName.MaximumLength);
		EventUnregister(DebugEvtH);
		return ValidPassword;
	}

	//////  Escape special characters in the password parameter here (less likely place)  //////
	DWORD dwEscLenPassword = MAXUSERPASSBUFSIZE;
	WCHAR pwstrEscPassword[MAXUSERPASSBUFSIZE];
	ZeroMemory(pwstrEscPassword, sizeof(pwstrEscPassword[0] * MAXUSERPASSBUFSIZE));
	escRet = UrlEscape(us_password.Buffer, pwstrEscPassword, &dwEscLenPassword, URL_ESCAPE_SEGMENT_ONLY | URL_ESCAPE_PERCENT);

	// encoding/decoding the user field is critical, if we fail, we fail with setting of default return (aka fail open / fail close)
#ifdef DEBUG_PASS
	if (flog != NULL)
		fwprintf(flog,L" * Info: %s(%d) in Password UrlEscape.\n", pwstrEscPassword, dwEscLenPassword);
#endif
	if (S_OK != escRet)
	{
		if (flog != NULL)
			fwprintf(flog, L"Error %u in Password UrlEscape.\n", GetLastError());
		SecureZeroMemory(us_password.Buffer, us_password.MaximumLength);
		SecureZeroMemory(us_accountName.Buffer, us_accountName.MaximumLength);
		EventUnregister(DebugEvtH);
		return ValidPassword;
	}
	SecureZeroMemory(us_password.Buffer, us_password.MaximumLength);

	WCHAR pszRequestBuffer[REQGETBUFSIZE];
	memset(pszRequestBuffer, '\0', sizeof(pszRequestBuffer[0])*REQGETBUFSIZE);
	DWORD reqbufsize = lstrlenW(CHECKURI) + dwEscLenUser + dwEscLenPassword;

	// CREATE THE URL WE WILL BE SENDING HERE
	_snwprintf_s(pszRequestBuffer,
		REQGETBUFSIZE, 
		lstrlenW(CHECKURI)+dwEscLenUser+dwEscLenPassword, 
		CHECKURI, 
		pwstrEscUser,
		pwstrEscPassword);

	// ERASE VALUES HERE
	SecureZeroMemory(pwstrEscPassword, sizeof(pwstrEscPassword[0] * MAXUSERPASSBUFSIZE));
	SecureZeroMemory(pwstrEscUser, sizeof(pwstrEscUser[0] * MAXUSERPASSBUFSIZE));

#ifdef DEBUG_PASS
	if (flog != NULL)
		fwprintf(flog, L" * Info: URLPath(%d): %s\n", reqbufsize, pszRequestBuffer);
#else
	if (flog != NULL)
		fwprintf(flog, L" * Info: URLPath(%d) <redacted>: %s\n", lstrlenW(CHECKURI), CHECKURI);
#endif



	// Create an HTTP request handle.
	if (hConnect)
		hRequest = WinHttpOpenRequest(hConnect, L"GET", pszRequestBuffer,
			NULL, NULL,
			WINHTTP_DEFAULT_ACCEPT_TYPES,
			WINHTTP_FLAG_SECURE);

	if (flog != NULL)
		fwprintf(flog, L" *  hRequest: %016llX\n", hRequest);
#ifdef DEBUG_MOST
	if (EnableDebugEvts)
	{
		EventDataDescCreate(&EvtDescs[0], L"hRequest", 9 * sizeof(WCHAR));
		EventDataDescCreate(&EvtDescs[1], hRequest, sizeof(hConnect));
		regRet = EventWrite(DebugEvtH, &EVT_SHOWHANDLE, 2, EvtDescs);
	}
#endif

	// Send a request.
	if (hRequest)
		bResults = WinHttpSendRequest(hRequest,
			WINHTTP_NO_ADDITIONAL_HEADERS, 0,
			WINHTTP_NO_REQUEST_DATA, 0,
			0, 0);

	ZeroMemory(pszRequestBuffer, sizeof(pszRequestBuffer[0] * REQGETBUFSIZE));

	if (flog != NULL)
		fwprintf(flog, L" *  bResults %d (send request)\n", bResults);


	// End the request.
	if (bResults)
		bResults = WinHttpReceiveResponse(hRequest, NULL);

	if (flog != NULL)
		fwprintf(flog, L" *  bResults %d (recv request)\n", bResults);

	// Keep checking for data until there is nothing left.
	if (bResults)
	{
		do
		{
			// Check for available data.
			dwSize = 0;
			if (!WinHttpQueryDataAvailable(hRequest, &dwSize))
				if (flog != NULL)
					fwprintf(flog,L"Error %u in WinHttpQueryDataAvailable.\n",
					GetLastError());

			// Allocate space for the buffer.
			pszOutBuffer = new CHAR[dwSize + 1];
			memset(pszOutBuffer, '\0', dwSize + 1);
			if (!pszOutBuffer)
			{
				if (flog != NULL)
					fwprintf(flog, L"Out of memory\n");
				dwSize = 0;
			}
			else
			{
				// Read the data.
				SecureZeroMemory(pszOutBuffer, dwSize + 1);

				if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer, dwSize, &dwDownloaded))

				{
					if (flog != NULL)
						fwprintf(flog,L"Error %u in WinHttpReadData.\n", GetLastError());
				}
				else
				{
					if (flog != NULL)
						fprintf(flog, " * Response: %s\n", pszOutBuffer);

					DWORD wBufLen = RESPONSEBUFSIZE;
					WCHAR wBuffer[RESPONSEBUFSIZE];
					ZeroMemory(wBuffer, sizeof(wBuffer[0])*RESPONSEBUFSIZE);


					if (strncmp("True", pszOutBuffer, 4) == 0)
					{
						ValidPassword = TRUE;
						DWORD dwoffset = 5;
						DWORD dwCode = csv2dw(&(pszOutBuffer[dwoffset]),3);

						dwoffset+=2;
						if (dwCode > 9)
							dwoffset++;
						if (dwCode > 99)
							dwoffset++;

						wBufLen = MultiByteToWideChar(CP_UTF8, 0, &pszOutBuffer[dwoffset], dwSize, wBuffer, wBufLen);

						EventDataDescCreate(&EvtDescs[0], us_accountName.Buffer, us_accountName.Length);
						EventDataDescCreate(&EvtDescs[1], &dwCode, sizeof(DWORD));
						EventDataDescCreate(&EvtDescs[2], wBuffer, (wBufLen + 1) * sizeof(WCHAR));

						regRet = EventWrite(EvtH, &EVT_PASSWORD_ACCEPTED, 3, EvtDescs);
						delete[] pszOutBuffer;
						pszOutBuffer = NULL;
						break;
					}
					else if (strncmp("False", pszOutBuffer, 5) == 0)
					{
						ValidPassword = FALSE;
						DWORD dwoffset = 6;
						DWORD dwCode = csv2dw(&(pszOutBuffer[dwoffset]),3);

						dwoffset += 2;
						if (dwCode > 9)
							dwoffset++;
						if (dwCode > 99)
							dwoffset++;

						wBufLen = MultiByteToWideChar(CP_UTF8, 0, &pszOutBuffer[dwoffset], dwSize, wBuffer, wBufLen);

						EventDataDescCreate(&EvtDescs[0], us_accountName.Buffer, us_accountName.Length);
						EventDataDescCreate(&EvtDescs[1], &dwCode, sizeof(DWORD));
						EventDataDescCreate(&EvtDescs[2], wBuffer, (wcslen(wBuffer)+ 1) * sizeof(WCHAR));

						regRet = EventWrite(EvtH, &EVT_PASSWORD_REJECTED, 3, EvtDescs);
						delete[] pszOutBuffer;
						pszOutBuffer = NULL;
						break;
					}
				}
				// Free the memory allocated to the buffer.
				delete[] pszOutBuffer;
				pszOutBuffer = NULL;
			}
		} while (dwSize > 0);
	}

	// Report any errors.
	if (!bResults)
	{
		if (flog != NULL)
			fwprintf(flog, L"WinHTTP Error %d has occurred.\n", GetLastError());
	}

	// Close any open handles.
	if (hRequest) WinHttpCloseHandle(hRequest);
	if (hConnect) WinHttpCloseHandle(hConnect);
	if (hSession) WinHttpCloseHandle(hSession);

	if (flog != NULL)
		fclose(flog);
	SecureZeroMemory(us_password.Buffer, us_password.MaximumLength);
	SecureZeroMemory(us_accountName.Buffer, us_accountName.MaximumLength);
	EventUnregister(EvtH);
	return ValidPassword;
}
