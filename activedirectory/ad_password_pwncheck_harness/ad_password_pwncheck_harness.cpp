#include "stdafx.h"

#include <Windows.h>

#include <SubAuth.h>

#define DEFDLLNAME _T("ad_password_pwncheck.dll")

#define DECLARE_CONST_UNICODE_STRING(_var, _string) \
const WCHAR _var ## _buffer[] = _string; \
const UNICODE_STRING _var = { sizeof(_string) - sizeof(WCHAR), sizeof(_string), (PWCH) _var ## _buffer } 

#define DECLARE_UNICODE_STRING_SIZE(_var, _size) \
WCHAR _var ## _buffer[_size]; \
UNICODE_STRING _var = { 0, _size * sizeof(WCHAR) , _var ## _buffer }

typedef BOOLEAN(*PasswordFilterPtr) (PUNICODE_STRING, PUNICODE_STRING, PUNICODE_STRING, BOOLEAN);
PasswordFilterPtr PasswordFilter = NULL;

int wmain(int argc, _TCHAR* argv[]) {
	UNICODE_STRING user;
	UNICODE_STRING password;

	if (argc != 3)
	{
		return 0;
	}

	wchar_t* pwszUser = argv[1];
	wchar_t* pwszPassword = argv[2];

	user.Buffer = pwszUser;
	user.Length = lstrlenW(pwszUser) * sizeof(TCHAR);
	user.MaximumLength = user.Length * sizeof(TCHAR);
	password.Buffer = pwszPassword;
	password.Length = lstrlenW(pwszPassword) * sizeof(TCHAR);
	password.MaximumLength = password.Length * sizeof(TCHAR);


	HMODULE CboePasswordDll = LoadLibrary(DEFDLLNAME);

	if (CboePasswordDll)
	{
		PasswordFilter = (PasswordFilterPtr)GetProcAddress(CboePasswordDll, "PasswordFilter");
	}

	if (PasswordFilter == NULL)
	{
		printf("Could not locate the PasswordFilter function in '%s'", DEFDLLNAME);
		return -1;
	}
	WCHAR nullstr[30];
	ZeroMemory(nullstr, 30);
	CopyMemory(nullstr, L"<NULL>", 12);
	UNICODE_STRING null = { 12,12,nullstr };
	printf("%S::%S: Returned ", user.Buffer, password.Buffer);
	BOOLEAN retval = PasswordFilter(&user, &null, &password, TRUE);

	_TCHAR* msg = L"False";
	if (retval != FALSE)
		msg = L"True";

	printf("%S\n", msg);
	return 0;
}

