// ad_password_pwncheck.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include "ad_password_pwncheck.h"


// This is an example of an exported variable
AD_PASSWORD_PWNCHECK_API int nad_password_pwncheck=0;

// This is an example of an exported function.
AD_PASSWORD_PWNCHECK_API int fnad_password_pwncheck(void)
{
    return 42;
}

// This is the constructor of a class that has been exported.
// see ad_password_pwncheck.h for the class definition
Cad_password_pwncheck::Cad_password_pwncheck()
{
    return;
}
