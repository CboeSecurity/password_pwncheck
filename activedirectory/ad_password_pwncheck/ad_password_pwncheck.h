// The following ifdef block is the standard way of creating macros which make exporting 
// from a DLL simpler. All files within this DLL are compiled with the AD_PASSWORD_PWNCHECK_EXPORTS
// symbol defined on the command line. This symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see 
// AD_PASSWORD_PWNCHECK_API functions as being imported from a DLL, whereas this DLL sees symbols
// defined with this macro as being exported.
#ifdef AD_PASSWORD_PWNCHECK_EXPORTS
#define AD_PASSWORD_PWNCHECK_API __declspec(dllexport)
#else
#define AD_PASSWORD_PWNCHECK_API __declspec(dllimport)
#endif

// This class is exported from the ad_password_pwncheck.dll
class AD_PASSWORD_PWNCHECK_API Cad_password_pwncheck {
public:
	Cad_password_pwncheck(void);
	// TODO: add your methods here.
};

extern AD_PASSWORD_PWNCHECK_API int nad_password_pwncheck;

AD_PASSWORD_PWNCHECK_API int fnad_password_pwncheck(void);
