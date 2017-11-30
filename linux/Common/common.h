
#define ISC_INCLUDE_COMMON_H 1

#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
//#include <conio.h>
//#include <wchar.h>
#include <string.h>
#include <time.h>
//#include <Windows.h>
#include <WinCryptEx.h>
#include <stdarg.h>

#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <CSP_WinDef.h>
#include <CSP_WinCrypt.h>
#include "reader/tchar.h"

#include <errno.h>
#include <locale.h>


#include "callin.h"
#include "cdzf.h"

// Logging functions (logger.c)

#define LOGLEVELNONE	0
#define LOGLEVELERR		1
#define LOGLEVELALL		2

#define LOGLEVELDEFAULT LOGLEVELALL
#define LOGFILENAME "/tmp/iscapi.log"

void logMessage(const char* msg, int level, const char* FFUNCTION, const char* FFILE, const int FLINE);
void logMessageFormat(const char* tFormat, int level, const char* FFUNCTION, const char* FFILE, const int FLINE, ...);

#define LogMessage(msg) logMessage(msg, LOGLEVELDEFAULT, __FUNCTION__, __FILE__, __LINE__)
#define LogMessageFormat(fmt, ...) logMessageFormat(fmt, LOGLEVELDEFAULT, __FUNCTION__, __FILE__, __LINE__, ##__VA_ARGS__)
#define LogError(msg) logLastError(); logMessage(msg, LOGLEVELERR, __FUNCTION__, __FILE__, __LINE__)

extern int setLogFileName(char* fn);
extern int setLogTargets(int targets);
extern int setLogLevel(int logLevel);
extern int setLogSourceLocation(int flag);
void consoleMessage(char* msg);
char* getLastErrorCode();
char* getLastErrorMsg();
void logLastError();


// Utils
wchar_t* ByteToStrW(void* pv);
void ByteToStr(DWORD cb, void* pv, LPSTR sz);
void ByteToZARRAY(int len, unsigned char *buf, ZARRAYP bytestr);
void ReverseByteToZARRAY(int len, unsigned char *buf, ZARRAYP bytestr);

// Long Strings support
void ByteToEXSTR(int len, Callin_char_t *buf, CACHE_EXSTRP bytestr); 

void commonFree();

// Crypto

//HCRYPTPROV fullAC(DWORD provType);
//void simpleRC(HCRYPTPROV hCryptProv);

#define CMS_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)




