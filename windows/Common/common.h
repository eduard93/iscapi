
#define ISC_INCLUDE_COMMON_H 1

#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <conio.h>
#include <wchar.h>
#include <time.h>
#include <Windows.h>
#include <WinCrypt.h>

#include "callin.h"
#include "cdzf.h"

// Logging functions (logger.c)

#define LOGLEVELNONE	0
#define LOGLEVELERR		1
#define LOGLEVELALL		2

#define LOGLEVELDEFAULT LOGLEVELALL
#define LOGFILENAME L"C:\\iscapi.log"

void logMessage(wchar_t* msg, int level, char* FFUNCTION, char* FFILE, int FLINE);
void logMessageFormat(wchar_t* tFormat, int level, char* FFUNCTION, char* FFILE, int FLINE, ...);

#define LogMessage(msg) logMessage(msg, LOGLEVELDEFAULT, __FUNCTION__, __FILE__, __LINE__)
#define LogMessageFormat(fmt, ...) logMessageFormat(fmt, LOGLEVELDEFAULT, __FUNCTION__, __FILE__, __LINE__, __VA_ARGS__)
#define LogError(msg) logLastError(); logMessage(msg, LOGLEVELERR, __FUNCTION__, __FILE__, __LINE__)

extern int setLogFileName(wchar_t* fn);
extern int setLogTargets(int targets);
extern int setLogLevel(int logLevel);
extern int setLogSourceLocation(int flag);
void consoleMessage(wchar_t * msg);
wchar_t* getLastErrorCode();
wchar_t* getLastErrorMsg();
void logLastError();


// Utils
wchar_t* ByteToStrW(void* pv);
void ByteToStr(DWORD cb, void* pv, LPSTR sz);
void ByteToZARRAY(int len, unsigned char *buf, ZARRAYP bytestr);
void ReverseByteToZARRAY(int len, unsigned char *buf, ZARRAYP bytestr);
// Crypto

//HCRYPTPROV fullAC(DWORD provType);
//void simpleRC(HCRYPTPROV hCryptProv);



