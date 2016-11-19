

#ifndef ISC_INCLUDE_COMMON_H
#include "..\Common\common.h"
#endif


#define LOGTARGETFILE 1
#define LOGTARGETCONSOLE 2
//#define LOGTARGETEVENTLOG 4 //Not used yet

wchar_t * LogFileName = LOGFILENAME;
int LogLevel = LOGLEVELDEFAULT;
int LogSourceLocation = 1;
int LogTargets = LOGTARGETFILE | LOGTARGETCONSOLE;

extern int setLogFileName(wchar_t* fn) {
	LogFileName = _wcsdup(fn);
	return 0;
}

int setLogTargets(int targets) {
	LogTargets = targets;
	return 0;
}

int setLogLevel(int logLevel) {
	LogLevel = logLevel;
	return 0;
}

int setLogSourceLocation(int flag) {
	LogSourceLocation = flag;
	return 0;
}

void logMessageToFile(wchar_t* msg) {
	FILE *fd = NULL;
	if (! (LogTargets & LOGTARGETFILE)) return;
	if ((fd = _wfopen(LogFileName, L"a,ccs=UTF-8")) == NULL) {
		wprintf(L"Error opening logfile: %s", LogFileName);
	}
	else {
		fwprintf(fd, L"%s\n", msg);
	}
	fflush(fd);
	fclose(fd);
}

void logMessageToConsole(wchar_t* msg) {
	if (LogTargets & LOGTARGETCONSOLE) wprintf (L"%s\n", msg);
}

void logMessage(wchar_t* msg, int level, char* FFUNCTION, char* FFILE, int FLINE) {
	wchar_t dtBuf[1024];
	struct tm lNow;
	time_t lTime;
	
	if (level > LogLevel) return;
	
	time(&lTime);
	localtime_s(&lNow, &lTime);
	wcsftime(dtBuf, sizeof(dtBuf), L"%Y-%m-%d %H:%M:%S", &lNow);

	if (LogSourceLocation > 0) {
		swprintf(dtBuf, sizeof(dtBuf), L"%s: File=%S, Function=%S, Line=%d: %s", dtBuf, FFILE, FFUNCTION, FLINE, msg);
	}
	else {
		swprintf(dtBuf, sizeof(dtBuf), L"%s: %s",  dtBuf, msg);
	}
	logMessageToFile(dtBuf);
	logMessageToConsole(dtBuf);

	//return _strdup(dtBuf);
}

void logMessageFormat(wchar_t* tFormat, int level, char* FFUNCTION, char* FFILE, int FLINE, ...) {
	wchar_t dtBuf[1024];
	struct tm lNow;
	time_t lTime;
	va_list argptr;

	if (level > LogLevel) return;

	time(&lTime);
	localtime_s(&lNow, &lTime);
	wcsftime(dtBuf, sizeof(dtBuf), L"%Y-%m-%d %H:%M:%S", &lNow);

	if (LogSourceLocation > 0) {
		swprintf(dtBuf, sizeof(dtBuf), L"%s: File=%S, Function=%S, Line=%d: ", dtBuf, FFILE, FFUNCTION, FLINE);
	}
	else {
		swprintf(dtBuf, sizeof(dtBuf), L"%s: ",  dtBuf);
	}

	va_start(argptr, FLINE);
	vswprintf_s(dtBuf + wcslen(dtBuf), sizeof(dtBuf) / sizeof(DWORD), tFormat, argptr);
	va_end(argptr);

	logMessageToFile(dtBuf);
	logMessageToConsole(dtBuf);

}

void consoleMessage(wchar_t * msg) {
	wprintf (L"%s\n", msg);
}

wchar_t* getLastErrorCode() {
	wchar_t buf[128] = L"0x";
	_itow(GetLastError(), buf + wcslen(buf), 16);
	return _wcsdup(buf);
}

wchar_t* getLastErrorMsg() {
	wchar_t buf[1024];
	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, GetLastError(), 0, buf, 1024, NULL);
	swprintf(buf, sizeof(buf), L"%s", buf);
	return _wcsdup(buf);
}

void logLastError() {
	wchar_t buf[1024];

	swprintf(buf, sizeof(buf), L"LastError Code=%s, Msg=%s", getLastErrorCode(), getLastErrorMsg());
	LogMessage(buf);
}
