

#ifndef ISC_INCLUDE_COMMON_H
#include "common.h"
#endif


#define LOGTARGETFILE 1
#define LOGTARGETCONSOLE 2
//#define LOGTARGETEVENTLOG 4 //Not used yet

char *LogFileName = LOGFILENAME;
int LogLevel = LOGLEVELDEFAULT;
int LogSourceLocation = 1;
int LogTargets = LOGTARGETFILE | LOGTARGETCONSOLE;

extern int setLogFileName(char* fn) {
	LogFileName = strdup(fn);
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

void logMessageToFile(char* msg) {
	FILE *fd = NULL;
	if (! (LogTargets & LOGTARGETFILE)) return;
	if ((fd = fopen(LogFileName, "a")) == NULL) {
		printf("Error opening logfile: %s", LogFileName);
	}
	else {
		fprintf(fd, "%s\n", msg);
	}
	fflush(fd);
	fclose(fd);
}

void logMessageToConsole(char* msg) {
	if (LogTargets & LOGTARGETCONSOLE) printf ("%s\n", msg);
}

void logMessage(const char* msg, int level, const char* FFUNCTION, const char* FFILE, const int FLINE) {

	
	char dtBuf[4096];
	struct tm *lNow;
	time_t lTime;
	
	if (level > LogLevel) return;
	
	time(&lTime);
	lNow = localtime(&lTime);
	
	strftime(dtBuf, sizeof(dtBuf), "%Y-%m-%d %H:%M:%S", lNow);
	
	if (LogSourceLocation > 0) {
		sprintf(dtBuf, "%s: File=%s, Function=%s, Line=%d: %s", dtBuf, FFILE, FFUNCTION, FLINE, msg);
	}
	else {
		sprintf(dtBuf, "%s: %s",  dtBuf, msg);
	}
	
	logMessageToFile(dtBuf);
	logMessageToConsole(dtBuf);

	//return _strdup(dtBuf);
}

void logMessageFormat(const char* tFormat, int level, const char* FFUNCTION, const char* FFILE, const int FLINE, ...) {
	char dtBuf[4096];
	struct tm *lNow;
	time_t lTime;
	va_list argptr;

	if (level > LogLevel) return;

	time(&lTime);
	lNow = localtime(&lTime);
	strftime(dtBuf, sizeof(dtBuf), "%Y-%m-%d %H:%M:%S", lNow);

	if (LogSourceLocation > 0) {
		sprintf(dtBuf, "%s: File=%s, Function=%s, Line=%d: ", dtBuf, FFILE, FFUNCTION, FLINE);
	}
	else {
		sprintf(dtBuf, "%s: ",  dtBuf);
	}

	va_start(argptr, FLINE);
	vsprintf(dtBuf + strlen(dtBuf), tFormat, argptr);
	va_end(argptr);

	logMessageToFile(dtBuf);
	logMessageToConsole(dtBuf);

}

void consoleMessage(char* msg) {
	printf ("%s\n", msg);
}

char* getLastErrorCode() {
	char buf[128] = "0x";
	sprintf(buf, "%d", GetLastError());
	//itoa(GetLastError(), buf + wcslen(buf), 16);
	return strdup(buf);
}

char* getLastErrorMsg() {
	char buf[1024];
	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, GetLastError(), 0, buf, 1024, NULL);
	sprintf(buf, "%s", buf);
	return strdup(buf);
}

void logLastError() {
	char buf[1024];

	sprintf(buf, "LastError Code=%s, Msg=%s", getLastErrorCode(), getLastErrorMsg());
	LogMessage(buf);
}
