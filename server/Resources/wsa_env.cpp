#define _CRT_SECURE_NO_WARNINGS
#include "wsa_env.h"
#include <iostream>
#include <fstream>
#include <sstream>

FILE *logfile;

void error_msg(const char *str)
{
	int last_err = WSAGetLastError();

	if (!last_err || last_err == 997)
	{
		fprintf(logfile, "%s : Success\n", str);
		return;
	}
	else if (last_err && str != NULL)
	{
		wchar_t *s = NULL;
		FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
			NULL, last_err, 0, (LPWSTR)&s, 0, NULL);
		
		fprintf(logfile,"%s : (%d)%S", str, last_err, s);
		LocalFree(s);
	}

	throw(std::exception(str));
}

void print_lasterr(const char *ertype)
{
	int last_err;

	if (ertype = "winapi")
		last_err = GetLastError();
	else last_err = WSAGetLastError();

	wchar_t *s = NULL;
	FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
		NULL, last_err, 0, (LPWSTR)&s, 0, NULL);

	printf("(%d)%S\n", last_err, s);
	LocalFree(s);
}

void initWSASockets()
{
	logfile = fopen("server_log.txt", "w");
	fclose(logfile);

	logfile = fopen("server_log.txt", "a");

	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);
	error_msg("WSAStartup");
}
void deinitWSASockets()
{
	WSACleanup();
	error_msg("WSACleanup");

	fclose(logfile);
}