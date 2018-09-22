#define _CRT_SECURE_NO_WARNINGS
#include "wsa_env.h"
#include <iostream>
#include <fstream>
#include <sstream>

#include <VersionHelpers.h>

FILE *logfile;

void error_msg(const char *str)
{
	int last_err = WSAGetLastError();

	if (!last_err)
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

	printf("(%d)%S", last_err, s);
	LocalFree(s);
}

void initWSASockets()
{
	logfile = fopen("client_log.txt", "w");
	fclose(logfile);

	logfile = fopen("client_log.txt", "a");

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

void help()
{
	std::cout << "disktypes  - get disk types of the system." << std::endl;
	std::cout << "owner <file|folder|key> <item_name>  - get owner of the file|folder|key." << std::endl;
	std::cout << "accright <file|folder|key> <item_name>  - get access rights of the file|folder|key." << std::endl;
	std::cout << "freemem - get avalible free memory on local disks." << std::endl;
	std::cout << "meminfo - get memory usage information." << std::endl;
	std::cout << "stop - correctly shutdown the client." << std::endl;
	std::cout << "osver - get current OS version." << std::endl;
	std::cout << "osboot time - get time since the OS was loaded." << std::endl;
	std::cout << "sys time - get system OS time.\n" << std::endl;
}

const char *OSversion(DWORD major, DWORD minor)
{
	if (IsWindows10OrGreater()) return "Windows 10";

	switch (major)
	{
	case 4:
		if (!minor) return "Windows 95";
		else if (minor == 10) return "Windows 98";
		else if (minor == 90) return "WindowsMe";
		break;
	case 5:
		if (!minor) return "Windows 2000";
		else if (minor == 1) return "Windows XP";
		else if (minor == 2) return "Windows 2003";
	case 6:
		if (!minor) return "Windows Vista";
		else if (minor == 1) return "Windows 7";
		else if (minor == 2) return "Windows 8";
		else if (minor == 3) return "Windows 8.1";
	default:
		break;
	}

	return NULL;
}