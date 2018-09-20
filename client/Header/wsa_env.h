#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <winerror.h>
#include <windows.h>
#include <winsock2.h>
#include <mswsock.h>
#include <map>
#include <aclapi.h>
#include <sddl.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wsock32.lib")


#define clean_olp(olp) memset(&olp, 0, sizeof(OVERLAPPED));

//Command hashes
#define GET_CTIME 0xA2111113
#define GET_OSBTIME 0xBCC11113
#define GET_OSVER 0xB111113
#define GET_MEMINF 0xA212122
#define GET_FREEMEM 0x12312311
#define GET_ACCRIGHTS 0x3331113
#define GET_OWNER 0x123451
#define GET_DISKTYPES 0x44332211

void error_msg(const char *str);
void print_lasterr(const char *ertype);
void initWSASockets();
void deinitWSASockets();

const char *OSversion(DWORD major, DWORD minor);
void help();