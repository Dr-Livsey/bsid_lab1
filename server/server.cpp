#include <iostream>
#include "wsa_env.h"


using std::cout;
using std::endl;

#define clean_olp(olp) memset(&olp, 0, sizeof(OVERLAPPED));
#pragma warning(disable : 4996)

struct client
{
	SOCKET sock;

	OVERLAPPED overlap_r;
	OVERLAPPED overlap_s;
	OVERLAPPED overlap_c;

	char request[2048];

	const char *ip;
	unsigned port;
};

struct ACEitem
{
	ACCESS_ALLOWED_ACE pAce;
	SID_NAME_USE SidType;
	CHAR Name[64];
};

struct VolInf
{
	char  lpRootPathName[4];
	char   FSname[MAX_PATH + 1];
};

class RequestHandler
{
public:
	RequestHandler() {}
	void handle_request(client *c);

private:
	void send_pack(client *c, char *buffer, ULONG buf_size);
	//Handlers
	void send_systime(client *c);
	void send_osbtime(client *c);
	void send_osver(client *c);
	void send_meminf(client *c);
	void send_freemem(client *c);
	void send_accrights(unsigned opcode, client *c);
	void send_disktypes(client *c);
};

void RequestHandler::send_pack(client *c, char *buffer, ULONG buf_size)
{
	DWORD lpNumberOfBytesSent, dwFlags = 0;
	WSABUF buf;
	buf.buf = buffer;
	buf.len = buf_size;

	clean_olp(c->overlap_s);
	WSASend(c->sock, &buf, 1, &lpNumberOfBytesSent, dwFlags, &c->overlap_s, NULL);
	error_msg("WSASend");
}
void RequestHandler::handle_request(client *c)
{
	unsigned opcode;
	memcpy((char*)&opcode, c->request, sizeof(unsigned));

	switch (opcode)
	{
	case GET_CTIME:
		send_systime(c);
		break;
	case GET_OSBTIME:
		send_osbtime(c);
		break;
	case GET_OSVER:
		send_osver(c);
		break;
	case GET_MEMINF:
		send_meminf(c);
		break;
	case GET_FREEMEM:
		send_freemem(c);
		break;
	case GET_ACCRIGHTS:
		send_accrights(opcode, c);
		break;
	case GET_OWNER:
		send_accrights(opcode, c);
		break;
	case GET_DISKTYPES:
		send_disktypes(c);
		break;
	default:
		break;
	}

}

void RequestHandler::send_systime(client *c)
{
	SYSTEMTIME sm;
	GetSystemTime(&sm);
	send_pack(c, (char*)&sm, sizeof(sm));
}
void RequestHandler::send_osbtime(client *c)
{
	DWORD osbtime[4];
	osbtime[3] = GetTickCount();
	osbtime[0] = osbtime[3] / (1000 * 60 * 60);
	osbtime[1] = osbtime[3] / (1000 * 60) - osbtime[0] * 60;
	osbtime[2] = (osbtime[3] / 1000) - (osbtime[0] * 60 * 60) - osbtime[1] * 60;
	osbtime[3] = osbtime[3] - osbtime[0] * 60 * 60 * 1000 - osbtime[1] * 60 * 1000 - osbtime[2] * 1000;

	send_pack(c, (char*)&osbtime, sizeof(DWORD) * 4);
}
void RequestHandler::send_osver(client *c)
{
	OSVERSIONINFOEX osvi;
	ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));
	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	GetVersionEx((LPOSVERSIONINFOA)&osvi);

	send_pack(c, (char*)&osvi, sizeof(OSVERSIONINFOEX));
}
void RequestHandler::send_meminf(client *c)
{
	MEMORYSTATUS stat;
	GlobalMemoryStatus(&stat);
	send_pack(c, (char*)&stat, sizeof(MEMORYSTATUS));
}
void RequestHandler::send_freemem(client *c)
{
	DWORD ldisks_mask = GetLogicalDrives();
	char send_buf[2048] = { 0 };
	unsigned dam = 0;
	char ldisks[26][3];

	for (int i = 0; i < 26; i++)
	{
		if ((ldisks_mask >> i) & 1)
		{
			ldisks[i][0] = char('A' + i);
			ldisks[i][1] = ':';
			ldisks[i][2] = '\0';

			if (GetDriveTypeA(ldisks[i]) == DRIVE_FIXED)			{
				DWORD sperc, bpers, fnum, total_clas;
				GetDiskFreeSpace(ldisks[i], &sperc, &bpers, &fnum, &total_clas);
				long double free_space = (double)fnum * (double)sperc * (double)bpers 
																	/ (1024. * 1024.*1024.);
				memcpy(&send_buf[4] + dam * (3 + sizeof(long double)), ldisks[i], 3);
				memcpy(&send_buf[4] + dam * (3 + sizeof(long double)) + 3,
					   (char*)&free_space, 
					   sizeof(long double));

				dam++;
			}
		}
	}

	memcpy(send_buf, (char*)&dam, sizeof(unsigned));
	send_pack(c, (char*)&send_buf, sizeof(unsigned) + dam * (3 + sizeof(long double)));
}
void RequestHandler::send_accrights(unsigned opcode, client *c)
{
	char item[128], cmd[10];
	unsigned short size, offset;

	memcpy((char*)&size, &c->request[4], sizeof(unsigned short));
	memcpy(cmd, &c->request[4] + sizeof(unsigned short), size);
	offset = sizeof(unsigned short) + size;

	memcpy((char*)&size, &c->request[4] + offset, sizeof(unsigned short));
	memcpy((char*)&item, &c->request[4] + sizeof(unsigned short) + offset, size);

	PACL  ppDacl;
	PSECURITY_DESCRIPTOR ppSD;
	PSID ppsidOwner;

	_SE_OBJECT_TYPE objtype;
	SECURITY_INFORMATION SI;
	SID_NAME_USE eSidType;

	DWORD NameBufferSize = 512;
	DWORD DomainBufferSize = 512;
	CHAR Name[512];
	CHAR DomainName[512];
	
	if (std::string(cmd) == "file" ||
		std::string(cmd) == "folder") objtype = SE_FILE_OBJECT;
	else
		objtype = SE_REGISTRY_KEY;

	switch (opcode)
	{
	case GET_ACCRIGHTS:
		SI = DACL_SECURITY_INFORMATION;
		break;
	case GET_OWNER:
		SI = OWNER_SECURITY_INFORMATION;
		break;
	default:
		break;
	}

	DWORD retval = GetNamedSecurityInfo(item,
										objtype,
										SI,
										&ppsidOwner,
										NULL,
										&ppDacl,
										NULL,
										&ppSD);
	char buffer[2048];

	if (retval != ERROR_SUCCESS)
	{
		memcpy(buffer, (char*)&retval, sizeof(DWORD));
		send_pack(c, buffer, sizeof(DWORD));
		LocalFree(ppSD);
		return;
	}

	ZeroMemory(buffer, sizeof(char) * 2048);

	if (opcode == GET_OWNER)
	{
		if (LookupAccountSid(NULL,
			ppsidOwner,
			Name,
			&NameBufferSize,
			DomainName,
			&DomainBufferSize,
			&eSidType))
		{
			send_pack(c, (char*)&retval, sizeof(retval));

			ACEitem acei;
			DWORD SidLength = GetLengthSid(ppsidOwner);
			LPSTR StringSid = new CHAR[SidLength];
			ConvertSidToStringSid(ppsidOwner, &StringSid);
			
			memcpy(acei.Name, Name, (NameBufferSize + 1) * sizeof(CHAR));
			acei.SidType = eSidType;

			memcpy(buffer, (char*)&SidLength, sizeof(DWORD));
			memcpy(buffer + sizeof(DWORD), (char*)&acei, sizeof(ACEitem));
			memcpy(buffer + sizeof(ACEitem) + sizeof(DWORD), StringSid, SidLength);
			delete StringSid;

			send_pack(c, buffer, sizeof(DWORD) + sizeof(ACEitem) + SidLength);
		}
		else
		{
			retval = GetLastError();
			memcpy(buffer, (char*)&retval, sizeof(DWORD));
			send_pack(c, buffer, sizeof(DWORD));
		}

		return;
	}

	ACL_SIZE_INFORMATION  aclsizeinfo;

	if (!GetAclInformation(ppDacl, 
							&aclsizeinfo, 
							sizeof(aclsizeinfo), 
							AclSizeInformation))
	{
		retval = GetLastError();
		memcpy(buffer, (char*)&retval, sizeof(DWORD));
		send_pack(c, buffer, sizeof(DWORD));
		return;
	}

	/*Send error_code = 0*/
	send_pack(c, (char*)&retval, sizeof(retval));

	ACCESS_ALLOWED_ACE * pAce = NULL;
	WORD aceamount = 0;

	offset = sizeof(WORD);
	setlocale(0, "RUS");
	for (DWORD cAce = 0; cAce < aclsizeinfo.AceCount; cAce++)
	{
		if (GetAce(ppDacl, cAce, (LPVOID*)&pAce))
		{
			ZeroMemory(Name, sizeof(CHAR) * 512);
			ZeroMemory(DomainName, sizeof(CHAR) * 512);
			NameBufferSize = 512;
			DomainBufferSize = 512;

			if (LookupAccountSid(NULL,
				&pAce->SidStart,
				Name,
				&NameBufferSize,
				DomainName,
				&DomainBufferSize,
				&eSidType))
			{
				struct ACEitem acei;
				DWORD SidLength = GetLengthSid(&pAce->SidStart);
				LPSTR StringSid = new CHAR[SidLength];
				ConvertSidToStringSid(&pAce->SidStart, &StringSid);
	
				memcpy((char*)&acei.pAce, pAce, sizeof(ACCESS_ALLOWED_ACE));
				memcpy(acei.Name, Name, (NameBufferSize + 1)* sizeof(CHAR));
				acei.SidType = eSidType;

				memcpy(buffer + offset, (char*)&acei, sizeof(ACEitem));
				offset += sizeof(ACEitem);
				memcpy(buffer + offset, (char*)&SidLength, sizeof(DWORD));
				offset += sizeof(DWORD);
				memcpy(buffer + offset, StringSid, SidLength);
				offset += (WORD)SidLength;

				delete StringSid;
				aceamount++;
			}
		}
	}

	memcpy(buffer, (char*)&aceamount, sizeof(WORD));
	send_pack(c, buffer, offset);

	LocalFree(ppSD);
}
void RequestHandler::send_disktypes(client *c)
{
	DWORD ldisks_mask = GetLogicalDrives();
	WORD disk_amount = 0, offset = sizeof(WORD);
	char buffer[2048];

	for (int i = 0; i < 26; i++)
	{
		if ((ldisks_mask >> i) & 1)
		{
			struct VolInf cur_vol;
			char   lpVolumeNameBuffer[MAX_PATH + 1];
			DWORD lpVolumeSerialNumber;
			DWORD lpMaximumComponentLength;
			DWORD lpFileSystemFlags;

			ZeroMemory(cur_vol.lpRootPathName, 3);
			sprintf(cur_vol.lpRootPathName, "%c:\\", char('A' + i));
			
			GetVolumeInformation(cur_vol.lpRootPathName,
								lpVolumeNameBuffer,
								sizeof(lpVolumeNameBuffer),
								&lpVolumeSerialNumber,
								&lpMaximumComponentLength,
								&lpFileSystemFlags,
								cur_vol.FSname,
								sizeof(cur_vol.FSname));

			memcpy(buffer + offset, (char*)&cur_vol, sizeof(VolInf));
			offset += sizeof(VolInf);
			disk_amount++;
		}
	}
	memcpy(buffer, (char*)&disk_amount, sizeof(WORD));
	send_pack(c, buffer, offset);
}


typedef std::map<SOCKET, client*> client_id;

class TCPServer
{
public:
	HANDLE iocp;
	HANDLE tiocp;
	SOCKET s;

	TCPServer(unsigned port)
	{
		try
		{
			s = WSASocket(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
			error_msg("WSASocket");

			sockaddr_in serv_addr;
			memset(serv_addr.sin_zero, 0, sizeof(char) * 8);
			serv_addr.sin_port = htons(port);
			serv_addr.sin_family = AF_INET;
			serv_addr.sin_addr.S_un.S_addr = htonl(INADDR_ANY);

			bind(s, (sockaddr*)&serv_addr, sizeof(serv_addr));
			error_msg("bind");

			listen(s, 512);
			error_msg("Liten");

			iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, (ULONG_PTR)0, 0);
			error_msg("CreateIoCompletionPort");

			tiocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, (ULONG_PTR)0, 0);
			error_msg("CreateIoCompletionPort");

			CreateIoCompletionPort((HANDLE)s, iocp, (ULONG_PTR)s, 0);
			error_msg("CreateIoCompletionPort.for listen");

			cout << "Listen " << port << endl;

			create_pool();

			schedule_accept();
		}
		catch (const std::exception &e)
		{
			cout << "Exception in: " << e.what() << endl;
		}
	
	}

	client* get_client(SOCKET sock) { return cmap[sock]; }
	void remove_client(SOCKET s) 
	{ 
		delete cmap[s];
		cmap.erase(s);
		closesocket(s);  
	}

	void schedule_accept();
	void schedule_request(client *c);
	void schedule_cancel(client *c);
	
	void accept_handler();

	~TCPServer() 
	{ 
		for (auto i = cmap.begin(); i != cmap.end(); i++)
  		{  
			closesocket(i->first);
			delete i->second;
		}

		cmap.clear();
		closesocket(s); 
		CloseHandle(threads[0]);
		CloseHandle(threads[1]);
		CloseHandle(iocp);
		CloseHandle(tiocp);
	}

private:
	SOCKET accepted_socket;
	std::map<SOCKET, client*> cmap;
	CHAR connection_buf[1024];
	OVERLAPPED overlap;

	void create_pool();
	static DWORD WINAPI PoolWorking(LPVOID lpParam);
	HANDLE threads[2];
};


DWORD WINAPI TCPServer::PoolWorking(LPVOID server)
{
	TCPServer *pServer = (TCPServer*)server;
	RequestHandler rhandler;

	while (true)
	{
		DWORD transfered;
		ULONG_PTR lpCompletionKey;
		OVERLAPPED *olp;

		bool retval = GetQueuedCompletionStatus(pServer->tiocp,
			&transfered,
			&lpCompletionKey,
			&olp,
			INFINITE);
	
		if (retval == true)
		{
			client *cur_client = pServer->get_client(lpCompletionKey);

			if (&cur_client->overlap_r == olp)
			{
				if (!transfered)
				{
					ZeroMemory(&cur_client->overlap_c, sizeof(OVERLAPPED));
					PostQueuedCompletionStatus(pServer->iocp, 
												1, 
												(ULONG_PTR)cur_client->sock,
												&cur_client->overlap_c);
					
				}
				else
				{
					rhandler.handle_request(cur_client);
					pServer->schedule_request(cur_client);
				}
			}
		}

	}

	return 0;
}
void TCPServer::create_pool()
{
	for (int i = 0; i < 2; i++)
	{
		threads[i] = CreateThread(NULL, 
								  0, 
								  (LPTHREAD_START_ROUTINE)&PoolWorking, 
								  this, 
								  0, 
								  0);
		error_msg("CreateThread");
	}
}

void TCPServer::schedule_accept()
{
	try
	{
		accepted_socket = WSASocket(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
		clean_olp(overlap);

		AcceptEx(s,
				accepted_socket,
				connection_buf,
				0,
				sizeof(sockaddr) + 16,
				sizeof(sockaddr) + 16,
				NULL,
				&overlap);

		error_msg("AcceptEx");
	}
	catch (const std::exception &e)
	{
		cout << "Exception in: " << e.what() << endl;
		closesocket(accepted_socket);
	}
}
void TCPServer::schedule_request(client *c)
{
	DWORD flags = 0;
	WSABUF buffer;

	ZeroMemory(c->request, sizeof(char) * 2048);
	buffer.buf = c->request;
	buffer.len = 2048 * sizeof(char);

	clean_olp(c->overlap_r);
	try
	{
		WSARecv(c->sock, &buffer, 1, NULL, &flags, &c->overlap_r, NULL);
		error_msg("WSARecv");
	}
	catch (const std::exception &e)
	{
		cout << "Exception in: " << e.what() << endl;
	}
}
void TCPServer::schedule_cancel(client *c)
{
	CancelIo((HANDLE)c->sock);
	ZeroMemory(&c->overlap_c, sizeof(OVERLAPPED));
	try
	{
		PostQueuedCompletionStatus(iocp, 0, (ULONG_PTR)c->sock, &c->overlap_c);
		error_msg("PostQueuedCompletionStatus");
	}
	catch (const std::exception &e)
	{
		cout << "Exception in: " << e.what() << endl;
	}
}
void TCPServer::accept_handler()
{
	client *new_cli = new client;
	int laddr_size, rmt_addr_size;
	sockaddr_in *local_addres;
	sockaddr_in *remote_addres;

	GetAcceptExSockaddrs(connection_buf,
		0,
		sizeof(sockaddr) + 16,
		sizeof(sockaddr) + 16,
		(sockaddr**)&local_addres,
		&laddr_size,
		(sockaddr**)&remote_addres,
		&rmt_addr_size);

	new_cli->ip = inet_ntoa(remote_addres->sin_addr);
	new_cli->port = ntohs(remote_addres->sin_port);
	new_cli->sock = accepted_socket;

	cout << "Peer connected : " << new_cli->ip << ":" << new_cli->port << endl;

	CreateIoCompletionPort((HANDLE)new_cli->sock, tiocp, new_cli->sock, 0);
	error_msg("CreateIoCompletionPort");

	cmap[accepted_socket] = new_cli;

	schedule_request(cmap[accepted_socket]);
	schedule_accept();
}

int main()
{
	initWSASockets();
	TCPServer server(19001);

	RequestHandler rhandler;

	/*Accept Connections.*/
	while (true)
	{
		DWORD transfered;
		ULONG_PTR lpCompletionKey;
		OVERLAPPED *overlap;

		bool retval = GetQueuedCompletionStatus(server.iocp,
				&transfered,
				&lpCompletionKey,
				&overlap,
				INFINITE);

		if (retval == true)
		{
			if (lpCompletionKey == server.s) server.accept_handler();
			else
			{
				client *cur_client = server.get_client(lpCompletionKey);

				if (&cur_client->overlap_c == overlap)
				{
					if (transfered == 1)
					{
						server.schedule_cancel(cur_client);
						continue;
					}

					cout << "Peer disconnected : " << cur_client->ip << ":"
						<< cur_client->port << endl;

					server.remove_client(cur_client->sock);
				}
			}
		}
	}

	deinitWSASockets();
	_getch();
	return EXIT_SUCCESS;
}