#include <iostream>
#include <string>
#include <bitset>

#include "wsa_env.h"
#include "acl_env.h"
#include "CryptoAPI.h"

#include <boost/lexical_cast.hpp>
#include <boost/regex.hpp>

#define clean_olp(olp) memset(&olp, 0, sizeof(OVERLAPPED));

using std::cout;
using std::endl;
using std::string;

struct VolInf
{
	char  lpRootPathName[4];
	char   FSname[MAX_PATH + 1];
};

class TCPSocket
{
public:
	TCPSocket();
	~TCPSocket() { closesocket(s); }

	void terminate();
	void connect_to_server(const char *ip, unsigned port);
	SOCKET get_sock() { return s; }

private:
	SOCKET s;
	void set_sockaddr(DWORD ip, unsigned short port, sockaddr_in &si);
};

TCPSocket::TCPSocket()
{
	try
	{
		s = WSASocket(AF_INET, SOCK_STREAM, 0, NULL, 0, 0);
		error_msg("WSASocket");
	}
	catch (const std::exception &e)
	{
		cout << "Exception in: " << e.what() << endl;
	}
}
void TCPSocket::terminate()
{
	closesocket(s);

	cout << endl << "Client terminating";
	for (int i = 0; i < 3;i++)
	{
		Sleep(200);
		cout << ".";
	}
}
void TCPSocket::set_sockaddr(DWORD ip, unsigned short port, sockaddr_in &si)
{
	memset(si.sin_zero, 0, 8 * sizeof(char));
	si.sin_family = AF_INET;
	si.sin_port = port;
	si.sin_addr.s_addr = ip;
}
void TCPSocket::connect_to_server(const char *ip, unsigned port)
{
	sockaddr_in serv_addr;
	set_sockaddr(inet_addr(ip), htons(port), serv_addr);

	for (int i = 0; i < 10; i++)
	{
		bool retval = WSAConnect(s, (sockaddr*)&serv_addr, sizeof(serv_addr), NULL, NULL, 0, 0);

		if (!retval)
		{
			cout << "Client connected to " << ip << ":" << port << endl;
			return;
		}
		else
		{
			cout << i + 1
				<< " : No connection could be made. Target machine actively refused it." << endl;
			Sleep(500);
		}
	}

	cout << "Connection refused.\n" << endl;
	throw (std::exception("refused"));
}

class RequestHandler
{
public:
	CryptoAPI CApi_client;

	RequestHandler(SOCKET s) : sh(s) { is_sKey_establish = false; }

	void get_systime();
	void get_osb_time();
	void get_osver();
	void get_meminf();
	void get_freemem();
	void get_accrights(unsigned opcode, string cmd, string item);
	void get_disktypes();
private:
	RequestHandler() {}
	void send_pack(char *buffer, ULONG buf_size);
	void recieve_pack();
	void make_request(unsigned opcode, char *add_inf, ULONG ai_size);
	void establish_session_key();

	SOCKET sh;
	char req_buffer[2048];
	bool is_sKey_establish;
};



void RequestHandler::send_pack(char *buffer, ULONG buf_size)
{
	PBYTE encrypted_buf = NULL;
	DWORD lpNumberOfBytesSent, dwFlags = 0;
	WSABUF buf;

	if (is_sKey_establish == true)
	{
		DWORD encr_size = buf_size;
		encrypted_buf = CApi_client.EncryptBuffer((PBYTE)buffer, buf_size, &encr_size);
		buf.buf = (char*)encrypted_buf;
		buf.len = encr_size;
	}
	else
	{
		buf.buf = buffer;
		buf.len = buf_size * sizeof(char);
	}

	WSASend(sh, &buf, 1, &lpNumberOfBytesSent, dwFlags, NULL, NULL);
	
	if (WSAECONNRESET == WSAGetLastError())
	{
		closesocket(sh);
		cout << "Connection reset." << endl;
		Sleep(500);
		exit(EXIT_FAILURE);
	}

	error_msg("WSASend");

	if (is_sKey_establish == true) delete[] encrypted_buf;
}
void RequestHandler::recieve_pack()
{
	DWORD flags = 0;
	DWORD RecvBytes;
	WSABUF buffer;

	ZeroMemory(req_buffer, sizeof(char) * 2048);
	buffer.buf = req_buffer;
	buffer.len = 2048 * sizeof(char);

	WSARecv(sh, &buffer, 1, &RecvBytes, &flags, NULL, NULL);

	if (WSAECONNRESET == WSAGetLastError())
	{
		closesocket(sh);
		cout << "Connection reset." << endl;
		Sleep(500);
		exit(EXIT_FAILURE);
	}

	if (is_sKey_establish == true)
	{
		CApi_client.DecryptBuffer((PBYTE)req_buffer, &RecvBytes);
	}
}
void RequestHandler::make_request(unsigned opcode, char *add_inf, ULONG ai_size)
{
	ZeroMemory(req_buffer, sizeof(char) * 2048);
	memcpy(req_buffer, (char*)&opcode, sizeof(unsigned));
	memcpy(req_buffer + sizeof(unsigned), add_inf, ai_size);
}

void RequestHandler::establish_session_key()
{
	is_sKey_establish = false;

	/*Export PublicKey and send it to server.*/
	CApi_client.GenerateExchangeKey();
	CApi_client.PublicKey = CApi_client.ExportKey(
												CApi_client.hExchangeKey,
												0,
												PUBLICKEYBLOB,
												&CApi_client.pbLen);
	char pbKeyBuf[2048];
	memcpy(pbKeyBuf, (char*)&CApi_client.pbLen, sizeof(DWORD));
	memcpy(pbKeyBuf + sizeof(DWORD), (char*)CApi_client.PublicKey, CApi_client.pbLen * sizeof(BYTE));
	send_pack(pbKeyBuf, sizeof(DWORD) + CApi_client.pbLen * sizeof(BYTE));

	/*Recieve Session Key encrypted with Public Key*/
	recieve_pack();
	memcpy((char*)&CApi_client.sLen, req_buffer, sizeof(DWORD));
	CApi_client.enSessionKey = new BYTE[CApi_client.sLen];
	memcpy(CApi_client.enSessionKey, req_buffer + sizeof(DWORD), sizeof(BYTE)*CApi_client.sLen);

	/*Decrypt Session Key with Public Key*/
	CApi_client.DecryptAndImportSessionKey();	

	is_sKey_establish = true;
}

void RequestHandler::get_systime()
{
	establish_session_key();

	unsigned opcode = GET_CTIME;
	make_request(opcode, NULL, 0);
	send_pack(req_buffer, strlen(req_buffer));

	establish_session_key();
	recieve_pack();
	
	SYSTEMTIME sm;
	memcpy(&sm, req_buffer, sizeof(sm));

	char data[128];
	sprintf(data, "Data : %hu.%hu.%hu, Time : %hu:%hu:%hu\n", sm.wDay, sm.wMonth, sm.wYear,
															 sm.wHour, sm.wMinute, sm.wSecond);
	cout << data << endl;
}
void RequestHandler::get_osb_time()
{
	establish_session_key();

	unsigned opcode = GET_OSBTIME;
	make_request(opcode, NULL, 0);
	send_pack(req_buffer, strlen(req_buffer));

	establish_session_key();
	recieve_pack();

	cout << "System time : ";
	for (int i = 0; i < 4; i++)
	{
		DWORD time_item;
		memcpy((char*)&time_item, req_buffer + i * sizeof(DWORD), sizeof(DWORD));

	    cout << time_item;
		if (i != 3) cout << ":";
	}
	cout << "\n" << endl;
}
void RequestHandler::get_osver()
{
	establish_session_key();

	unsigned opcode = GET_OSVER;

	make_request(opcode, NULL, 0);
	send_pack(req_buffer, strlen(req_buffer));

	establish_session_key();
	recieve_pack();

	OSVERSIONINFOEX osvi;
	memcpy((char*)&osvi, req_buffer, sizeof(OSVERSIONINFOEX));

	cout << "OS version is " 
		 << OSversion(osvi.dwMajorVersion, osvi.dwMinorVersion) << ".\n" << endl;
}
void RequestHandler::get_meminf()
{
	establish_session_key();

	unsigned opcode = GET_MEMINF;

	make_request(opcode, NULL, 0);
	send_pack(req_buffer, strlen(req_buffer));

	establish_session_key();
	recieve_pack();

	MEMORYSTATUS stat;
	memcpy((char*)&stat, req_buffer, sizeof(MEMORYSTATUS));

	cout << "Memory Usage Information:" << endl;
	cout << "Memory load = " << stat.dwMemoryLoad << " %\n" << endl;
	cout << "Physical Memory: " << endl;
	cout << "Total = "	<< stat.dwTotalPhys << " byte(s)" << endl;
	cout << "Available = " << stat.dwAvailPhys << " byte(s)\n" << endl;
	cout << "Page Memory: " << endl;
	cout << "Total = " << stat.dwTotalPageFile << " byte(s)" << endl;
	cout << "Available = " << stat.dwAvailPageFile << " byte(s)\n" << endl;
	cout << "Virtual Memory: " << endl;
	cout << "Total = " << stat.dwTotalVirtual << " byte(s)" << endl;
	cout << "Available = " << stat.dwAvailVirtual << " byte(s)\n" << endl;
}
void RequestHandler::get_freemem()
{
	establish_session_key();

	unsigned opcode = GET_FREEMEM;

	make_request(opcode, NULL, 0);
	send_pack(req_buffer, strlen(req_buffer));

	establish_session_key();
	recieve_pack();

	unsigned disk_amount;
	memcpy((char*)&disk_amount, req_buffer, sizeof(unsigned));

	cout << "Free memory on local disk(s):" << endl;
	for (unsigned i = 0; i < disk_amount; i++)
	{
		char disk_name[3];
		long double dsize;
		memcpy(disk_name, &req_buffer[4] + i * (3 + sizeof(long double)), 3);
		memcpy(&dsize, 
			   &req_buffer[4] + i * (3 + sizeof(long double)) + 3, 
			   sizeof(long double));

		cout << "Disk " << disk_name << " " << dsize << " Gb" << endl;
	}
	cout << "\n";
}
void RequestHandler::get_accrights(unsigned opcode, string cmd, string item)
{
	establish_session_key();

	setlocale(0, "RUS");
	char tmp[128];
	unsigned short cmd_len = (unsigned short)(cmd.length() + 1);
	unsigned short item_len = (unsigned short)(item.length() + 1);
	unsigned short offset = 0;

	memcpy(tmp, (char*)&cmd_len, sizeof(unsigned short));
	memcpy(tmp + sizeof(unsigned short), cmd.c_str(), cmd_len);
	offset += sizeof(unsigned short) + cmd_len;

	memcpy(tmp + offset, (char*)&item_len, sizeof(unsigned short));
	memcpy(tmp + offset + sizeof(unsigned short), item.c_str(), item_len);
	offset += sizeof(unsigned short) + item_len;

	make_request(opcode, (char*)tmp, offset);
	send_pack(req_buffer, offset + sizeof(unsigned));

	/*Receive error code of operation.*/
	DWORD err;

	establish_session_key();
	recieve_pack();

	memcpy((char*)&err, req_buffer, sizeof(DWORD));

	if (err != ERROR_SUCCESS)
	{
		SetLastError(err);
		print_lasterr("winapi");
		cout << "\n" << endl;
		return;
	}

	/*Receive information pack.*/
	establish_session_key();
	recieve_pack();

	if (opcode == GET_OWNER)
	{
		ACEitem acei;
		DWORD SidLength;
		memcpy((char*)&SidLength, req_buffer, sizeof(DWORD));

		LPSTR StringSid = new CHAR[SidLength];
		memcpy((char*)&acei, &req_buffer[sizeof(DWORD)], sizeof(ACEitem));
		memcpy(StringSid, &req_buffer[sizeof(DWORD)] + sizeof(ACEitem), SidLength);

		cout << "\nOwner:" << endl;
		cout << "SID: " << StringSid << endl;
		cout << "SID type: " << use_name_labels[acei.SidType - 1] << endl;
		cout << "User: " << acei.Name << endl << endl;

		delete StringSid;
		return;
	}

	WORD aceamount = 0;
	offset = sizeof(WORD);

	memcpy((char*)&aceamount, req_buffer, offset);

	cout << "\nAccess Control List:\n" << endl;
	for (WORD i = 0; i < aceamount; i++)
	{
		ACEitem acei;
		DWORD SidLength;
		memcpy((char*)&acei, req_buffer + offset, sizeof(ACEitem));
		offset += sizeof(ACEitem);
		memcpy((char*)&SidLength, req_buffer + offset, sizeof(DWORD));
		offset += sizeof(DWORD);
		LPSTR StringSid = new CHAR[SidLength];
		memcpy(StringSid, req_buffer + offset, SidLength);
		offset += SidLength;

		cout << "SID: " << StringSid << endl;
		cout << "User: " << acei.Name << endl;
		cout << "SID type: " << use_name_labels[acei.SidType - 1] << endl;
		cout << "ACE type: " << ace_type_labels[acei.pAce.Header.AceType] << endl;
		cout << "Binary Access Mask: " << std::bitset<32>(acei.pAce.Mask) << endl;
		cout << "Access Rights: " << endl;
		view_accrights(acei.pAce.Mask);
		cout << endl;

		delete StringSid;
	}

}
void RequestHandler::get_disktypes()
{
	establish_session_key();

	const char *DT[] = {
	{  "DRIVE_UNKNOWN" },
	{  "DRIVE_NO_ROOT_DIR"},
	{  "DRIVE_REMOVABLE" },
	{  "DRIVE_FIXED"  },
	{  "DRIVE_REMOTE" },
	{  "DRIVE_CDROM" },
	{  "DRIVE_RAMDISK" } };
	unsigned opcode = GET_DISKTYPES;

	make_request(opcode, NULL, 0);
	send_pack(req_buffer, strlen(req_buffer));

	establish_session_key();
	recieve_pack();

	WORD disk_amount, offset = sizeof(WORD);
	memcpy((char*)&disk_amount, req_buffer, sizeof(WORD));

	for (int i = 0;i < disk_amount; i++)
	{
		VolInf diskinf;
		memcpy((char*)&diskinf, req_buffer + offset, sizeof(VolInf));
		offset += sizeof(VolInf);

		cout << "Disk: " << diskinf.lpRootPathName
			<< ". Type: " << DT[GetDriveType(diskinf.lpRootPathName)]
			<< ". Filesystem: " << diskinf.FSname
			<< endl;
	}
	cout << endl;
}


void addr_verify(string &addr_string, unsigned *port)
{
	boost::smatch matches;
	boost::regex ideal("^(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}):(\\d{1,5})$");

	if (boost::regex_match(addr_string, matches, ideal) == false)
	{
		throw(std::exception("Invalid address. Try again."));
	}
	else
	{
		*port = boost::lexical_cast<unsigned>(matches.str(2));
		addr_string = matches.str(1);
	}
}
bool regexp_verify(string ideal, boost::smatch &m, string test)
{
	boost::smatch matches;
	boost::regex ar(ideal);
	return boost::regex_match(test, m, ar);
}


int main(int argc, char *argv[])
{
	string user_addr;
	unsigned port = 19001;
	const char *ip = NULL;

	cout << "Specify server addres: xxx.xxx.xxx.xxx:xxxxx\n" << endl << ">";
	while (ip == NULL)
	{
		try
		{
			std::getline(std::cin, user_addr);
			addr_verify(user_addr, &port);
			ip = user_addr.c_str();
		}
		catch (const std::exception &e)
		{
			cout << e.what() << endl << endl << ">";
		}
	}

	initWSASockets();
	TCPSocket client;

	try
	{
		client.connect_to_server(ip, port);
	}
	catch (const std::exception &e)
	{
		if (string(e.what()) == "refused")
		{
			deinitWSASockets();
			client.terminate();
			return EXIT_FAILURE;
		}
	}


	string cmd_line;
	RequestHandler rhandler(client.get_sock());
	while (cmd_line != "stop")
	{
		cout << ">";
		std::getline(std::cin, cmd_line);
	
		if (cmd_line == "sys time"){ rhandler.get_systime(); continue; }
		else if (cmd_line == "disktypes") { rhandler.get_disktypes(); continue; }
		else if (cmd_line == "freemem"){ rhandler.get_freemem(); continue; }
		else if (cmd_line.substr(0, cmd_line.find(" ")) == "accright")
		{
			boost::smatch matches;
			if (regexp_verify(string("^accright (key|folder|file) (.+)$"), matches, cmd_line)) 
			{
				rhandler.get_accrights(GET_ACCRIGHTS, matches[1], matches[2]);
				continue;
			}
		}
		else if (cmd_line.substr(0, cmd_line.find(" ")) == "owner")
		{
			boost::smatch matches;
			if (regexp_verify(string("^owner (key|folder|file) (.+)$"), matches, cmd_line))
			{
				rhandler.get_accrights(GET_OWNER, matches[1], matches[2]);
				continue;
			}
		}
		else if (cmd_line == "osboot time"){ rhandler.get_osb_time(); continue; }
		else if (cmd_line == "osver"){ rhandler.get_osver(); continue; }
		else if (cmd_line == "meminfo"){ rhandler.get_meminf(); continue; }
		else if (cmd_line == "--help"){ help(); continue; }
		
		if (cmd_line != "stop" && cmd_line != "")
		{
			cout << "Incorrect command. Enter '--help' to view command list.\n" << endl;
		}

	}


	client.terminate();
	deinitWSASockets();
	return EXIT_SUCCESS;
}
