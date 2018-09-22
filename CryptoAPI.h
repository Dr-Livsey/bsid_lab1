#include <windows.h>
#include <wincrypt.h>

#pragma comment(lib, "crypt32.lib")

class CryptoAPI
{
public:
	CryptoAPI();
	~CryptoAPI();

	void GenerateSessionKey();
	void GenerateExchangeKey();

	void EncryptAndExportSessionKey();
	void DecryptAndImportSessionKey();

	PBYTE ExportKey(
					HCRYPTKEY hKey,
		            HCRYPTKEY hExpKey, 
					DWORD BlobType,
					DWORD *keylen
				    );

	PBYTE EncryptBuffer(BYTE *buffer, DWORD BufLen, DWORD *TotalSize);
	void DecryptBuffer(BYTE * buffer, DWORD *BufLen);

	HCRYPTPROV hProv;
	HCRYPTKEY SessionKey;
	HCRYPTKEY hExchangeKey;

	BYTE *enSessionKey;
	DWORD sLen;

	BYTE *PublicKey;
	DWORD pbLen;
};

