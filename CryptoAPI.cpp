#include "CryptoAPI.h"
#include <iostream>




CryptoAPI::CryptoAPI()
{
	CryptAcquireContextA(
		&hProv,
		NULL,
		MS_ENH_RSA_AES_PROV,
		PROV_RSA_AES,
		CRYPT_VERIFYCONTEXT);
}


CryptoAPI::~CryptoAPI()
{
	CryptReleaseContext(hProv, 0);
	CryptDestroyKey(hExchangeKey);
	CryptDestroyKey(SessionKey);

	if (enSessionKey != NULL) delete [] enSessionKey;
	if (PublicKey != NULL) delete [] PublicKey;
}

void CryptoAPI::GenerateSessionKey()
{
	CryptGenKey(hProv,
		CALG_AES_256,
		CRYPT_EXPORTABLE,
		&SessionKey);				
}

void CryptoAPI::GenerateExchangeKey()
{
	CryptGenKey(hProv,
				CALG_RSA_KEYX,
				RSA1024BIT_KEY,
				&hExchangeKey);
}

void CryptoAPI::EncryptAndExportSessionKey()
{
	HCRYPTKEY hpbKey;

	CryptImportKey(hProv,
					PublicKey,
					pbLen,
					0,
					0,
					&hpbKey);
	
	enSessionKey = ExportKey(SessionKey, hpbKey, SIMPLEBLOB, &sLen);
}

void CryptoAPI::DecryptAndImportSessionKey()
{
	HCRYPTKEY hsKey;
	CryptImportKey(hProv,
				   enSessionKey,
				   sLen,
				   hExchangeKey,
				   0,
				   &hsKey);

	SessionKey = hsKey;
}

PBYTE CryptoAPI::ExportKey(HCRYPTKEY hKey, HCRYPTKEY hExpKey, DWORD BlobType, DWORD *keylen)
{
	BYTE *keyData;
	CryptExportKey(hKey,
				   hExpKey,
				   BlobType,
				   0,                          
				   NULL,                       
				   keylen);

	keyData = new BYTE[(*keylen)];

	CryptExportKey(hKey,
					hExpKey,
					BlobType,
					0,
					keyData,
					keylen);

	return keyData;
}

PBYTE CryptoAPI::EncryptBuffer(BYTE *buffer, DWORD BufLen, DWORD *TotalSize)
{
	const size_t block_size = 16;
	BYTE chunk[block_size] = { 0 };

	DWORD chunk_size;
	DWORD plain_size = BufLen;
	DWORD offset = 0;
	DWORD encryption_size = BufLen;

	bool is_final = false;

	CryptEncrypt(SessionKey,
		NULL,
		TRUE,
		0,
		NULL,
		&encryption_size,
		*TotalSize);

	BYTE *result_buf = new BYTE[encryption_size];
	ZeroMemory(result_buf, sizeof(BYTE) * encryption_size);

	while (plain_size)
	{
		ZeroMemory(chunk, sizeof(BYTE) * 16);
		if (plain_size >= block_size)
		{
			memcpy(chunk, buffer + offset, block_size);
			plain_size -= block_size;
			chunk_size = block_size;
		}
		else
		{
			memcpy(chunk, buffer + offset, plain_size);
			chunk_size = plain_size;
			plain_size = 0;
			is_final = true;
		}

		CryptEncrypt(SessionKey,
			NULL,
			is_final,
			0,
			chunk,
			&chunk_size,
			block_size);

		memcpy(result_buf + offset, chunk, sizeof(BYTE) * chunk_size);
		offset += chunk_size;
	}

	*TotalSize = offset;
	return result_buf;
}


void CryptoAPI::DecryptBuffer(BYTE *buffer, DWORD *BufLen)
{
	const size_t block_size = 16;
	BYTE chunk[block_size] = { 0 };

	DWORD chunk_size;
	DWORD cipher_size = *BufLen;
	DWORD offset = 0;

	bool is_final = false;

	while (cipher_size)
	{
		ZeroMemory(chunk, sizeof(BYTE) * block_size);
		if (cipher_size > block_size)
		{
			memcpy(chunk, buffer + offset, block_size);
			cipher_size -= block_size;
			chunk_size = block_size;
		}
		else
		{
			memcpy(chunk, buffer + offset, cipher_size);
			chunk_size = cipher_size;
			cipher_size = 0;
			is_final = true;
		}

		CryptDecrypt(SessionKey,
			NULL,
			is_final,
			0,
			chunk,
			&chunk_size);

		memcpy(buffer + offset, chunk, sizeof(BYTE) * chunk_size);
		offset += chunk_size;
	}

	*BufLen = offset;
}

