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
	DWORD slast = BufLen;
	CryptEncrypt(SessionKey,
				NULL,
				TRUE,
				0,
				NULL,
				&BufLen,
				*TotalSize);

	BYTE *result_buf = new BYTE[BufLen];
	std::copy_n(buffer, slast, result_buf);
	
	(*TotalSize) = BufLen;

	CryptEncrypt(SessionKey,
			NULL,
			TRUE,
			0,
			result_buf,
			&slast,
			*TotalSize);

	return result_buf;
}

void CryptoAPI::DecryptBuffer(BYTE *buffer, DWORD *BufLen)
{
	 CryptDecrypt(SessionKey,
				NULL,
				0,
				FALSE,
				buffer,
				BufLen);
}

