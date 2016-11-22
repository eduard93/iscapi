
#define ZF_DLL

#ifndef ISC_INCLUDE_COMMON_H
#include "../Common/common.h"
#endif

static HCRYPTPROV hProv = NULL;
static HCRYPTKEY hKey = NULL;
static HCRYPTHASH hHash = NULL;
static HCRYPTKEY hSessionKey = NULL;
static HCRYPTKEY hAgreeKey = NULL;

DWORD globalProviderID = 0;
DWORD globalHashAlgID = 0;
DWORD globalSignAlgID = 0;
BOOL globalMKS = FALSE;
BOOL globalSilentFlag = TRUE;

char* globalPIN = NULL;
char* globalContainerName = NULL;
char* globalProviderName = NULL;

//static long hashAlgId = 0;
//static long provTypeId = 0;

HCRYPTPROV internalAcquireContext();

char* binaryMsg = "<will not display because binary value breaks console>";


extern int LogMessageCOS(char* msg) {
	LogMessage(msg);
	return 0;
}

int internalInit(DWORD provTypeId, DWORD algId, char *containerName, char *pin, char *providerName) {
	globalProviderID = provTypeId;
	globalPIN = strdup(pin);
	
	globalHashAlgID = algId;
	
	if ((NULL != containerName) && (strcmp(containerName, "") != 0)) {
		globalContainerName = strdup(containerName);
	}
	if ((NULL != providerName) && (strcmp(providerName, "") != 0)) {
		globalProviderName = strdup(providerName);
	}
	internalAcquireContext();
	return 0;
}

void internalReleaseContext() {
	LogMessage("Releasing context...");
	if (hProv) CryptReleaseContext(hProv, 0);
	hProv = 0;
}

HCRYPTPROV internalAcquireContext() {
	//HCRYPTPROV hCryptProv = 0;
	DWORD dwFlags = CRYPT_SILENT;
	BOOL result = FALSE;
	//char* pin;

	setLogTargets(1);

	LogMessage("internalAcquireContext called...");

	if (!globalSilentFlag) {
		dwFlags = 0;
	}

	if (globalMKS) {
		LogMessage("Using MACHINE_KEYSET");
		dwFlags |= CRYPT_MACHINE_KEYSET;
	}

	if (!globalContainerName) {
		if(TRUE == (result = CryptAcquireContext(&hProv, NULL, globalProviderName, globalProviderID, dwFlags))) {
			LogMessageFormat("Context Acquired for provType: %d", globalProviderID);
		}
	}
	else {
		if(TRUE == (result = CryptAcquireContext(&hProv, globalContainerName, NULL /* SHOULD be nULL for linux capilite! */, globalProviderID, dwFlags /* | CRYPT_SILENT */))) {
			if (globalPIN) {
				LogMessageFormat("Setting PP_SIGNATURE_PIN=%s", globalPIN);
				if (TRUE == CryptSetProvParam(hProv, PP_SIGNATURE_PIN, (LPBYTE)globalPIN, 0)) {
				    LogMessage("PP_SIGNATURE_PIN OK");
				}
				else {
				    LogError("ERROR while setting PP_SIGNATURE_PIN");
				    return 0;
				}
			}
			LogMessageFormat("Context Acquired for ProviderType=%d, ProviderName=%s, Container=%s", globalProviderID, globalProviderName, globalContainerName);
		}
	}

	if (result == FALSE) {
		LogError("Failed to Acquire CSP Context");
	}
	return hProv;
}


int internalHashData(ZARRAYP dataToHash) {

	// Create the hash object.
	if (!hHash) {
		if(CryptCreateHash(hProv, globalHashAlgID, 0, 0, &hHash)) {
			LogMessageFormat("Hash object created.");
		}
		else {
			LogError("Error during CryptCreateHash.");
			return 1;
		}
	}
	else {
		LogMessage("Hash object already exists");
	}

	// Compute the cryptographic hash of the buffer.
	if(CryptHashData(hHash, dataToHash->data, dataToHash->len, 0)) {
		LogMessageFormat("The data buffer has been hashed.");
		return 0;
	}
	else {
		LogError("Error during CryptHashData.");
	}
	return 1;
}

int internalDestroyHash() {
	if (hHash) {
		CryptDestroyHash(hHash);
		LogMessage("Hash object destroyed");
	}
	else {
		LogError("DestroyHash: Hash object does not exists (or already destroyed).");
	}
	hHash = 0;
	return 0;
}

int internalGetHashValue(ZARRAYP hashVal) {
	BYTE* pbData;
	DWORD pdwDataLen = 0;
	char buf[1024];

	if (hHash) {
		if (CryptGetHashParam(hHash, HP_HASHVAL, NULL, &pdwDataLen, 0)) {
			LogMessageFormat("Hash value data length=%d", pdwDataLen);
			pbData = (BYTE*)LocalAlloc(LMEM_ZEROINIT, pdwDataLen + 1);
			if (!CryptGetHashParam(hHash, HP_HASHVAL, pbData, &pdwDataLen, 0)) {
				LogError("CryprGetHashParam");
				LocalFree(pbData);
				internalDestroyHash();
				return 1;
			}
			else {
				LogMessage("CryptGetHashParam successed");
				ByteToZARRAY(pdwDataLen, pbData, hashVal);
				LogMessageFormat("HashValue=%s", binaryMsg /*pbData*/);

				ByteToStr(pdwDataLen, pbData, buf);
				LogMessageFormat("pbDataHex=%s", buf);
				LocalFree(pbData);
				internalDestroyHash();
				return 0;
			}
		}
		else {
			LogError("CryptGetHashParam - unable to retrieve HashValue DataLen");
		}
	}
	else {
		LogError("Hash object does not exists");
	}
	return 1;
}

int internalSignHash(ZARRAYP hashVal, ZARRAYP signVal) {
	BYTE* pbData;
	DWORD dwSigLen;
	BYTE* pbSignature;

	char buf[1024];

	if (hHash) {
		LogMessage("Destroying existing Hash object");
		internalDestroyHash();
	}

	if(CryptCreateHash(hProv, globalHashAlgID, 0, 0, &hHash)) {
		LogMessageFormat("Hash object created.");
	}
	else {
		LogError("Error during CryptCreateHash.");
		return 1;
	}

	pbData = (BYTE*)LocalAlloc(LMEM_ZEROINIT, hashVal->len);
	memcpy(pbData, hashVal->data, hashVal->len);
	if (CryptSetHashParam(hHash, HP_HASHVAL, pbData, 0)) {
		ByteToStr(hashVal->len, pbData, buf);
		LogMessageFormat("CryptSetHashParam success, HashBytes=%s", buf);
	}
	else {
		LogError("CryptSetHashParam");
		LocalFree(pbData);
		return 1;
	}
	LocalFree(pbData);

	// Determine the size of the signature and allocate memory.
	dwSigLen= 0;
	if (CryptSignHash(hHash, AT_KEYEXCHANGE, NULL, 0, NULL, &dwSigLen)) {
		LogMessageFormat("Signature length %d found.", dwSigLen);
	}
	else {
		LogError("Error during CryptSignHash for dwSigLen");
		return 1;
	}

	// Allocate memory for the signature buffer.
	pbSignature = (BYTE *)LocalAlloc(LMEM_ZEROINIT, dwSigLen);

	// Sign the hash object.
	if (CryptSignHash(hHash, AT_KEYEXCHANGE, NULL, 0, pbSignature, &dwSigLen)) {
		LogMessageFormat("SignatureValue=%s", binaryMsg /*pbSignature*/);
		ByteToStr(dwSigLen, pbSignature, buf);
		LogMessageFormat("SignatureBytes=%s", buf);
		ByteToZARRAY(dwSigLen, pbSignature, signVal);
		//ReverseByteToZARRAY(dwSigLen, pbSignature, signVal); // todo: WTF????
		//ByteToStr(signVal->len, signVal->data, buf);
		//LogMessageFormat("ReverseSignatureBytes=%S", buf);
	}
	else {
		LogError("Error during CryptSignHash.");
		LocalFree(pbSignature);
		return 1;
	}
	LocalFree(pbSignature);
	internalDestroyHash();
	return 0;
}


int internalSignCurrentHash(ZARRAYP signVal) {
	DWORD dwSigLen;
	BYTE* pbSignature;

	char buf[1024];

	LogMessage("SignExistingHash");

	// Determine the size of the signature and allocate memory.
	dwSigLen= 0;
	if (CryptSignHash(hHash, AT_KEYEXCHANGE, 0, 0, 0, &dwSigLen)) {
		LogMessageFormat("Signature length %d found.", dwSigLen);
	}
	else {
		LogError("Error during CryptSignHash for dwSigLen");
		return 1;
	}

	// Allocate memory for the signature buffer.
	pbSignature = (BYTE *)LocalAlloc(LMEM_ZEROINIT, dwSigLen);

	// Sign the hash object.
	if (CryptSignHash(hHash, AT_KEYEXCHANGE, NULL, 0, pbSignature, &dwSigLen)) {
		LogMessageFormat("SignatureValue=%s", binaryMsg /*pbSignature*/);
		ByteToStr(dwSigLen, pbSignature, buf);
		LogMessageFormat("SignatureBytes=%s", buf);
		ByteToZARRAY(dwSigLen, pbSignature, signVal);
		//memcpy(signVal, pbSignature, dwSigLen);
		//signVal[dwSigLen] = '\0';

	}
	else {
		LogError("Error during CryptSignHash.");
		LocalFree(pbSignature);
		return 1;
	}
	LocalFree(pbSignature);
	internalDestroyHash();
	return 0;
}

int internalVerifySignature(ZARRAYP hashVal, ZARRAYP signVal, int *result) {
	BYTE* pbData;
	DWORD dwSigLen;
	BYTE* pbSignature;
	char buf[1024];

	*result = 0;

	if (hHash) {
		LogMessage("Destroying existing Hash object");
		internalDestroyHash();
	}

	if(CryptCreateHash(hProv, globalHashAlgID, 0, 0, &hHash)) {
		LogMessageFormat("Hash object created.");
	}
	else {
		LogError("Error during CryptCreateHash.");
		return 1;
	}

	pbData = (BYTE*)LocalAlloc(LMEM_ZEROINIT, hashVal->len);
	memcpy(pbData, hashVal->data, hashVal->len);

	ByteToStr(hashVal->len, pbData, buf);
	LogMessageFormat("Hash Received for verifying=%s", buf);

	if (CryptSetHashParam(hHash, HP_HASHVAL, pbData, 0)) {
		LogMessage("CryptSetHashParam success");
	}
	else {
		LogError("CryptSetHashParam");
		LocalFree(pbData);
		return 1;
	}
	LocalFree(pbData);

	//Verify Signature
	if(!CryptGetUserKey(hProv, AT_KEYEXCHANGE, &hKey)) {
		LogError("CryptGetUserKey");
		LocalFree(pbData);
		return 1;
	}
	else {
		LogMessage("CryptGetUserKey: public key acquired");
	}

	dwSigLen = signVal->len;
	pbSignature = (BYTE *)LocalAlloc(LMEM_ZEROINIT, dwSigLen);
	memcpy(pbSignature, signVal->data, dwSigLen);
	
	ByteToStr(dwSigLen, pbSignature, buf);
	LogMessageFormat("Signature received=%s", buf);

	if (CryptVerifySignature(hHash, pbSignature, dwSigLen, hKey, NULL, 0)) {
		LogMessage("Signature is verified");
		*result = 1;
	}
	else {
		LogError("Signature is NOT verified");
	}
	LocalFree(pbSignature);
	CryptDestroyKey(hKey);
	internalDestroyHash();

	return 0;
}

int internalVerifySignatureByKey(ZARRAYP hashVal, ZARRAYP signVal, ZARRAYP pubKey, int *result) {
	BYTE* pbData;
	//DWORD dwSigLen;
	//BYTE* pbSignature;
	char buf[1024];

	*result = 0;

	if (hHash) {
		LogMessage("Destroying existing Hash object");
		internalDestroyHash();
	}

	if(CryptCreateHash(hProv, globalHashAlgID, 0, 0, &hHash)) {
		LogMessageFormat("Hash object created.");
	}
	else {
		LogError("Error during CryptCreateHash.");
		return 1;
	}

	pbData = (BYTE*)LocalAlloc(LMEM_ZEROINIT, hashVal->len);
	memcpy(pbData, hashVal->data, hashVal->len);

	ByteToStr(hashVal->len, pbData, buf);
	LogMessageFormat("Hash Received for verifying=%s", buf);

	if (CryptSetHashParam(hHash, HP_HASHVAL, pbData, 0)) {
		LogMessage("CryptSetHashParam success");
	}
	else {
		LogError("CryptSetHashParam");
		LocalFree(pbData);
		return 1;
	}
	LocalFree(pbData);

	//Verify Signature
	if (!CryptImportKey(hProv, pubKey->data, pubKey->len, 0, 0, &hKey)) {
		LogError("CryptImportKey");
		return 1;
	}
	else {
		LogMessage("CryptImportKey: key imported");
	}

	ByteToStr(signVal->len, signVal->data, buf);
	LogMessageFormat("Signature received=%s", buf);

	if (CryptVerifySignature(hHash, signVal->data, signVal->len, hKey, NULL, 0)) {
		LogMessage("Signature is verified");
		*result = 1;
	}
	else {
		LogError("Signature is NOT verified");
	}
	CryptDestroyKey(hKey);
	internalDestroyHash();

	return 0;
}


int internalExportUserKey(ZARRAYP keyVal) {
	BYTE* pbKeyBlob;
	DWORD dwBlobLen = 0;

	char buf[1024];

	if (!CryptGetUserKey(hProv, AT_KEYEXCHANGE, &hKey)) {
		LogError("GetUserKey");
		return 1;
	}

	if(CryptExportKey(hKey, 0, PUBLICKEYBLOB, 0, NULL, &dwBlobLen)) {
		LogMessageFormat("Size of the BLOB for the public key=%d", dwBlobLen);
	}
	else {
		LogError("CryptExportKey: Error computing BLOB length");
	}

	pbKeyBlob = (BYTE*)LocalAlloc(LMEM_ZEROINIT, dwBlobLen);

	if(CryptExportKey(hKey, 0, PUBLICKEYBLOB, 0, pbKeyBlob, &dwBlobLen)) {
		ByteToStr(dwBlobLen, pbKeyBlob, buf);
		LogMessageFormat("Contents has been written to the BLOB, = %s", buf);
		ByteToZARRAY(dwBlobLen, pbKeyBlob, keyVal);
		LocalFree(pbKeyBlob);
	}
	else {
		LogError("Error during CryptExportKey");
		LocalFree(pbKeyBlob);
		return 1;
	}	
	return 0;
}

int internalExportCertificate(ZARRAYP certVal) {
	BYTE* pbKeyBlob;
	DWORD dwBlobLen = 0;

	char buf[32000];
	    
	if (!CryptGetUserKey(hProv, AT_KEYEXCHANGE, &hKey)) {
		LogError("GetUserKey");
		return 1;
	}

        if(CryptGetKeyParam(hKey, KP_CERTIFICATE, NULL, &dwBlobLen, 0)) {
		LogMessageFormat("Size of the BLOB for the public key=%d", dwBlobLen);
	}
	else {
		LogError("CryptGetKeyParam: Error computing BLOB length");
		return 1;
	}

	pbKeyBlob = (BYTE*)LocalAlloc(LMEM_ZEROINIT, dwBlobLen);
	if(CryptGetKeyParam(hKey, KP_CERTIFICATE, pbKeyBlob, &dwBlobLen, 0)) {
		ByteToStr(dwBlobLen, pbKeyBlob, buf);
		LogMessageFormat("Certificate has been written to the BLOB, = %s", buf);
		ByteToZARRAY(dwBlobLen, pbKeyBlob, certVal);
		LocalFree(pbKeyBlob);
	}
	else {
		LogError("Error during CryptGetKetParam KP_CERTIFICATE");
		LocalFree(pbKeyBlob);
		return 1;
	}
	return 0;
}


// http://www.rsdn.org/article/crypto/usingcryptoapi.xml#EFKAC

int internalEncryptData(ZARRAYP data, ZARRAYP encryptedData) {
	DWORD count;
	PBYTE pbData;
	
	char buf[32000];

	// Генерация сессионного ключа
	if (hSessionKey) CryptDestroyKey(hSessionKey);
	if (!CryptGenKey(hProv, CALG_G28147, CRYPT_EXPORTABLE, &hSessionKey)) {
      		LogError("CryptGenKey");
        	return 1;
        }
        LogMessage("Generated SessionKey"); 
	
	// Выделение памяти под буфер
	pbData = (BYTE*)LocalAlloc(LMEM_ZEROINIT, data->len);
	memcpy(pbData, data->data, data->len);

	// Протоколирование оригинальных данных
	ByteToStr(data->len, pbData, buf);
	LogMessageFormat("Data Received for encrypting=%s", buf);
	
	// Шифрование
	count = data->len;
	if (!CryptEncrypt(hSessionKey, 0, TRUE, 0, pbData, &count, data->len)) {
		LogError("CryptEncrypt");
		LocalFree(pbData);
        	return 1;
        }
        LogMessageFormat("Received bufLen = %d", count);

	// Протоколирование шифрованных  данных
	ByteToStr(data->len, pbData, buf);
	LogMessageFormat("Encrypted Data = %s", buf);
        
        ByteToZARRAY(count, pbData, encryptedData);
        LocalFree(pbData);

 	return 0;
}

int internalExportSessionKey(ZARRAYP publicKeyBlob, ZARRAYP encryptedSessionKey) {

	DWORD count = 0;
	PBYTE pbData;
	PBYTE pbBlob;
	
	// Получение ключа для экспорта ключа шифрования
	if (hKey) CryptDestroyKey(hKey);
	if (!CryptGetUserKey(hProv, AT_KEYEXCHANGE, &hKey)) {
		LogError("CryptGetUserKey");
		return 1;
	}

	// Импорт ключа
	pbBlob = (BYTE*)LocalAlloc(LMEM_ZEROINIT, publicKeyBlob->len);
	memcpy(pbBlob, publicKeyBlob->data, publicKeyBlob->len);
	
	if (hAgreeKey) CryptDestroyKey(hAgreeKey);
	
	if (!CryptImportKey(hProv, pbBlob, publicKeyBlob->len, hKey, 0, &hAgreeKey)) {
		LogError("CryptImportKey");
		LocalFree(pbBlob);
		return 1;
	}
	else {
		LogMessage("+ CryptImportKey");
	}
	LocalFree(pbBlob);
	
	// Получение размера массива, используемого для экспорта ключа
	if (!CryptExportKey(hSessionKey, hAgreeKey, SIMPLEBLOB, 0, NULL, &count)) {
		LogError("CryptExportKey: length"); 
  		return 1;
  	}
  
  	// Инициализация массива, используемого для экспорта ключа
	pbData = (BYTE*)LocalAlloc(LMEM_ZEROINIT, count);

 	// Экспорт ключа шифрования
 	if (!CryptExportKey(hSessionKey, hAgreeKey, SIMPLEBLOB, 0, pbData, &count)) { 
		LogError("CryptExportKey");
		LocalFree(pbData);
		return 1;
	}

	ByteToZARRAY(count, pbData, encryptedSessionKey);
	LocalFree(pbData);
	if (hSessionKey) CryptDestroyKey(hSessionKey);
	if (hAgreeKey) CryptDestroyKey(hAgreeKey);
	
	return 0;

}

int internalDecryptData(ZARRAYP encryptedData, ZARRAYP encryptedSessionKey, ZARRAYP senderPublicKeyBlob, ZARRAYP decryptedData) {
	
	BYTE pbData[32000];
	DWORD len;
	
	// Получение ключа для расшифровки сессионых ключей
	if (hKey) CryptDestroyKey(hKey);
	if (!CryptGetUserKey(hProv, AT_KEYEXCHANGE, &hKey)) {
		LogError("CryptGetUserKey");
		return 1;
	}
	LogMessage("Private exchange key loaded");

	// Получение ключа согласования импортом открытого ключа отправителя на закрытом ключе получателя.
	if (hAgreeKey) CryptDestroyKey(hAgreeKey);
	if(!CryptImportKey(hProv, senderPublicKeyBlob->data, senderPublicKeyBlob->len, hKey, 0, &hAgreeKey)) {
		LogError("CryptImportKey: hAgreeKey");
		return 1;
	}
	LogMessage("hAgreeKey imported");

	// Получение сессионного ключа импортом зашифрованного сессионного ключа на ключе Agree.
	if (hSessionKey) CryptDestroyKey(hSessionKey);
	if(!CryptImportKey(hProv, encryptedSessionKey->data, encryptedSessionKey->len, hAgreeKey, 0, &hSessionKey)) {
		LogError("CryptImportKey: hSessionKey");
		return 1;
	}
	
	// Расшифровка данных
	memcpy(pbData, encryptedData->data, encryptedData->len);
	len = encryptedData->len;
	if(!CryptDecrypt(hSessionKey, 0, TRUE, 0, pbData, &len)) {
		LogError("CryptDecrypt");
	}
	LogMessageFormat("Decrypted length = %d", len);
	LogMessageFormat("Decrypted data = %s", pbData);
	
	// Возвращаем результат
	ByteToZARRAY(len, pbData, decryptedData);
  	
  	return 0;

}

int internalReleaseAll() {
	internalDestroyHash();
	internalReleaseContext();
	return 0;
}

int internalInitLogger(char* logFileName, int logLevel, int logTargets) {
	setLogFileName(logFileName);
	setLogLevel(logLevel);
	setLogTargets(logTargets);
	setLogSourceLocation(1);
	return 0;
}

ZFBEGIN
	ZFENTRY("Init", "iiccc", internalInit)
	ZFENTRY("InitLogger", "cii", internalInitLogger)
	ZFENTRY("HashData", "b", internalHashData)
	ZFENTRY("GetHashValue", "B", internalGetHashValue)
	ZFENTRY("SignHash", "bB", internalSignHash)
	ZFENTRY("SignCurrentHash", "B", internalSignCurrentHash)
	ZFENTRY("VerifyHash", "bbP", internalVerifySignature)
	ZFENTRY("VerifyHashByKey", "bbbP", internalVerifySignatureByKey)
	ZFENTRY("ExportUserKey", "B", internalExportUserKey)
	ZFENTRY("ExportCertificate", "B", internalExportCertificate)
	ZFENTRY("EncryptData", "bB", internalEncryptData)
	ZFENTRY("ExportSessionKey", "bB", internalExportSessionKey)
	ZFENTRY("DecryptData", "bbbB", internalDecryptData)
	ZFENTRY("LogMessage", "w", LogMessageCOS)
	ZFENTRY("Release", "", internalReleaseAll)
ZFEND

//ZFENTRY("SetLogFileName", "w", setLogFileName)
//ZFENTRY("SetLogTargets", "i", setLogTargets)

