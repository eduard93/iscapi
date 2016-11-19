
#define ZF_DLL

#ifndef ISC_INCLUDE_COMMON_H
#include "..\Common\common.h"
#endif

static HCRYPTPROV hProv;
static HCRYPTKEY hKey;
static HCRYPTHASH hHash;

DWORD globalProviderID = 0;
DWORD globalHashAlgID = 0;
DWORD globalSignAlgID = 0;
BOOL globalMKS = FALSE;
BOOL globalSilentFlag = TRUE;

wchar_t* globalPIN = NULL;
wchar_t* globalContainerName = NULL;
wchar_t* globalProviderName = NULL;

//static long hashAlgId = 0;
//static long provTypeId = 0;

HCRYPTPROV internalAcquireContext();


extern int LogMessageCOS(wchar_t* msg) {
	LogMessage(msg);
	return 0;
}

int internalInit(DWORD provTypeId, DWORD algId, wchar_t *containerName, wchar_t *pin, wchar_t *providerName) {
	globalProviderID = provTypeId;
	globalPIN = _wcsdup(pin);
	
	globalHashAlgID = algId;
	
	if ((NULL != containerName) && (wcscmp(containerName, L"") != 0)) {
		globalContainerName = _wcsdup(containerName);
	}
	if ((NULL != providerName) && (wcscmp(providerName, L"") != 0)) {
		globalProviderName = _wcsdup(providerName);
	}
	internalAcquireContext();
	return 0;
}

void internalReleaseContext() {
	LogMessage(L"Releasing context...");
	if (hProv) {
		CryptReleaseContext(hProv, 0);
	}
	hProv = 0;
	//logLastError();
}

HCRYPTPROV internalAcquireContext() {
	//HCRYPTPROV hCryptProv = 0;
	DWORD dwFlags = CRYPT_SILENT;
	BOOL result = FALSE;
	char* pin;

	setLogTargets(1);

	LogMessage(L"internalAcquireContext called...");

	if (!globalSilentFlag) {
		dwFlags = 0;
	}

	if (globalMKS) {
		LogMessage(L"Using MACHINE_KEYSET");
		dwFlags |= CRYPT_MACHINE_KEYSET;
	}

	if (!globalContainerName) {
		if(TRUE == (result = CryptAcquireContext(&hProv, NULL, globalProviderName, globalProviderID, dwFlags))) {
			LogMessageFormat(L"Context Acquired for provType: %d", globalProviderID);
		}
	}
	else {
		if(TRUE == (result = CryptAcquireContext(&hProv, globalContainerName, globalProviderName, globalProviderID, dwFlags /* | CRYPT_SILENT */))) {
			if (globalPIN) {
				pin = (char *)LocalAlloc(LMEM_ZEROINIT, wcslen(globalPIN)+1);
				wcstombs(pin, globalPIN, wcslen(globalPIN)+1);
				LogMessageFormat(L"Setting SIGNATURE_PIN=%s", globalPIN);
				//LogMessageFormat(L"Setting SIGNATURE_PIN=%s", L"111111");
				CryptSetProvParam(hProv, PP_SIGNATURE_PIN, (LPBYTE)pin, 0);
				LocalFree(pin);
			}
			LogMessageFormat(L"Context Acquired for ProviderType=%d, ProviderName=%s, Container=%s", globalProviderID, globalProviderName, globalContainerName);
		}
	}

	if (result == FALSE) {
		LogError(L"Failed to Acquire CSP Context");
	}

	//CryptSetProvParam(

	return hProv;
}


int internalHashData(ZARRAYP dataToHash) {

	// Create the hash object.
	if (!hHash) {
		if(CryptCreateHash(hProv, globalHashAlgID, 0, 0, &hHash)) {
			LogMessageFormat(L"Hash object created.");
		}
		else {
			LogError(L"Error during CryptCreateHash.");
			return 1;
		}
	}
	else {
		LogMessage(L"Hash object already exists");
	}

	// Compute the cryptographic hash of the buffer.
	if(CryptHashData(hHash, dataToHash->data, dataToHash->len, 0)) {
		LogMessageFormat(L"The data buffer has been hashed.");
		return 0;
	}
	else {
		LogError(L"Error during CryptHashData.");
	}
	return 1;
}

int internalDestroyHash() {
	if (hHash) {
		CryptDestroyHash(hHash);
		LogMessage(L"Hask object destroyed");
	}
	else {
		LogError(L"DestroyHash: Hash object does not exists (or already destroyed).");
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
			LogMessageFormat(L"Hash value data length=%d", pdwDataLen);
			pbData = (BYTE*)LocalAlloc(LMEM_ZEROINIT, pdwDataLen + 1);
			if (!CryptGetHashParam(hHash, HP_HASHVAL, pbData, &pdwDataLen, 0)) {
				LogError(L"CryprGetHashParam");
				LocalFree(pbData);
				internalDestroyHash();
				return 1;
			}
			else {
				LogMessage(L"CryptGetHashParam successed");
				ByteToZARRAY(pdwDataLen, pbData, hashVal);
				LogMessageFormat(L"HashValue=%S", pbData);

				ByteToStr(pdwDataLen, pbData, buf);
				LogMessageFormat(L"pbDataHex=%S", buf);
				LocalFree(pbData);
				internalDestroyHash();
				return 0;
			}
		}
		else {
			LogError(L"CryptGetHashParam - unable to retrieve HashValue DataLen");
		}
	}
	else {
		LogError(L"Hash object does not exists");
	}
	return 1;
}

int internalSignHash(ZARRAYP hashVal, ZARRAYP signVal) {
	BYTE* pbData;
	DWORD dwSigLen;
	BYTE* pbSignature;

	char buf[1024];

	if (hHash) {
		LogMessage(L"Destroying existing Hash object");
		internalDestroyHash();
	}

	if(CryptCreateHash(hProv, globalHashAlgID, 0, 0, &hHash)) {
		LogMessageFormat(L"Hash object created.");
	}
	else {
		LogError(L"Error during CryptCreateHash.");
		return 1;
	}

	pbData = (BYTE*)LocalAlloc(LMEM_ZEROINIT, hashVal->len);
	memcpy(pbData, hashVal->data, hashVal->len);
	if (CryptSetHashParam(hHash, HP_HASHVAL, pbData, 0)) {
		ByteToStr(hashVal->len, pbData, buf);
		LogMessageFormat(L"CryptSetHashParam success, HashBytes=%S", buf);
	}
	else {
		LogError(L"CryptSetHashParam");
		LocalFree(pbData);
		return 1;
	}
	LocalFree(pbData);

	// Determine the size of the signature and allocate memory.
	dwSigLen= 0;
	if (CryptSignHash(hHash, AT_KEYEXCHANGE, 0, 0, 0, &dwSigLen)) {
		LogMessageFormat(L"Signature length %d found.", dwSigLen);
	}
	else {
		LogError(L"Error during CryptSignHash for dwSigLen");
		return 1;
	}

	// Allocate memory for the signature buffer.
	pbSignature = (BYTE *)LocalAlloc(LMEM_ZEROINIT, dwSigLen);

	// Sign the hash object.
	if (CryptSignHash(hHash, AT_KEYEXCHANGE, NULL, 0, pbSignature, &dwSigLen)) {
		LogMessageFormat(L"SignatureValue=%S", pbSignature);
		ByteToStr(dwSigLen, pbSignature, buf);
		LogMessageFormat(L"SignatureBytes=%S", buf);
		ByteToZARRAY(dwSigLen, pbSignature, signVal);
		//ReverseByteToZARRAY(dwSigLen, pbSignature, signVal); // todo: WTF????
		//ByteToStr(signVal->len, signVal->data, buf);
		//LogMessageFormat(L"ReverseSignatureBytes=%S", buf);
	}
	else {
		LogError(L"Error during CryptSignHash.");
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

	LogMessage(L"SignExistingHash");

	// Determine the size of the signature and allocate memory.
	dwSigLen= 0;
	if (CryptSignHash(hHash, AT_KEYEXCHANGE, 0, 0, 0, &dwSigLen)) {
		LogMessageFormat(L"Signature length %d found.", dwSigLen);
	}
	else {
		LogError(L"Error during CryptSignHash for dwSigLen");
		return 1;
	}

	// Allocate memory for the signature buffer.
	pbSignature = (BYTE *)LocalAlloc(LMEM_ZEROINIT, dwSigLen);

	// Sign the hash object.
	if (CryptSignHash(hHash, AT_KEYEXCHANGE, NULL, 0, pbSignature, &dwSigLen)) {
		LogMessageFormat(L"SignatureValue=%S", pbSignature);
		ByteToStr(dwSigLen, pbSignature, buf);
		LogMessageFormat(L"SignatureBytes=%S", buf);
		ByteToZARRAY(dwSigLen, pbSignature, signVal);
		//memcpy(signVal, pbSignature, dwSigLen);
		//signVal[dwSigLen] = '\0';

	}
	else {
		LogError(L"Error during CryptSignHash.");
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
		LogMessage(L"Destroying existing Hash object");
		internalDestroyHash();
	}

	if(CryptCreateHash(hProv, globalHashAlgID, 0, 0, &hHash)) {
		LogMessageFormat(L"Hash object created.");
	}
	else {
		LogError(L"Error during CryptCreateHash.");
		return 1;
	}

	pbData = (BYTE*)LocalAlloc(LMEM_ZEROINIT, hashVal->len);
	memcpy(pbData, hashVal->data, hashVal->len);

	ByteToStr(hashVal->len, pbData, buf);
	LogMessageFormat(L"Hash Received for verifying=%S", buf);

	if (CryptSetHashParam(hHash, HP_HASHVAL, pbData, 0)) {
		LogMessage(L"CryptSetHashParam success");
	}
	else {
		LogError(L"CryptSetHashParam");
		LocalFree(pbData);
		return 1;
	}
	LocalFree(pbData);

	//Verify Signature
	if(!CryptGetUserKey(hProv, AT_KEYEXCHANGE, &hKey)) {
		LogError(L"CryptGetUserKey");
		LocalFree(pbData);
		return 1;
	}
	else {
		LogMessage(L"CryptGetUserKey: public key acquired");
	}

	dwSigLen = signVal->len;
	pbSignature = (BYTE *)LocalAlloc(LMEM_ZEROINIT, dwSigLen);
	memcpy(pbSignature, signVal->data, dwSigLen);
	
	ByteToStr(dwSigLen, pbSignature, buf);
	LogMessageFormat(L"Signature received=%S", buf);

	if (CryptVerifySignature(hHash, pbSignature, dwSigLen, hKey, NULL, 0)) {
		LogMessage(L"Signature is verified");
		*result = 1;
	}
	else {
		LogError(L"Signature is NOT verified");
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
		LogMessage(L"Destroying existing Hash object");
		internalDestroyHash();
	}

	if(CryptCreateHash(hProv, globalHashAlgID, 0, 0, &hHash)) {
		LogMessageFormat(L"Hash object created.");
	}
	else {
		LogError(L"Error during CryptCreateHash.");
		return 1;
	}

	pbData = (BYTE*)LocalAlloc(LMEM_ZEROINIT, hashVal->len);
	memcpy(pbData, hashVal->data, hashVal->len);

	ByteToStr(hashVal->len, pbData, buf);
	LogMessageFormat(L"Hash Received for verifying=%S", buf);

	if (CryptSetHashParam(hHash, HP_HASHVAL, pbData, 0)) {
		LogMessage(L"CryptSetHashParam success");
	}
	else {
		LogError(L"CryptSetHashParam");
		LocalFree(pbData);
		return 1;
	}
	LocalFree(pbData);

	//Verify Signature
	if (!CryptImportKey(hProv, pubKey->data, pubKey->len, 0, 0, &hKey)) {
		LogError(L"CryptImportKey");
		return 1;
	}
	else {
		LogMessage(L"CryptImportKey: key imported");
	}

	ByteToStr(signVal->len, signVal->data, buf);
	LogMessageFormat(L"Signature received=%S", buf);

	if (CryptVerifySignature(hHash, signVal->data, signVal->len, hKey, NULL, 0)) {
		LogMessage(L"Signature is verified");
		*result = 1;
	}
	else {
		LogError(L"Signature is NOT verified");
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
		LogError(L"GetUserKey");
		return 1;
	}

	if(CryptExportKey(hKey, 0, PUBLICKEYBLOB, 0, NULL, &dwBlobLen)) {
		LogMessageFormat(L"Size of the BLOB for the public key=%d", dwBlobLen);
	}
	else {
		LogError(L"CryptExportKey: Error computing BLOB length");
	}

	pbKeyBlob = (BYTE*)LocalAlloc(LMEM_ZEROINIT, dwBlobLen);

	if(CryptExportKey(hKey, 0, PUBLICKEYBLOB, 0, pbKeyBlob, &dwBlobLen)) {
		ByteToStr(dwBlobLen, pbKeyBlob, buf);
		LogMessageFormat(L"Contents has been written to the BLOB, = %S", buf);
		ByteToZARRAY(dwBlobLen, pbKeyBlob, keyVal);
	}
	else {
		LogError(L"Error during CryptExportKey");
		LocalFree(pbKeyBlob);
		return 1;
	}	
	return 0;
}

int internalReleaseAll() {
	internalDestroyHash();
	internalReleaseContext();
	return 0;
}

int internalInitLogger(wchar_t* logFileName, int logLevel, int logTargets) {
	setLogFileName(logFileName);
	setLogLevel(logLevel);
	setLogTargets(logTargets);
	setLogSourceLocation(0);
	return 0;
}

ZFBEGIN
	ZFENTRY("Init", "iiwww", internalInit)
	ZFENTRY("InitLogger", "wii", internalInitLogger)
	ZFENTRY("HashData", "b", internalHashData)
	ZFENTRY("GetHashValue", "B", internalGetHashValue)
	ZFENTRY("SignHash", "bB", internalSignHash)
	ZFENTRY("SignCurrentHash", "B", internalSignCurrentHash)
	ZFENTRY("VerifyHash", "bbP", internalVerifySignature)
	ZFENTRY("VerifyHashByKey", "bbbP", internalVerifySignatureByKey)
	ZFENTRY("ExportUserKey", "B", internalExportUserKey)
	ZFENTRY("LogMessage", "w", LogMessageCOS)
	ZFENTRY("Release", "", internalReleaseAll)
ZFEND

//ZFENTRY("SetLogFileName", "w", setLogFileName)
//ZFENTRY("SetLogTargets", "i", setLogTargets)

