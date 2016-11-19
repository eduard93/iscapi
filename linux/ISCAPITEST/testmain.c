
#ifndef ISC_INCLUDE_COMMON_H
#include "../Common/common.h"
#endif

DWORD globalProviderID = 0;
DWORD globalHashAlgID = 0;
DWORD globalSignAlgID = 0;
BOOL globalMKS = FALSE;
BOOL globalSilentFlag = TRUE;
char* globalPIN = NULL;
char* globalContainerName = NULL;
char* testData = NULL;
char* globalProviderName = "\\\\.\\HDIMAGE\\test";


int command = 0;

const char* testCN = "c:/air/rnd-1-1734-1a0d-e0ab-6c69-d7ae-c092-c152";


HCRYPTPROV fullAC(DWORD provType) {
	HCRYPTPROV hCryptProv = 0;
	DWORD dwFlags = CRYPT_SILENT;
	BOOL result = FALSE;
	//char* pin;

	LogMessage("FullAC called...");

	if (globalMKS) {
		LogMessage("Using MACHINE_KEYSET");
		dwFlags |= CRYPT_MACHINE_KEYSET;
	}

	if (!globalSilentFlag) {
		dwFlags = 0;
	}

	if (!globalContainerName) {
		if(TRUE == (result = CryptAcquireContext(&hCryptProv, NULL, NULL, provType, dwFlags))) {
			LogMessageFormat("Context Acquired for provType: %d", provType);
		}
	}
	else {
		if(TRUE == (result = CryptAcquireContext(&hCryptProv, globalContainerName, NULL, provType, dwFlags /* | CRYPT_SILENT */))) {
			if (globalPIN) {
				//pin = (char *)LocalAlloc(LMEM_ZEROINIT, strlen(globalPIN)+1);
				//wcstombs(pin, globalPIN, wcslen(globalPIN)+1);
				LogMessageFormat("Setting SIGNATURE_PIN=%s", globalPIN);
				//LogMessageFormat(L"Setting SIGNATURE_PIN=%s", L"111111");
				CryptSetProvParam(hCryptProv, PP_SIGNATURE_PIN, (LPBYTE)globalPIN, 0);
				//LocalFree(pin);
			}
			LogMessageFormat("Context Acquired for provType=%d, Container=%s", provType, globalContainerName);
		}
	}

	if (result == FALSE) {
		LogError("Failed to Acquire CSP Context");
	}

	return hCryptProv;
}

void simpleRC(HCRYPTPROV hCryptProv) {
	LogMessage("Releasing context...");
	if (hCryptProv) {
		CryptReleaseContext(hCryptProv, 0);
	}
	logLastError();
}



void showProviders() {
	DWORD dwIndex=0;
	DWORD dwType;
	DWORD cbName;
	LPTSTR pszName;

	LogMessage("EnumProviders: ");

	while (CryptEnumProviders(dwIndex, NULL, 0, &dwType, NULL, &cbName)) {
		if (!cbName) break;

		if (!(pszName = (LPTSTR)LocalAlloc(LMEM_ZEROINIT, cbName))) return;

		if (!CryptEnumProviders(dwIndex++, NULL, 0, &dwType, pszName, &cbName)) { 
			LogError("CryptEnumProviders");
			return;
		}
		LogMessageFormat("Provider Name: %s, Type: %d", pszName, dwType);
		LocalFree(pszName);
	}
	logLastError();
}

HCRYPTPROV simpleAC(DWORD provType) {
	HCRYPTPROV hCryptProv = 0;
	DWORD dwFlags = CRYPT_VERIFYCONTEXT;
	BOOL result = FALSE;

	LogMessage("simpleAC called...");

	if (globalMKS) {
		LogMessage("Using MACHINE_KEYSET");
		dwFlags |= CRYPT_MACHINE_KEYSET;
	}

	if (!globalContainerName) {
		printf("888"); exit(0);
		if(TRUE == (result = CryptAcquireContext(&hCryptProv, "\\\\.\\HDIMAGE\\.test", globalProviderName, provType, dwFlags))) {
			LogMessageFormat("Context Acquired for provType: %d", provType);
		}
	}
	else {
	    printf("777"); exit(0);
		if(TRUE == (result = CryptAcquireContext(&hCryptProv, globalContainerName, globalProviderName, provType, dwFlags))) {
			LogMessageFormat("Context Acquired for provType=%d, Container=%s", provType, globalContainerName);
		}
	}

	if (!result) {
		LogError("Failed to Acquire CSP Context");
	}

	return hCryptProv;
}


void showProviderContainers() {
	DWORD dwIndex=0;
	BYTE pbData[1024];
	BOOL fMore = TRUE;
	HCRYPTPROV hCryptProv = 0;
	DWORD cbData = 1024;
	DWORD dwFlags = CRYPT_FIRST;
	CHAR* pszAlgType = NULL;

	DWORD provType = globalProviderID;

	if (provType == 0) {
		LogMessage("No ProviderType specified, please use /pid switch. Exiting");
		exit(1);
	}

	LogMessageFormat("Containers for Provider Type=%d", provType);

	hCryptProv = simpleAC(provType);

	if (!hCryptProv) {
		LogError("Context isn't acquired");
		return;
	}

	// Provider Name
	if(CryptGetProvParam(hCryptProv, PP_NAME, pbData, &cbData, 0)) {
		LogMessageFormat("Provider Name=%S", pbData);
	}
	else {
		LogError("Error getting ProvName");
		return;
	}

	// Enumerate containers

	LogMessage("Enumerating the containers available:");

	cbData = 1024;
	dwFlags = CRYPT_FIRST;
	while(fMore) {
		if(CryptGetProvParam(hCryptProv, PP_ENUMCONTAINERS, pbData, &cbData, dwFlags)) {       
			dwFlags = CRYPT_NEXT;
			LogMessageFormat("%S", pbData);
		}
		else
		{
			fMore = FALSE;
		}
	}
	simpleRC(hCryptProv);
}


void showProviderParams() {
	DWORD dwIndex=0;
	BYTE pbData[1024];
	BOOL fMore = TRUE;
	HCRYPTPROV hCryptProv = 0;
	BYTE* ptr;
	ALG_ID aiAlgid;
	DWORD dwBits;
	DWORD dwNameLen;
	CHAR szName[100];
	DWORD cbData = 1024;
	DWORD dwIncrement = sizeof(DWORD);
	DWORD dwFlags = CRYPT_FIRST;
	DWORD dwParam = PP_CLIENT_HWND;
	CHAR* pszAlgType = NULL;

	DWORD provType = globalProviderID;
	
	if (provType == 0) {
		LogMessage("No ProviderType specified, please use /pid switch. Exiting");
		exit(1);
	}

	LogMessage("Provider Params: ");

	hCryptProv = simpleAC(provType);

	if (!hCryptProv) {
		LogError("Context isn't acquired");
		return;
	}

	// Provider Name
	if(CryptGetProvParam(hCryptProv, PP_NAME, pbData, &cbData, 0)) {
		LogMessageFormat("Provider Name=%S", pbData);
	}
	else {
		LogError("Error getting ProvName");
		return;
	}

	// Default Container
	cbData = 1024;
	if(CryptGetProvParam(hCryptProv, PP_CONTAINER, pbData, &cbData, 0)) {
		LogMessageFormat("Default Container=%S", pbData);
	}
	else {
		LogError("Error getting default Container");
	}

	// Enumerate Algs

	LogMessage("Enumerating the supported algorithms");

	LogMessage("     Algid      Bits    Type               Name");
	LogMessage("    _________________________________________________________");

	cbData = 1024;
	dwFlags = CRYPT_FIRST;
	while(fMore) {
		if(CryptGetProvParam(hCryptProv, PP_ENUMALGS, pbData, &cbData, dwFlags)) {       
			dwFlags = CRYPT_NEXT;
			ptr = pbData;
			aiAlgid = *(ALG_ID *)ptr;
			ptr += sizeof(ALG_ID);
			dwBits = *(DWORD *)ptr;
			ptr += dwIncrement;
			dwNameLen = *(DWORD *)ptr;
			ptr += dwIncrement;
			strncpy(szName, /*sizeof(szName), */ (char *) ptr,  dwNameLen);

			//-------------------------------------------------------
			// Determine the algorithm type.
			switch(GET_ALG_CLASS(aiAlgid)) {
			case ALG_CLASS_DATA_ENCRYPT: 
				pszAlgType = "Encrypt  ";
				break;

			case ALG_CLASS_HASH:         
				pszAlgType = "Hash     ";
				break;

			case ALG_CLASS_KEY_EXCHANGE: 
				pszAlgType = "Exchange ";
				break;

			case ALG_CLASS_SIGNATURE:
				pszAlgType = "Signature";
				break;

			default:
				pszAlgType = "Unknown  ";
				break;
			}

			LogMessageFormat("    %8.8d    %-4d    %S          %S",
				aiAlgid, 
				dwBits, 
				pszAlgType, 
				szName);
		}
		else
		{
			fMore = FALSE;
		}
	}

	simpleRC(hCryptProv);
}



BYTE* doHashAndSign() {
	HCRYPTPROV hProv = 0;
	HCRYPTHASH hHash = 0, hHash2 = 0;
	HCRYPTKEY hKey = 0;	
	//HCRYPTKEY hPubKey;

	BYTE *pbSignature;
	DWORD dwSigLen;

	BYTE* pbData;
	DWORD pdwDataLen = 0;

	char* data, *hashVal;

	char buf[4096];

	if (!testData || !globalProviderID || !globalHashAlgID) {
		LogMessageFormat(L"Either Data (/data), ProviderID (/pid) or HashAlgID (/hid) isn't specified");
		return 0;
	}

	if (!globalContainerName) LogMessage(L"Using Default container (or specify your own by /cn switch"); 

	hProv = fullAC(globalProviderID);


	// Create the hash object.
	if(CryptCreateHash(hProv, globalHashAlgID, 0, 0, &hHash)) {
		LogMessageFormat(L"Hash object created.");
	}
	else {
		LogError(L"Error during CryptCreateHash.");
	}

	// Compute the cryptographic hash of the buffer.
	data = (char*)LocalAlloc(LMEM_ZEROINIT, wcslen(testData));
	wcstombs(data, testData, wcslen(testData));
	if(CryptHashData(hHash, (BYTE *)data, wcslen(testData), 0)) {
		LogMessage(L"The data buffer has been hashed.");
	}
	else {
		LogError(L"Error during CryptHashData.");
	}
	LocalFree(data);

	if (!hHash) {
		LogError(L"No hHash received, exiting");
		return 0;
	}

	if (!CryptDuplicateHash(hHash, NULL, 0, &hHash2)) {
		LogError(L"CryptDuplicateHash");
		return 0;
	}
	
	// Show the hash value
	if (hHash2) {
		if (CryptGetHashParam(hHash2, HP_HASHVAL, NULL, &pdwDataLen, 0)) {
			LogMessageFormat(L"Hash value data length=%d", pdwDataLen);
			pbData = (BYTE*)LocalAlloc(LMEM_ZEROINIT, pdwDataLen + 1);
			if (!CryptGetHashParam(hHash, HP_HASHVAL, pbData, &pdwDataLen, 0)) {
				LogError(L"CryprGetHashParam");
				LocalFree(pbData);
				return NULL;
				//internalDestroyHash();
			}
			else {
				LogMessage(L"CryptGetHashParam successed");
				hashVal = (char*)LocalAlloc(LMEM_ZEROINIT, pdwDataLen + 1);
				strcpy(hashVal, (char*)pbData);
				//hashVal[pdwDataLen] = '\0';
				LogMessageFormat(L"HashValue=%S", hashVal);
				ByteToStr(strlen(hashVal), hashVal, buf);
				LogMessageFormat(L"HashValStr= %S", buf);
				ByteToStr(pdwDataLen, pbData, buf);
				LogMessageFormat(L"pbDataBytes=%S", buf);
				LocalFree(pbData);
				LocalFree(hashVal);
			}
		}
		else {
			LogError(L"CryptGetHashParam - unable to retrieve HashValue DataLen");
			return NULL;
		}
	}
	else {
		LogError(L"Hash object does not exists");
		return NULL;
	}

	CryptDestroyHash(hHash2);


	/*
	/// Пытаемся получить ключ из контейнера, на который ссылается контекст криптопровайдера.
	if (!CryptGetUserKey(hProv, AT_SIGNATURE, &hKey))	{
		if(GetLastError() == NTE_NO_KEY) {
			LogMessage(L"Key doesn't exist. Creating...");

			/// Если в контейнере нет ключа - создаем.
			if(!CryptGenKey(hProv, AT_SIGNATURE, 0, &hKey)) {
				if(GetLastError() == NTE_SILENT_CONTEXT) {
					/// Если в неинтерактивном режиме создать ключ не получается, переоткроем контекст в интерактивном режиме.
					LogMessage(L"Switching to interactive mode.");
					simpleRC(hProv);
					globalSilentFlag = FALSE;
					hProv = fullAC(globalProviderID);
					/// Создаем ключ в интерактивном режиме.
					if(!CryptGenKey(hProv, AT_SIGNATURE, 0, &hKey)) {
						LogError(L"CryptGenKey - interactive");
					}
				}
				else {
					LogError(L"CryptGenKey - silent");
				}
			}
		}
		else {
			LogError(L"GetUserKey");
		}
	}

	*/

	// Determine the size of the signature and allocate memory.
	dwSigLen= 0;
	if (CryptSignHash(hHash, AT_KEYEXCHANGE, 0, 0, 0, &dwSigLen)) {
		LogMessageFormat(L"Signature length %d found.", dwSigLen);
	}
	else {
		LogError(L"Error during CryptSignHash.");
	}

	// Allocate memory for the signature buffer.
	if(pbSignature = (BYTE *)malloc(dwSigLen)) {
		LogMessage(L"Memory allocated for the signature.");
	}
	else {
		LogError(L"Out of memory.");
	}

	// Sign the hash object.
	if (CryptSignHash(hHash, AT_KEYEXCHANGE, NULL, 0, pbSignature, &dwSigLen)) {
		LogMessageFormat(L"Signature for hash = %S", pbSignature);
		ByteToStr(dwSigLen, pbSignature, buf);
		LogMessageFormat(L"SignatureBytes=%S", buf);
	}
	else {
		LogError(L"Error during CryptSignHash.");
	}

	//Verify Signature
	if(!CryptGetUserKey(hProv, AT_KEYEXCHANGE, &hKey)) {
		LogError(L"CryptGetUserKey");
		return NULL;
	}

	if (CryptVerifySignature(hHash, pbSignature, dwSigLen, hKey, NULL, 0)) {
		LogMessage(L"Signature is verified");
	}
	else {
		LogError(L"Signnature is NOT verified");
	}
	

	// Destroy the hash object.
	if(hHash) CryptDestroyHash(hHash);

	return pbSignature;
}

int main(int argc, wchar_t *argv[])
{
	int i;
	
	setLogSourceLocation(0);
	
	for(i = 0; argv[i] != NULL; i++) {

		// Providers list
		if (strcmp(argv[i], "pl") == 0) {
			//showProviders();
			command = 1;
		}

		// Provider Params - /pid required
		if (strcmp(argv[i], "pp") == 0) {
			command = 2;
		}

		// Provider Containers
		if (strcmp(argv[i], L"pc") == 0) {
			command = 3;
		}

		// Whether to use MACHINE_KEYSET
		if (strcmp(argv[i], L"/mks") == 0) {
			globalMKS = TRUE;
		}

		// Provider ID
		if (strcmp(argv[i], "/pid") == 0) {
			i++;
			globalProviderID = atol(argv[i]);
		}

		// Hash Algo ID
		if (strcmp(argv[i], L"/hid") == 0) {
			globalHashAlgID = atol(argv[++i]);
		}

		// Sign Algo ID
		if (strcmp(argv[i], L"/sid") == 0) {
			i++;
			globalSignAlgID = atol(argv[i]);
		}

		// Data to be Hashed or Signed
		if (strcmp(argv[i], L"/data") == 0) {
			i++;
			testData = wcsdup(argv[i]);
		}

		// Provider name
		if (strcmp(argv[i], L"/pname") == 0) {
			i++;
			globalProviderName = wcsdup(argv[i]);
		}

		// Signature PIN
		if (strcmp(argv[i], L"/pin") == 0) {
			globalPIN = wcsdup(argv[++i]);
		}

		// CSP container name
		if (strcmp(argv[i], L"/cn") == 0) {
			globalContainerName = wcsdup(argv[++i]);
		}

		if (strcmp(argv[i], L"Sign") == 0) {
			command = 14;
		}
	}

	switch (command) {

	case 1:
		showProviders();
		break;
	case 2:
		showProviderParams();
		break;
	case 3:
		showProviderContainers();
		break;
	case 14:
		doHashAndSign();
		break;

	default:
		//showUsage();
		break;
	};

	//_getch();
	return 0;
}



