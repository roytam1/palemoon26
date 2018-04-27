/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "secrng.h"

#ifdef XP_WIN
#include <windows.h>
#include <time.h>

static BOOL
CurrentClockTickTime(LPDWORD lpdwHigh, LPDWORD lpdwLow)
{
    LARGE_INTEGER   liCount;

    if (!QueryPerformanceCounter(&liCount))
        return FALSE;

    *lpdwHigh = liCount.u.HighPart;
    *lpdwLow = liCount.u.LowPart;
    return TRUE;
}

size_t RNG_GetNoise(void *buf, size_t maxbuf)
{
    DWORD   dwHigh, dwLow, dwVal;
    int     n = 0;
    int     nBytes;
    time_t  sTime;

    if (maxbuf <= 0)
        return 0;

    CurrentClockTickTime(&dwHigh, &dwLow);

    // get the maximally changing bits first
    nBytes = sizeof(dwLow) > maxbuf ? maxbuf : sizeof(dwLow);
    memcpy((char *)buf, &dwLow, nBytes);
    n += nBytes;
    maxbuf -= nBytes;

    if (maxbuf <= 0)
        return n;

    nBytes = sizeof(dwHigh) > maxbuf ? maxbuf : sizeof(dwHigh);
    memcpy(((char *)buf) + n, &dwHigh, nBytes);
    n += nBytes;
    maxbuf -= nBytes;

    if (maxbuf <= 0)
        return n;

    // get the number of milliseconds that have elapsed since Windows started
    dwVal = GetTickCount();

    nBytes = sizeof(dwVal) > maxbuf ? maxbuf : sizeof(dwVal);
    memcpy(((char *)buf) + n, &dwVal, nBytes);
    n += nBytes;
    maxbuf -= nBytes;

    if (maxbuf <= 0)
        return n;

    // get the time in seconds since midnight Jan 1, 1970
    time(&sTime);
    nBytes = sizeof(sTime) > maxbuf ? maxbuf : sizeof(sTime);
    memcpy(((char *)buf) + n, &sTime, nBytes);
    n += nBytes;

    return n;
}

void RNG_SystemInfoForRNG(void)
{
    DWORD           dwVal;
    char            buffer[256];
    int             nBytes;
    MEMORYSTATUS    sMem;
    HANDLE          hVal;
    DWORD           dwSerialNum;
    DWORD           dwComponentLen;
    DWORD           dwSysFlags;
    char            volName[128];
    DWORD           dwSectors, dwBytes, dwFreeClusters, dwNumClusters;

    nBytes = RNG_GetNoise(buffer, 20);  // get up to 20 bytes
    RNG_RandomUpdate(buffer, nBytes);

    sMem.dwLength = sizeof(sMem);
    GlobalMemoryStatus(&sMem);                // assorted memory stats
    RNG_RandomUpdate(&sMem, sizeof(sMem));

    dwVal = GetLogicalDrives();
    RNG_RandomUpdate(&dwVal, sizeof(dwVal));  // bitfields in bits 0-25

    dwVal = sizeof(buffer);
    if (GetComputerName(buffer, &dwVal))
        RNG_RandomUpdate(buffer, dwVal);

    hVal = GetCurrentProcess();               // 4 or 8 byte pseudo handle (a
                                              // constant!) of current process
    RNG_RandomUpdate(&hVal, sizeof(hVal));

    dwVal = GetCurrentProcessId();            // process ID (4 bytes)
    RNG_RandomUpdate(&dwVal, sizeof(dwVal));

    dwVal = GetCurrentThreadId();             // thread ID (4 bytes)
    RNG_RandomUpdate(&dwVal, sizeof(dwVal));

    volName[0] = '\0';
    buffer[0] = '\0';
    GetVolumeInformation(NULL,
                         volName,
                         sizeof(volName),
                         &dwSerialNum,
                         &dwComponentLen,
                         &dwSysFlags,
                         buffer,
                         sizeof(buffer));

    RNG_RandomUpdate(volName,         strlen(volName));
    RNG_RandomUpdate(&dwSerialNum,    sizeof(dwSerialNum));
    RNG_RandomUpdate(&dwComponentLen, sizeof(dwComponentLen));
    RNG_RandomUpdate(&dwSysFlags,     sizeof(dwSysFlags));
    RNG_RandomUpdate(buffer,          strlen(buffer));

    if (GetDiskFreeSpace(NULL, &dwSectors, &dwBytes, &dwFreeClusters, 
                         &dwNumClusters)) {
        RNG_RandomUpdate(&dwSectors,      sizeof(dwSectors));
        RNG_RandomUpdate(&dwBytes,        sizeof(dwBytes));
        RNG_RandomUpdate(&dwFreeClusters, sizeof(dwFreeClusters));
        RNG_RandomUpdate(&dwNumClusters,  sizeof(dwNumClusters));
    }

    nBytes = RNG_GetNoise(buffer, 20);  // get up to 20 bytes
    RNG_RandomUpdate(buffer, nBytes);
}


/*
 * CryptoAPI requires Windows NT 4.0 or Windows 95 OSR2 and later.
 * Until we drop support for Windows 95, we need to emulate some
 * definitions and declarations in <wincrypt.h> and look up the
 * functions in advapi32.dll at run time.
 */

#ifndef WIN64
typedef unsigned long HCRYPTPROV;
#endif

#define CRYPT_VERIFYCONTEXT 0xF0000000

#define PROV_RSA_FULL 1

typedef BOOL
(WINAPI *CryptAcquireContextAFn)(
    HCRYPTPROV *phProv,
    LPCSTR pszContainer,
    LPCSTR pszProvider,
    DWORD dwProvType,
    DWORD dwFlags);

typedef BOOL
(WINAPI *CryptReleaseContextFn)(
    HCRYPTPROV hProv,
    DWORD dwFlags);

typedef BOOL
(WINAPI *CryptGenRandomFn)(
    HCRYPTPROV hProv,
    DWORD dwLen,
    BYTE *pbBuffer);

/*
 * Windows XP and Windows Server 2003 and later have RtlGenRandom,
 * which must be looked up by the name SystemFunction036.
 */
typedef BOOLEAN
(APIENTRY *RtlGenRandomFn)(
    PVOID RandomBuffer,
    ULONG RandomBufferLength);

size_t RNG_SystemRNG(void *dest, size_t maxLen)
{
    HMODULE hModule;
    RtlGenRandomFn pRtlGenRandom;
    CryptAcquireContextAFn pCryptAcquireContextA;
    CryptReleaseContextFn pCryptReleaseContext;
    CryptGenRandomFn pCryptGenRandom;
    HCRYPTPROV hCryptProv;
    size_t bytes = 0;

    hModule = LoadLibrary("advapi32.dll");
    if (hModule == NULL) {
	return bytes;
    }
    pRtlGenRandom = (RtlGenRandomFn)
	GetProcAddress(hModule, "SystemFunction036");

    if (pRtlGenRandom) {
	if (pRtlGenRandom(dest, maxLen)) {
	    bytes = maxLen;
	    goto done;
	}
    }
    pCryptAcquireContextA = (CryptAcquireContextAFn)
	GetProcAddress(hModule, "CryptAcquireContextA");
    pCryptReleaseContext = (CryptReleaseContextFn)
	GetProcAddress(hModule, "CryptReleaseContext");
    pCryptGenRandom = (CryptGenRandomFn)
	GetProcAddress(hModule, "CryptGenRandom");
    if (!pCryptAcquireContextA || !pCryptReleaseContext || !pCryptGenRandom) {
	return bytes;
    }
    if (pCryptAcquireContextA(&hCryptProv, NULL, NULL,
	PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
	if (pCryptGenRandom(hCryptProv, maxLen, dest)) {
	    bytes = maxLen;
	}
	pCryptReleaseContext(hCryptProv, 0);
    }
done:
    FreeLibrary(hModule);
    return bytes;
}
#endif  /* is XP_WIN */
