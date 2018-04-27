/* -*- Mode: C++; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/* vim:set et sw=4 ts=4: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <stdarg.h>
#include <windef.h>
#include <winbase.h>
#include <wingdi.h>
#include <winuser.h>
#include <ole2.h>
#include <netcon.h>
#include <objbase.h>
#include <iprtrmib.h>
#include "plstr.h"
#include "nsThreadUtils.h"
#include "nsIObserverService.h"
#include "nsServiceManagerUtils.h"
#include "nsNotifyAddrListener.h"
#include "nsString.h"
#include "nsAutoPtr.h"
#include "mozilla/Services.h"
#include "nsCRT.h"

#include <iptypes.h>
#include <iphlpapi.h>

typedef DWORD (WINAPI *GetAdaptersAddressesFunc)(ULONG, DWORD, PVOID,
                                                 PIP_ADAPTER_ADDRESSES,
                                                 PULONG);
typedef DWORD (WINAPI *GetAdaptersInfoFunc)(PIP_ADAPTER_INFO, PULONG);
typedef DWORD (WINAPI *GetIfEntryFunc)(PMIB_IFROW);
typedef DWORD (WINAPI *GetIpAddrTableFunc)(PMIB_IPADDRTABLE, PULONG, BOOL);
typedef DWORD (WINAPI *NotifyAddrChangeFunc)(PHANDLE, LPOVERLAPPED);
typedef void (WINAPI *NcFreeNetconPropertiesFunc)(NETCON_PROPERTIES*);

static HMODULE sIPHelper, sNetshell;
static GetAdaptersAddressesFunc sGetAdaptersAddresses;
static GetAdaptersInfoFunc sGetAdaptersInfo;
static GetIfEntryFunc sGetIfEntry;
static GetIpAddrTableFunc sGetIpAddrTable;
static NotifyAddrChangeFunc sNotifyAddrChange;
static NcFreeNetconPropertiesFunc sNcFreeNetconProperties;

static void InitIPHelperLibrary(void)
{
    if (!sIPHelper) {
        sIPHelper = LoadLibraryW(L"iphlpapi.dll");
        if (sIPHelper) {
            sGetAdaptersAddresses = (GetAdaptersAddressesFunc)
                GetProcAddress(sIPHelper, "GetAdaptersAddresses");
            sGetAdaptersInfo = (GetAdaptersInfoFunc)
                GetProcAddress(sIPHelper, "GetAdaptersInfo");
            sGetIfEntry = (GetIfEntryFunc)
                GetProcAddress(sIPHelper, "GetIfEntry");
            sGetIpAddrTable = (GetIpAddrTableFunc)
                GetProcAddress(sIPHelper, "GetIpAddrTable");
            sNotifyAddrChange = (NotifyAddrChangeFunc)
                GetProcAddress(sIPHelper, "NotifyAddrChange");
        }
    }
}

static void InitNetshellLibrary(void)
{
    if (!sNetshell) {
        sNetshell = LoadLibraryW(L"Netshell.dll");
        if (sNetshell) {
            sNcFreeNetconProperties = (NcFreeNetconPropertiesFunc)
                GetProcAddress(sNetshell, "NcFreeNetconProperties");
        }
    }
}

static void FreeDynamicLibraries(void)
{
    if (sIPHelper)
    {
        sGetAdaptersAddresses = nullptr;
        sGetAdaptersInfo = nullptr;
        sGetIfEntry = nullptr;
        sGetIpAddrTable = nullptr;
        sNotifyAddrChange = nullptr;

        FreeLibrary(sIPHelper);
        sIPHelper = nullptr;
    }

    if (sNetshell) {
        sNcFreeNetconProperties = nullptr;
        FreeLibrary(sNetshell);
        sNetshell = nullptr;
    }
}

NS_IMPL_THREADSAFE_ISUPPORTS3(nsNotifyAddrListener,
                              nsINetworkLinkService,
                              nsIRunnable,
                              nsIObserver)

nsNotifyAddrListener::nsNotifyAddrListener()
    : mLinkUp(true)  // assume true by default
    , mStatusKnown(false)
    , mCheckAttempted(false)
    , mShutdownEvent(nullptr)
{
}

nsNotifyAddrListener::~nsNotifyAddrListener()
{
    NS_ASSERTION(!mThread, "nsNotifyAddrListener thread shutdown failed");
    FreeDynamicLibraries();
}

NS_IMETHODIMP
nsNotifyAddrListener::GetIsLinkUp(bool *aIsUp)
{
    if (!mCheckAttempted && !mStatusKnown) {
        mCheckAttempted = true;
        CheckLinkStatus();
    }

    *aIsUp = mLinkUp;
    return NS_OK;
}

NS_IMETHODIMP
nsNotifyAddrListener::GetLinkStatusKnown(bool *aIsUp)
{
    *aIsUp = mStatusKnown;
    return NS_OK;
}

NS_IMETHODIMP
nsNotifyAddrListener::GetLinkType(uint32_t *aLinkType)
{
  NS_ENSURE_ARG_POINTER(aLinkType);

  // XXX This function has not yet been implemented for this platform
  *aLinkType = nsINetworkLinkService::LINK_TYPE_UNKNOWN;
  return NS_OK;
}

NS_IMETHODIMP
nsNotifyAddrListener::Run()
{
    PR_SetCurrentThreadName("Link Monitor");

    HANDLE ev = CreateEvent(nullptr, FALSE, FALSE, nullptr);
    NS_ENSURE_TRUE(ev, NS_ERROR_OUT_OF_MEMORY);

    HANDLE handles[2] = { ev, mShutdownEvent };
    OVERLAPPED overlapped = { 0 };
    bool shuttingDown = false;

    InitIPHelperLibrary();

    if (!sNotifyAddrChange) {
        CloseHandle(ev);
        return NS_ERROR_NOT_AVAILABLE;
    }

    overlapped.hEvent = ev;
    while (!shuttingDown) {
        HANDLE h;
        DWORD ret = sNotifyAddrChange(&h, &overlapped);

        if (ret == ERROR_IO_PENDING) {
            ret = WaitForMultipleObjects(2, handles, FALSE, INFINITE);
            if (ret == WAIT_OBJECT_0) {
                CheckLinkStatus();
            } else {
                shuttingDown = true;
            }
        } else {
            shuttingDown = true;
        }
    }
    CloseHandle(ev);

    return NS_OK;
}

NS_IMETHODIMP
nsNotifyAddrListener::Observe(nsISupports *subject,
                              const char *topic,
                              const PRUnichar *data)
{
    if (!strcmp("xpcom-shutdown-threads", topic))
        Shutdown();

    return NS_OK;
}

nsresult
nsNotifyAddrListener::Init(void)
{
    nsCOMPtr<nsIObserverService> observerService =
        mozilla::services::GetObserverService();
    if (!observerService)
        return NS_ERROR_FAILURE;

    nsresult rv = observerService->AddObserver(this, "xpcom-shutdown-threads",
                                               false);
    NS_ENSURE_SUCCESS(rv, rv);

    mShutdownEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    NS_ENSURE_TRUE(mShutdownEvent, NS_ERROR_OUT_OF_MEMORY);

    rv = NS_NewThread(getter_AddRefs(mThread), this);
    NS_ENSURE_SUCCESS(rv, rv);

    return NS_OK;
}

nsresult
nsNotifyAddrListener::Shutdown(void)
{
    // remove xpcom shutdown observer
    nsCOMPtr<nsIObserverService> observerService =
        mozilla::services::GetObserverService();
    if (observerService)
        observerService->RemoveObserver(this, "xpcom-shutdown-threads");

    if (!mShutdownEvent)
        return NS_OK;

    SetEvent(mShutdownEvent);

    nsresult rv = mThread->Shutdown();

    // Have to break the cycle here, otherwise nsNotifyAddrListener holds
    // onto the thread and the thread holds onto the nsNotifyAddrListener
    // via its mRunnable
    mThread = nullptr;

    CloseHandle(mShutdownEvent);
    mShutdownEvent = NULL;

    return rv;
}

/* Sends the given event to the UI thread.  Assumes aEventID never goes out
 * of scope (static strings are ideal).
 */
nsresult
nsNotifyAddrListener::SendEventToUI(const char *aEventID)
{
    if (!aEventID)
        return NS_ERROR_NULL_POINTER;

    nsresult rv;
    nsCOMPtr<nsIRunnable> event = new ChangeEvent(this, aEventID);
    if (NS_FAILED(rv = NS_DispatchToMainThread(event)))
        NS_WARNING("Failed to dispatch ChangeEvent");
    return rv;
}

NS_IMETHODIMP
nsNotifyAddrListener::ChangeEvent::Run()
{
    nsCOMPtr<nsIObserverService> observerService =
        mozilla::services::GetObserverService();
    if (observerService)
        observerService->NotifyObservers(
                mService, NS_NETWORK_LINK_TOPIC,
                NS_ConvertASCIItoUTF16(mEventID).get());
    return NS_OK;
}

DWORD
nsNotifyAddrListener::GetOperationalStatus(DWORD aAdapterIndex)
{
    DWORD status = MIB_IF_OPER_STATUS_CONNECTED;

    // If this fails, assume it's connected.  Didn't find a KB, but it
    // failed for me w/Win2K SP2, and succeeded for me w/Win2K SP3.
    if (sGetIfEntry) {
        MIB_IFROW ifRow;

        ifRow.dwIndex = aAdapterIndex;
        if (sGetIfEntry(&ifRow) == ERROR_SUCCESS)
            status = ifRow.dwOperStatus;
    }
    return status;
}

/**
 * Calls GetIpAddrTable to check whether a link is up.  Assumes so if any
 * adapter has a non-zero IP (v4) address.  Sets mLinkUp if GetIpAddrTable
 * succeeds, but doesn't set mStatusKnown.
 * Returns ERROR_SUCCESS on success, and a Win32 error code otherwise.
 */
DWORD
nsNotifyAddrListener::CheckIPAddrTable(void)
{
    if (!sGetIpAddrTable)
        return ERROR_CALL_NOT_IMPLEMENTED;

    ULONG size = 0;
    DWORD ret = sGetIpAddrTable(nullptr, &size, FALSE);
    if (ret == ERROR_INSUFFICIENT_BUFFER && size > 0) {
        PMIB_IPADDRTABLE table = (PMIB_IPADDRTABLE) malloc(size);
        if (!table)
            return ERROR_OUTOFMEMORY;

        ret = sGetIpAddrTable(table, &size, FALSE);
        if (ret == ERROR_SUCCESS) {
            bool linkUp = false;

            for (DWORD i = 0; !linkUp && i < table->dwNumEntries; i++) {
                if (GetOperationalStatus(table->table[i].dwIndex) >=
                        MIB_IF_OPER_STATUS_CONNECTED &&
                        table->table[i].dwAddr != 0 &&
                        // Nor a loopback
                        table->table[i].dwAddr != 0x0100007F)
                    linkUp = true;
            }
            mLinkUp = linkUp;
        }
        free(table);
    }
    return ret;
}

/**
 * Checks whether a link is up by calling GetAdaptersInfo.  If any adapter's
 * operational status is at least MIB_IF_OPER_STATUS_CONNECTED, checks:
 * 1. If it's configured for DHCP, the link is considered up if the DHCP
 *    server is initialized.
 * 2. If it's not configured for DHCP, the link is considered up if it has a
 *    nonzero IP address.
 * Sets mLinkUp and mStatusKnown if GetAdaptersInfo succeeds.
 * Returns ERROR_SUCCESS on success, and a Win32 error code otherwise.  If the
 * call is not present on the current platform, returns ERROR_NOT_SUPPORTED.
 */
DWORD
nsNotifyAddrListener::CheckAdaptersInfo(void)
{
    if (!sGetAdaptersInfo)
        return ERROR_NOT_SUPPORTED;

    ULONG adaptersLen = 0;

    DWORD ret = sGetAdaptersInfo(0, &adaptersLen);
    if (ret == ERROR_BUFFER_OVERFLOW && adaptersLen > 0) {
        PIP_ADAPTER_INFO adapters = (PIP_ADAPTER_INFO) malloc(adaptersLen);
        if (!adapters)
            return ERROR_OUTOFMEMORY;

        ret = sGetAdaptersInfo(adapters, &adaptersLen);
        if (ret == ERROR_SUCCESS) {
            bool linkUp = false;
            PIP_ADAPTER_INFO ptr;

            for (ptr = adapters; ptr && !linkUp; ptr = ptr->Next) {
                if (GetOperationalStatus(ptr->Index) >=
                        MIB_IF_OPER_STATUS_CONNECTED) {
                    if (ptr->DhcpEnabled) {
                        if (PL_strcmp(ptr->DhcpServer.IpAddress.String,
                                      "255.255.255.255")) {
                            // it has a DHCP server, therefore it must have
                            // a usable address
                            linkUp = true;
                        }
                    }
                    else {
                        PIP_ADDR_STRING ipAddr;
                        for (ipAddr = &ptr->IpAddressList; ipAddr && !linkUp;
                             ipAddr = ipAddr->Next) {
                            if (PL_strcmp(ipAddr->IpAddress.String, "0.0.0.0")) {
                                linkUp = true;
                            }
                        }
                    }
                }
            }
            mLinkUp = linkUp;
            mStatusKnown = true;
        }
        free(adapters);
    }
    return ret;
}

bool
nsNotifyAddrListener::CheckIsGateway(PIP_ADAPTER_ADDRESSES aAdapter)
{
    if (!aAdapter->FirstUnicastAddress)
        return false;

    LPSOCKADDR aAddress = aAdapter->FirstUnicastAddress->Address.lpSockaddr;
    if (!aAddress)
        return false;

    PSOCKADDR_IN in_addr = (PSOCKADDR_IN)aAddress;
    bool isGateway = (aAddress->sa_family == AF_INET &&
        in_addr->sin_addr.S_un.S_un_b.s_b1 == 192 &&
        in_addr->sin_addr.S_un.S_un_b.s_b2 == 168 &&
        in_addr->sin_addr.S_un.S_un_b.s_b3 == 0 &&
        in_addr->sin_addr.S_un.S_un_b.s_b4 == 1);

    if (isGateway)
      isGateway = CheckICSStatus(aAdapter->FriendlyName);

    return isGateway;
}

bool
nsNotifyAddrListener::CheckICSStatus(PWCHAR aAdapterName)
{
    InitNetshellLibrary();

    // This method enumerates all privately shared connections and checks if some
    // of them has the same name as the one provided in aAdapterName. If such
    // connection is found in the collection the adapter is used as ICS gateway
    bool isICSGatewayAdapter = false;

    HRESULT hr;
    nsRefPtr<INetSharingManager> netSharingManager;
    hr = CoCreateInstance(
                CLSID_NetSharingManager,
                NULL,
                CLSCTX_INPROC_SERVER,
                IID_INetSharingManager,
                getter_AddRefs(netSharingManager));

    nsRefPtr<INetSharingPrivateConnectionCollection> privateCollection;
    if (SUCCEEDED(hr)) {
        hr = netSharingManager->get_EnumPrivateConnections(
                    ICSSC_DEFAULT,
                    getter_AddRefs(privateCollection));
    }

    nsRefPtr<IEnumNetSharingPrivateConnection> privateEnum;
    if (SUCCEEDED(hr)) {
        nsRefPtr<IUnknown> privateEnumUnknown;
        hr = privateCollection->get__NewEnum(getter_AddRefs(privateEnumUnknown));
        if (SUCCEEDED(hr)) {
            hr = privateEnumUnknown->QueryInterface(
                        IID_IEnumNetSharingPrivateConnection,
                        getter_AddRefs(privateEnum));
        }
    }

    if (SUCCEEDED(hr)) {
        ULONG fetched;
        VARIANT connectionVariant;
        while (!isICSGatewayAdapter &&
               SUCCEEDED(hr = privateEnum->Next(1, &connectionVariant,
               &fetched)) &&
               fetched) {
            if (connectionVariant.vt != VT_UNKNOWN) {
                // We should call VariantClear here but it needs to link
                // with oleaut32.lib that produces a Ts incrase about 10ms
                // that is undesired. As it is quit unlikely the result would
                // be of a different type anyway, let's pass the variant
                // unfreed here.
                NS_ERROR("Variant of unexpected type, expecting VT_UNKNOWN, we probably leak it!");
                continue;
            }

            nsRefPtr<INetConnection> connection;
            if (SUCCEEDED(connectionVariant.punkVal->QueryInterface(
                              IID_INetConnection,
                              getter_AddRefs(connection)))) {
                connectionVariant.punkVal->Release();

                NETCON_PROPERTIES *properties;
                if (SUCCEEDED(connection->GetProperties(&properties))) {
                    if (!wcscmp(properties->pszwName, aAdapterName))
                        isICSGatewayAdapter = true;

                    if (sNcFreeNetconProperties)
                        sNcFreeNetconProperties(properties);
                }
            }
        }
    }

    return isICSGatewayAdapter;
}

DWORD
nsNotifyAddrListener::CheckAdaptersAddresses(void)
{
    if (!sGetAdaptersAddresses)
        return ERROR_NOT_SUPPORTED;

    ULONG len = 16384;

    PIP_ADAPTER_ADDRESSES addresses = (PIP_ADAPTER_ADDRESSES) malloc(len);
    if (!addresses)
        return ERROR_OUTOFMEMORY;

    DWORD ret = sGetAdaptersAddresses(AF_UNSPEC, 0, NULL, addresses, &len);
    if (ret == ERROR_BUFFER_OVERFLOW) {
        free(addresses);
        addresses = (PIP_ADAPTER_ADDRESSES) malloc(len);
        if (!addresses)
            return ERROR_BUFFER_OVERFLOW;
        ret = sGetAdaptersAddresses(AF_UNSPEC, 0, NULL, addresses, &len);
    }

    if (FAILED(CoInitializeEx(NULL, COINIT_MULTITHREADED))) {
        free(addresses);
        return ERROR_NOT_SUPPORTED;
    }

    if (ret == ERROR_SUCCESS) {
        PIP_ADAPTER_ADDRESSES ptr;
        bool linkUp = false;

        for (ptr = addresses; !linkUp && ptr; ptr = ptr->Next) {
            if (ptr->OperStatus == IfOperStatusUp &&
                    ptr->IfType != IF_TYPE_SOFTWARE_LOOPBACK &&
                    !CheckIsGateway(ptr))
                linkUp = true;
        }
        mLinkUp = linkUp;
        mStatusKnown = true;
    }
    free(addresses);

    CoUninitialize();

    return ret;
}

/**
 * Checks the status of all network adapters.  If one is up and has a valid IP
 * address, sets mLinkUp to true.  Sets mStatusKnown to true if the link status
 * is definitive.
 */
void
nsNotifyAddrListener::CheckLinkStatus(void)
{
    DWORD ret;
    const char *event;

    // This call is very expensive (~650 milliseconds), so we don't want to
    // call it synchronously. Instead, we just start up assuming we have a
    // network link, but we'll report that the status is unknown.
    if (NS_IsMainThread()) {
        NS_WARNING("CheckLinkStatus called on main thread! No check "
                   "performed. Assuming link is up, status is unknown.");
        mLinkUp = true;
    } else {
        ret = CheckAdaptersAddresses();
        if (ret == ERROR_NOT_SUPPORTED)
            ret = CheckAdaptersInfo();
        if (ret == ERROR_NOT_SUPPORTED)
            ret = CheckIPAddrTable();
        if (ret != ERROR_SUCCESS) {
            mLinkUp = true;
        }
    }

    if (mStatusKnown)
        event = mLinkUp ? NS_NETWORK_LINK_DATA_UP : NS_NETWORK_LINK_DATA_DOWN;
    else
        event = NS_NETWORK_LINK_DATA_UNKNOWN;
    SendEventToUI(event);
}
