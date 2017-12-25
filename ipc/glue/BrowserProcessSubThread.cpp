/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * vim: sw=2 ts=8 et :
 */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "mozilla/ipc/BrowserProcessSubThread.h"
#include "chrome/common/notification_service.h"

#if defined(OS_WIN)
#include <objbase.h>
#endif

namespace mozilla {
namespace ipc {

//
// BrowserProcessSubThread
//

// Friendly names for the well-known threads.
static const char* kBrowserThreadNames[BrowserProcessSubThread::ID_COUNT] = {
  "Goanna_IOThread",  // IO
//  "Chrome_FileThread",  // FILE
//  "Chrome_DBThread",  // DB
//  "Chrome_HistoryThread",  // HISTORY
#if defined(OS_LINUX)
  "Goanna_Background_X11Thread",  // BACKGROUND_X11
#endif
};

Lock BrowserProcessSubThread::sLock;
BrowserProcessSubThread* BrowserProcessSubThread::sBrowserThreads[ID_COUNT] = {
  NULL,  // IO
//  NULL,  // FILE
//  NULL,  // DB
//  NULL,  // HISTORY
#if defined(OS_LINUX)
  NULL,  // BACKGROUND_X11
#endif
};

BrowserProcessSubThread::BrowserProcessSubThread(ID aId) :
  base::Thread(kBrowserThreadNames[aId]),
  mIdentifier(aId),
  mNotificationService(NULL)
{
  AutoLock lock(sLock);
  DCHECK(aId >= 0 && aId < ID_COUNT);
  DCHECK(sBrowserThreads[aId] == NULL);
  sBrowserThreads[aId] = this;
}

BrowserProcessSubThread::~BrowserProcessSubThread()
{
  Stop();
  {AutoLock lock(sLock);
    sBrowserThreads[mIdentifier] = NULL;
  }

}

void
BrowserProcessSubThread::Init()
{
#if defined(OS_WIN)
  // Initializes the COM library on the current thread.
  CoInitialize(NULL);
#endif
  mNotificationService = new NotificationService();
}

void
BrowserProcessSubThread::CleanUp()
{
  delete mNotificationService;
  mNotificationService = NULL;

#if defined(OS_WIN)
  // Closes the COM library on the current thread. CoInitialize must
  // be balanced by a corresponding call to CoUninitialize.
  CoUninitialize();
#endif
}

// static
MessageLoop*
BrowserProcessSubThread::GetMessageLoop(ID aId)
{
  AutoLock lock(sLock);
  DCHECK(aId >= 0 && aId < ID_COUNT);

  if (sBrowserThreads[aId])
    return sBrowserThreads[aId]->message_loop();

  return NULL;
}

} // namespace ipc
} // namespace mozilla
