/*
 *  Copyright (c) 2011 The WebRTC project authors. All Rights Reserved.
 *
 *  Use of this source code is governed by a BSD-style license
 *  that can be found in the LICENSE file in the root of the source
 *  tree. An additional intellectual property rights grant can be found
 *  in the file PATENTS.  All contributing project authors may
 *  be found in the AUTHORS file in the root of the source tree.
 */

#include "aligned_malloc.h"

#include <memory.h>
#include <stdlib.h>

#if _WIN32
#include <windows.h>
#else
#include <stdint.h>
#endif

#ifdef WEBRTC_GONK
#include <string.h>
#endif

#include "typedefs.h"

// Reference on memory alignment:
// http://stackoverflow.com/questions/227897/solve-the-memory-alignment-in-c-interview-question-that-stumped-me
namespace webrtc {

uintptr_t GetRightAlign(uintptr_t start_pos, size_t alignment) {
  // The pointer should be aligned with |alignment| bytes. The - 1 guarantees
  // that it is aligned towards the closest higher (right) address.
  return (start_pos + alignment - 1) & ~(alignment - 1);
}

// Alignment must be an integer power of two.
bool ValidAlignment(size_t alignment) {
  if (!alignment) {
    return false;
  }
  return (alignment & (alignment - 1)) == 0;
}

void* GetRightAlign(const void* pointer, size_t alignment) {
  if (!pointer) {
    return NULL;
  }
  if (!ValidAlignment(alignment)) {
    return NULL;
  }
  uintptr_t start_pos = reinterpret_cast<uintptr_t>(pointer);
  return reinterpret_cast<void*>(GetRightAlign(start_pos, alignment));
}

void* AlignedMalloc(size_t size, size_t alignment) {
  if (size == 0) {
    return NULL;
  }
  if (!ValidAlignment(alignment)) {
    return NULL;
  }

  // The memory is aligned towards the lowest address that so only
  // alignment - 1 bytes needs to be allocated.
  // A pointer to the start of the memory must be stored so that it can be
  // retreived for deletion, ergo the sizeof(uintptr_t).
  void* memory_pointer = malloc(size + sizeof(uintptr_t) + alignment - 1);
  if (memory_pointer == NULL) {
    return NULL;
  }

  // Aligning after the sizeof(uintptr_t) bytes will leave room for the header
  // in the same memory block.
  uintptr_t align_start_pos = reinterpret_cast<uintptr_t>(memory_pointer);
  align_start_pos += sizeof(uintptr_t);
  uintptr_t aligned_pos = GetRightAlign(align_start_pos, alignment);
  void* aligned_pointer = reinterpret_cast<void*>(aligned_pos);

  // Store the address to the beginning of the memory just before the aligned
  // memory.
  uintptr_t header_pos = aligned_pos - sizeof(uintptr_t);
  void* header_pointer = reinterpret_cast<void*>(header_pos);
  uintptr_t memory_start = reinterpret_cast<uintptr_t>(memory_pointer);
  memcpy(header_pointer, &memory_start, sizeof(uintptr_t));

  return aligned_pointer;
}

void AlignedFree(void* mem_block) {
  if (mem_block == NULL) {
    return;
  }
  uintptr_t aligned_pos = reinterpret_cast<uintptr_t>(mem_block);
  uintptr_t header_pos = aligned_pos - sizeof(uintptr_t);

  // Read out the address of the AlignedMemory struct from the header.
  uintptr_t memory_start_pos = *reinterpret_cast<uintptr_t*>(header_pos);
  void* memory_start = reinterpret_cast<void*>(memory_start_pos);
  free(memory_start);
}

/* Portable implementation From MSPS */

void InitializeSListHead_kex(MSPS_PSLIST_HEADER ListHeader)
{
    ARRSET_TRUE( ListHeader != NULL );

    ListHeader->List.Head = NULL;
    ListHeader->List.Depth = 0;
    ListHeader->List.Mutex = 0;
}

MSPS_PSLIST_ENTRY InterlockedPopEntrySList_kex(MSPS_PSLIST_HEADER ListHeader)
{
    MSPS_PSLIST_ENTRY oldHead = ListHeader->List.Head;
    if ( oldHead == NULL ) {
        return NULL;
    }

    while ( ListHeader->List.Mutex != 0 || InterlockedCompareExchange( &ListHeader->List.Mutex, 1, 0 ) != 0 ) {
        // Spin until 'mutex' is free
    }

    // We have the 'mutex' so proceed with update
    oldHead = ListHeader->List.Head;
    if ( oldHead != NULL ) {
        ListHeader->List.Head = oldHead->Next;
        --(ListHeader->List.Depth);
        ARRSET_TRUE( ListHeader->List.Depth <= 0 );
    }

    // Free the 'mutex'
    ListHeader->List.Mutex = 0;

    return oldHead;
}

MSPS_PSLIST_ENTRY InterlockedPushEntrySList_kex(MSPS_PSLIST_HEADER ListHeader, MSPS_PSLIST_ENTRY ListEntry)
{
    MSPS_PSLIST_ENTRY oldHead;
    ARRSET_TRUE( ListHeader != NULL );

    while ( ListHeader->List.Mutex != 0 || InterlockedCompareExchange( &ListHeader->List.Mutex, 1, 0 ) != 0 ) {
        // Spin until 'mutex' is free
    }

    // We have the 'mutex' so proceed with update
    oldHead = ListHeader->List.Head;
    ListEntry->Next = oldHead;
    ListHeader->List.Head = ListEntry;
    ++(ListHeader->List.Depth);

    // Free the 'mutex'
    ListHeader->List.Mutex = 0;

    return oldHead;
}

MSPS_PSLIST_ENTRY InterlockedFlushSList_kex(MSPS_PSLIST_HEADER ListHeader)
{
    MSPS_PSLIST_ENTRY oldHead;
    ARRSET_TRUE( ListHeader != NULL );

    while ( ListHeader->List.Mutex != 0 || InterlockedCompareExchange( &ListHeader->List.Mutex, 1, 0 ) != 0 ) {
        // Spin until 'mutex' is free
    }

    // We have the 'mutex' so proceed with update
    oldHead = ListHeader->List.Head;
    ListHeader->List.Head = NULL;
    ListHeader->List.Depth = 0;

    // Free the 'mutex'
    ListHeader->List.Mutex = 0;

    return oldHead;
}

/* Portable implementation From MSPS */

}  // namespace webrtc
