/* Alloc.c -- Memory allocation functions
2013-11-12 : Igor Pavlov : Public domain */

#include "Precomp.h"

#ifdef _WIN32
#include <windows.h>
#endif
#include <stdlib.h>

#include "Alloc.h"

/* #define _SZ_ALLOC_DEBUG */

/* use _SZ_ALLOC_DEBUG to debug alloc/free operations */
#ifdef _SZ_ALLOC_DEBUG
#include <stdio.h>
int g_allocCount = 0;
int g_allocCountMid = 0;
int g_allocCountBig = 0;
#endif

#ifdef HEAP_MEMORY_DEBUG
#include <stdio.h>
typedef struct _HeapCheckBlock {
    INT32 size;
    INT32 freed;
    INT32 mark;
    struct _HeapCheckBlock *prev, *next;
    INT32 dummy;
} HeapCheckBlock;
static HeapCheckBlock *pmemchecktop = NULL;
static size_t totalAllocated = 0;
static size_t wholeAllocated = 0;
#endif

void *MyAlloc(size_t size)
{
  if (size == 0)
    return 0;
  #ifdef _SZ_ALLOC_DEBUG
  {
    void *p = malloc(size);
    fprintf(stderr, "\nAlloc %10d bytes, count = %10d,  addr = %8X", size, g_allocCount++, (unsigned)p);
    return p;
  }
  #else
#ifdef HEAP_MEMORY_DEBUG
  size_t alignedsize = size + (size % 8 == 0 ? 0 : (8 - size % 8));
  void *p = malloc(alignedsize + sizeof(HeapCheckBlock) * 2 + 16);
  fprintf(stderr, "current total allocated is : %d : %d\n" , totalAllocated, wholeAllocated);
  if (p == NULL) {
#if 0
      size_t total = 0;
      HeapCheckBlock *pl = pmemchecktop;
      while (pl != NULL) {
          total += pl->size;
          pl = pl->next;
      }
      totalAllocated = total;
#endif
      fprintf(stderr, "failed to allocate, total allocated is : %d : %d\n" , totalAllocated, wholeAllocated);
      return NULL;
  }
  HeapCheckBlock *pcheck0 = (HeapCheckBlock *) p;

  pcheck0->mark = 0xf0f05757;
#if 0
  pcheck0->next = pcheck0->prev = NULL;
  if (pmemchecktop == NULL) {
      pmemchecktop = pcheck0;
  } else {
      pcheck0->next = pmemchecktop;
      pmemchecktop->prev = pcheck0;
      pmemchecktop = pcheck0;
  }
#endif
  void *r = (void *)((char *) p + sizeof(HeapCheckBlock));
  pcheck0->size = alignedsize;
  HeapCheckBlock *pcheck1 = (HeapCheckBlock *) ((char *) r + alignedsize);
  pcheck1->size = size;
  pcheck0->freed = pcheck1->freed = 0;

  totalAllocated += alignedsize;
  wholeAllocated += alignedsize;
  return r;
#else
  return malloc(size);
#endif
  #endif
}

void MyFree(void *address)
{
  #ifdef _SZ_ALLOC_DEBUG
  if (address != 0)
    fprintf(stderr, "\nFree; count = %10d,  addr = %8X", --g_allocCount, (unsigned)address);
  #endif
#ifdef HEAP_MEMORY_DEBUG
  if (address == NULL) {
      return;
  }
  void *origaddr = (void *) ((char *) address - sizeof(HeapCheckBlock));
  HeapCheckBlock *pcheck0 = (HeapCheckBlock *) origaddr;
  HeapCheckBlock *pcheck1 = (HeapCheckBlock *) ((char *) address + pcheck0->size);
  if (pcheck0->freed != 0) {
      fprintf(stderr, "memory corruption detected!!\n");
  } else {
      if (pcheck0->mark != 0xf0f05757) {
          fprintf(stderr, "memory corruption detected, may not be allocated by same allocator\n");
      } else {
          if (pcheck0->size != pcheck1->size) {
              fprintf(stderr, "memory corruption detected\n");
          }
          if (pcheck0->freed != 0) {
              fprintf(stderr, "!!freeing already freed area!!!\n");
          }
          pcheck0->freed = 1;
          if (pcheck1->freed != 0) {
              fprintf(stderr, "!!freeing already freed area!!!\n");
          }
          pcheck1->freed = 1;
      }
  }
  fflush(stderr);
#if 0
  if (pcheck0->prev != NULL) pcheck0->prev->next = pcheck0->next;
  if (pcheck0->next != NULL) pcheck0->next->prev = pcheck0->prev;
#endif
  totalAllocated -= pcheck0->size;
  wholeAllocated -= pcheck0->size;
  free(origaddr);
#else
  free(address);
#endif
}

#ifdef _WIN32
static size_t vsize(void *p)
{
    size_t total = 0;
    MEMORY_BASIC_INFORMATION info;
    void *pnext = p;
    while (TRUE) {
        VirtualQuery(pnext, &info, sizeof(info));

        if (info.AllocationBase == p) {
            total += info.RegionSize;
        } else {
            break;
        }
        pnext = (char *) pnext + info.RegionSize;
    }
    return total;
}

void *MidAlloc(size_t size)
{
  if (size == 0)
    return 0;
  #ifdef _SZ_ALLOC_DEBUG
  fprintf(stderr, "\nAlloc_Mid %10d bytes;  count = %10d", size, g_allocCountMid++);
  #endif
#ifdef HEAP_MEMORY_DEBUG
  void *p = VirtualAlloc(0, size, MEM_COMMIT, PAGE_READWRITE);
  if (p != NULL) {
      wholeAllocated += vsize(p);
  } else {
      fprintf(stderr, "valloc failed: %d : %d\n", totalAllocated, wholeAllocated);
  }
  return p;
#else
  return VirtualAlloc(0, size, MEM_COMMIT, PAGE_READWRITE);
#endif
}

void MidFree(void *address)
{
  #ifdef _SZ_ALLOC_DEBUG
  if (address != 0)
    fprintf(stderr, "\nFree_Mid; count = %10d", --g_allocCountMid);
  #endif
  if (address == 0)
    return;
#ifdef HEAP_MEMORY_DEBUG
  if (address != NULL)
      wholeAllocated -= vsize(address);
#endif
  VirtualFree(address, 0, MEM_RELEASE);
}

#ifndef MEM_LARGE_PAGES
#undef _7ZIP_LARGE_PAGES
#endif

#ifdef _7ZIP_LARGE_PAGES
SIZE_T g_LargePageSize = 0;
typedef SIZE_T (WINAPI *GetLargePageMinimumP)();
#endif

void SetLargePageSize()
{
  #ifdef _7ZIP_LARGE_PAGES
  SIZE_T size = 0;
  GetLargePageMinimumP largePageMinimum = (GetLargePageMinimumP)
        GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "GetLargePageMinimum");
  if (largePageMinimum == 0)
    return;
  size = largePageMinimum();
  if (size == 0 || (size & (size - 1)) != 0)
    return;
  g_LargePageSize = size;
  #endif
}


void *BigAlloc(size_t size)
{
  if (size == 0)
    return 0;
  #ifdef _SZ_ALLOC_DEBUG
  fprintf(stderr, "\nAlloc_Big %10d bytes;  count = %10d", size, g_allocCountBig++);
  #endif

  #ifdef _7ZIP_LARGE_PAGES
  if (g_LargePageSize != 0 && g_LargePageSize <= (1 << 30) && size >= (1 << 18))
  {
    void *res = VirtualAlloc(0, (size + g_LargePageSize - 1) & (~(g_LargePageSize - 1)),
        MEM_COMMIT | MEM_LARGE_PAGES, PAGE_READWRITE);
    if (res != 0)
      return res;
  }
  #endif
#ifdef HEAP_MEMORY_DEBUG
  void *p = VirtualAlloc(0, size, MEM_COMMIT, PAGE_READWRITE);
  if (p != NULL) {
      wholeAllocated += vsize(p);
  } else {
    fprintf(stderr, "valloc failed: %d : %d\n", totalAllocated, wholeAllocated)      ;
  }
  return p;
#else
  return VirtualAlloc(0, size, MEM_COMMIT, PAGE_READWRITE);
#endif
}

void BigFree(void *address)
{
  #ifdef _SZ_ALLOC_DEBUG
  if (address != 0)
    fprintf(stderr, "\nFree_Big; count = %10d", --g_allocCountBig);
  #endif

  if (address == 0)
    return;

#ifdef HEAP_MEMORY_DEBUG
  if (address != NULL)
    wholeAllocated -= vsize(address);
#endif

  VirtualFree(address, 0, MEM_RELEASE);
}

#endif
