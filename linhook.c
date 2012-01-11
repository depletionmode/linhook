
#include "linhook.h"

#include <stdint.h>
#include <malloc.h>
#include <sys/mman.h>

void *_mem_pool;
void *_mem_pool_nxt_avail;
void __linhook_malloc_pool(int pool_size)
{
    /* allocate memory pool for trampolines */
    _mem_pool = malloc(pool_size);

    _mem_pool_nxt_avail = _mem_pool;
}

void *__linhook_malloc(int size)
{
    /* alloc mem form pool if available */
    if (_mem_pool - _mem_pool_nxt_avail >= size) {
        void *alloc = _mem_pool_nxt_avail;

        _mem_pool_nxt_avail += size;

        return alloc;
    }

    return NULL;
}

void __linhook_memcpy(void *dst, void *src, int len)
{
    int i;

    for (i = 0; i < len; i++)
        ((unsigned char*)dst)[i] = ((unsigned char*)src)[i];
}

int __linhook_mprotect(void *addr, int len, int prot)
{
    /* call mprotect syscall directly */
    __asm__("mov eax, 0xa");
    __asm__("syscall");
}

unsigned char *__build_jmp(void *dst, void *src)
{
     /* far jmp - relative addressing */
     static unsigned char ins[] = { 0xe9, 0, 0, 0, 0 };
     uint32_t loc = (uint32_t)dst - (uint32_t)src - 5;

     __linhook_memcpy(ins + 1, (void *)&loc, 4);

     return ins;
}

int __linhook_hook_addr(void *addr, void *n__fptr, void **o__fptr)
{
    /* allocate mem for trampoline */
    void *trampoline = __linhook_malloc(10);

    /* check if mem alloc fails */
    if (!*trampoline)
        return 0;

    /* set up trampoline */
    __linhook_memcpy(trampoline, addr, 5);
    __linhook_memcpy(trampoline + 5, __build_jmp(addr + 5, trampoline + 5), 5);
    __linhook_mprotect(trampoline - ((uint64_t)*o__fptr % PAGE_SIZE), PAGE_SIZE, PROT_READ|PROT_EXEC);

    /* set up jmp to new fcn */
    __linhook_mprotect(addr - ((uint64_t)addr % PAGE_SIZE), PAGE_SIZE, PROT_READ|PROT_WRITE);
    __linhook_memcpy(addr, __build_jmp(n__fptr, addr), 5);
    __linhook_mprotect(addr - ((uint64_t)addr % PAGE_SIZE), PAGE_SIZE, PROT_READ|PROT_EXEC);

    /* set up original fcn ptr */
    *o__fptr = trampoline;

    return 1;
}
