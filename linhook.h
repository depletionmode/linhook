
#define MEM_POOL_SIZE 4096

#define LINHOOK_INIT __attribute__((constructor)) \
                     void __linhook_init
#define LINHOOK_MALLOC_POOL() __linhook_malloc_pool(MEM_POOL_SIZE)
#define LINHOOK_HOOK_FCN(X,Y,Z) __linhook_hook_addr(X,Y,Z)

void __linhook_malloc_pool(int);
void __linhook_hook_addr(void *, void *, void **);
