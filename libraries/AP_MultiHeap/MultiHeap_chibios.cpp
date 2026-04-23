/*
  allocation backend functions using native ChibiOS chHeap API
 */

#include "AP_MultiHeap.h"
#include <AP_HAL/AP_HAL_Boards.h>

#if ENABLE_HEAP && CONFIG_HAL_BOARD == HAL_BOARD_CHIBIOS

#include <ch.h>
#include <hal.h>
#include <limits.h>

/*
  heap functions used by lua scripting
 */
void *MultiHeap::heap_create(uint32_t size)
{
    if (size > (UINT32_MAX - sizeof(memory_heap_t))) {
        return nullptr;
    }

    auto *heap = static_cast<memory_heap_t *>(malloc(size + sizeof(memory_heap_t)));
    if (heap == nullptr) {
        return nullptr;
    }
    chHeapObjectInit(heap, heap + 1U, size);
    return heap;
}

void MultiHeap::heap_destroy(void *ptr)
{
    free(ptr);
}

void *MultiHeap::heap_allocate(void *heap, uint32_t size)
{
    if (heap == nullptr) {
        return nullptr;
    }
    if (size == 0) {
        return nullptr;
    }
    return chHeapAlloc(static_cast<memory_heap_t *>(heap), size);
}

void MultiHeap::heap_free(void *ptr)
{
    if (ptr == nullptr) {
        return;
    }
    chHeapFree(ptr);
}

#endif // ENABLE_HEAP && CONFIG_HAL_BOARD
