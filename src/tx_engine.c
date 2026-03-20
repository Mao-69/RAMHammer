#define _GNU_SOURCE
#include "tx_engine.h"
#include "utils.h"

#include <immintrin.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdalign.h>

#define CHIP_DURATION_NS  4000ULL
#define CARRIER_BURST_NS  60ULL

static uint8_t hamming_74_encode(uint8_t n)
{
    int d1 = (n >> 3) & 1;
    int d2 = (n >> 2) & 1;
    int d3 = (n >> 1) & 1;
    int d4 = (n >> 0) & 1;

    int p1 = d1 ^ d2 ^ d4;
    int p2 = d1 ^ d3 ^ d4;
    int p3 = d2 ^ d3 ^ d4;

    return (p1 << 6) | (p2 << 5) | (d1 << 4) | (p3 << 3) | (d2 << 2) | (d3 << 1) | d4;
}

static void send_on_burst(void* buffer)
{
    __m256i pattern = _mm256_set1_epi64x(0xAAAAAAAAAAAAAAAAULL);
    uint64_t end = __rdtsc() + (g_tsc_per_chip * CARRIER_BURST_NS / 1000ULL);

    while (__rdtsc() < end)
    {
        _mm256_stream_si256((__m256i*)buffer, pattern);
        _mm_sfence();
    }
}

void* tx_memory_thread(void* arg)
{
    int core = (intptr_t)arg;
    pin_to_core(core);

    // FIXED: Move 8MB buffer to the HEAP (aligned for AVX2)
    void* large_buffer = NULL;
    if (posix_memalign(&large_buffer, 64, 8ULL * 1024 * 1024) != 0) {
        fprintf(stderr, "[!] Failed to allocate hammer buffer on core %d\n", core);
        return NULL;
    }

    uint64_t next_chip = __rdtsc();

    while (atomic_load_explicit(&g_keep_running, memory_order_relaxed))
    {
        uint64_t now = __rdtsc();
        if (now < next_chip)
        {
            _mm_pause();
            continue;
        }

        int state = atomic_load_explicit(&g_tx_state, memory_order_acquire);
        if (state)
        {
            send_on_burst(large_buffer);
        }

        next_chip += g_tsc_per_chip * CHIP_DURATION_NS / 1000ULL;
    }

    free(large_buffer); // Clean up on exit
    return NULL;
}

void send_bit(int bit)
{
    atomic_store_explicit(&g_tx_state, bit, memory_order_release);
    usleep(CHIP_DURATION_NS / 1000 + 100); 
}

void send_byte(uint8_t byte)
{
    uint8_t nibbles[2] = { (byte >> 4) & 0x0F, byte & 0x0F };

    for (int i = 0; i < 2; i++)
    {
        uint8_t encoded = hamming_74_encode(nibbles[i]);
        for (int bit = 6; bit >= 0; bit--)
        {
            send_bit((encoded >> bit) & 1);
        }
    }
}
