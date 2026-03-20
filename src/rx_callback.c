#define _GNU_SOURCE
#include "rx_callback.h"
#include "utils.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <math.h>
#include <string.h>
#include <zlib.h>
#include <time.h>
#include <stdlib.h>

#define BARKER_13       0b1111100110101ULL
#define BARKER_LEN      13
#define WINDOW_SIZE     32
#define MAX_FRAME_BYTES (1024*1024 + 64)

static float mag_window[WINDOW_SIZE] = {0};
static int mag_head = 0;

static uint8_t rx_buffer[MAX_FRAME_BYTES];
static size_t rx_byte_idx = 0;
static bool in_frame = false;
static uint32_t expected_len = 0;
static bool last_level = false;

static const float barker_seq[BARKER_LEN] = {1,1,1,1,1,0,0,1,1,0,1,0,1};

void rx_callback(unsigned char* buf, uint32_t len, void* ctx)
{
    (void)ctx;

    for (uint32_t i = 0; i < len; i += 2)
    {
        float re = buf[i] - 127.5f;
        float im = buf[i+1] - 127.5f;
        float mag = sqrtf(re*re + im*im);

        mag_window[mag_head % WINDOW_SIZE] = mag;
        mag_head++;

        if (!in_frame)
        {
            float corr = 0.0f;
            for (int k = 0; k < BARKER_LEN; k++)
                corr += mag_window[(mag_head - BARKER_LEN + k) % WINDOW_SIZE] * barker_seq[k];

            float avg = 0.0f;
            for (int k = 0; k < WINDOW_SIZE; k++) avg += mag_window[k];
            avg /= WINDOW_SIZE;

            if (corr > avg * 12.0f)
            {
                printf("\n[RX %ld] Barker sync (corr=%.1f) → collecting frame\n", time(NULL), corr);
                in_frame = true;
                rx_byte_idx = 0;
                expected_len = 0;
                memset(rx_buffer, 0, sizeof(rx_buffer));
                last_level = (mag > avg * 1.5f);
            }
        }
        else
        {
            bool level = (mag > 90.0f);  // NRZ - absolute threshold
            bool bit = level;
            last_level = level;

            size_t byte_idx = rx_byte_idx / 8;
            int bit_pos = 7 - (rx_byte_idx % 8);

            if (bit) rx_buffer[byte_idx] |= (1u << bit_pos);
            rx_byte_idx++;

            if (rx_byte_idx == 32)
            {
                expected_len = (rx_buffer[0] << 24) | (rx_buffer[1] << 16) |
                               (rx_buffer[2] << 8)  | rx_buffer[3];
                printf("[RX] Frame length: %u bytes\n", expected_len);

                if (expected_len > MAX_FRAME_BYTES - 8 || expected_len < 16) {
                    printf("[RX] Invalid length → abort\n");
                    in_frame = false;
                }
            }

            if (rx_byte_idx >= 32 + expected_len + 4)
            {
                uint8_t* ciphertext = rx_buffer + 4;
                size_t ct_len = expected_len;

                uint32_t rx_crc = (rx_buffer[4 + ct_len] << 24) |
                                  (rx_buffer[5 + ct_len] << 16) |
                                  (rx_buffer[6 + ct_len] << 8)  |
                                   rx_buffer[7 + ct_len];

                uint32_t calc_crc = ramhammer_crc32(ciphertext, ct_len);

                if (calc_crc != rx_crc) {
                    printf("[RX] CRC error\n");
                    in_frame = false;
                    continue;
                }

                printf("[RX] CRC OK → decrypting %zu bytes\n", ct_len);

                uint8_t master_key[32];
                if (load_master_key("ramhammer.key", master_key) != 0) {
                    in_frame = false;
                    continue;
                }

                // Same time-window context as TX
                time_t now = time(NULL);
                time_t window = now - (now % 300);
                char context[64];
                snprintf(context, sizeof(context), "ramhammer-campaign-2026-%016lx", window);

                uint8_t session_key[32];
                if (derive_session_key(master_key, context, session_key) != 0) {
                    in_frame = false;
                    continue;
                }

                uint8_t plaintext[ct_len];
                size_t pt_len = 0;
                if (ramhammer_decrypt(ciphertext, ct_len, plaintext, &pt_len, session_key) != 0) {
                    printf("[RX] Decryption failed\n");
                    in_frame = false;
                    continue;
                }

                printf("[RX] Decrypt OK — %zu bytes\n", pt_len);

                // Read original size from first 4 bytes
                uint32_t orig_size = ntohl(*(uint32_t*)plaintext);
                printf("[RX] Original uncompressed size: %u bytes\n", orig_size);

                uLongf dest_len = orig_size + 1024;  // exact + margin
                uint8_t* decompressed = malloc(dest_len);
                if (uncompress(decompressed, &dest_len, plaintext + 4, pt_len - 4) == Z_OK)
                {
                    char fname[128];
                    snprintf(fname, sizeof(fname), "recovered_%ld.bin", time(NULL));
                    FILE* out = fopen(fname, "wb");
                    if (out) {
                        fwrite(decompressed, 1, dest_len, out);
                        fclose(out);
                        printf("[RX] Saved: %s (%lu bytes)\n", fname, dest_len);
                    }
                }
                else
                {
                    printf("[RX] Decompression failed\n");
                }

                free(decompressed);
                in_frame = false;
            }
        }
    }
}