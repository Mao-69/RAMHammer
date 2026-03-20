#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdalign.h>

void pin_to_core(int core);
uint64_t calibrate_tsc(unsigned int sleep_ms);

extern atomic_bool g_keep_running;
extern atomic_int  g_tx_state;
extern uint64_t    g_tsc_per_chip;

// Crypto
int load_master_key(const char* filepath, uint8_t master_key[32]);

int derive_session_key(const uint8_t master_key[32], const char* context,
                       uint8_t session_key[32]);

int ramhammer_encrypt(const uint8_t* pt, size_t pt_len,
                      uint8_t* ct, size_t* ct_len, const uint8_t key[32]);

int ramhammer_decrypt(const uint8_t* ct, size_t ct_len,
                      uint8_t* pt, size_t* pt_len, const uint8_t key[32]);

uint32_t ramhammer_crc32(const uint8_t* data, size_t len);

#endif