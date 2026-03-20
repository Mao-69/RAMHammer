#ifndef TX_ENGINE_H
#define TX_ENGINE_H

#include <stdint.h>

void* tx_memory_thread(void* arg);
void  send_bit(int bit);
void  send_byte(uint8_t byte);

#endif