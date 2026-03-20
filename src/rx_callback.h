#ifndef RX_CALLBACK_H
#define RX_CALLBACK_H

#include <rtl-sdr.h>

void rx_callback(unsigned char* buf, uint32_t len, void* ctx);

#endif