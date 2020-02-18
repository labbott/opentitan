// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include "sw/device/lib/base/stdasm.h"
#include "sw/device/lib/common.h"
#include "sw/device/lib/log.h"
#include "sw/device/lib/uart.h"
#include "sw/device/lib/aes.h"

// Based on Appendix F.1.1 of https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf


static unsigned char key[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
		     0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };

// Blocks 1-4
static unsigned char plain[] = {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
    0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
    0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
    0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
    0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
    0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
};

// Blocks 1-4
static unsigned char cypher[] = {
    0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60,
    0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97,
    0xf5, 0xd3, 0xd5, 0x85, 0x03, 0xb9, 0x69, 0x9d,
    0xe7, 0x85, 0x89, 0x5a, 0x96, 0xfd, 0xba, 0xaf,
    0x43, 0xb1, 0xcd, 0x7f, 0x59, 0x8e, 0xce, 0x23,
    0x88, 0x1b, 0x00, 0xe3, 0xed, 0x03, 0x06, 0x88,
    0x7b, 0x0c, 0x78, 0x5e, 0x27, 0xe8, 0xad, 0x3f,
    0x82, 0x23, 0x20, 0x71, 0x04, 0x72, 0x5d, 0xd4
};

static unsigned char out[16*4];

void aes_test_trigger(void) {
  aes_cfg_t cfg;
  int i, j;
  int error = 0;
  unsigned char *working = plain;
  unsigned char *outp = out;
  LOG_INFO("start AES test with trigger\n");

  aes_clear();
  cfg.operation = kAesEnc;
  cfg.key_len = kAes128;
  cfg.manual_operation = 1;

  aes_init(cfg);

  aes_key_put(key, kAes128);


  for (i = 0; i < 4; i++) {
	aes_data_put_wait(working);
	working += 16;
	aes_trigger();
	aes_data_get_wait(outp);
	outp += 16;	
  }
  LOG_INFO("done!\n");
  for (j = 0; j < 16*4; j++){
	if (cypher[j] != out[j]) {
		error = 1;
		break;
	}
  }

  if (error) {
	LOG_INFO("Found an error at byte %d\n", j);
  } else {
	LOG_INFO("Encryption succesful!\n");
  }

}

void aes_test_automatic(void) {
  aes_cfg_t cfg;
  int i, j;
  int error = 0;
  unsigned char *working = plain;
  unsigned char *outp = out;
  LOG_INFO("start AES test\n");

  aes_clear();
  cfg.operation = kAesEnc;
  cfg.key_len = kAes128;
  cfg.manual_operation = 0;

  aes_init(cfg);

  aes_key_put(key, kAes128);

  aes_data_put_wait(working);
  working += 16;
  aes_data_put(working);
  working += 16;

  LOG_INFO("wrote intial data\n");
  for (i = 0; i < 4; i++) {

	 aes_data_get_wait(outp);
	 outp += 16;

  	LOG_INFO("got data for block %d\n", i);
	 if (i < 2) {
		aes_data_put(working);
		working += 16;
  		LOG_INFO("write for block %d\n", i+2);
	 }
		
  }

  LOG_INFO("done!\n");
  for (j = 0; j < 16*4; j++){
	if (cypher[j] != out[j]) {
		error = 1;
		break;
	}
  }
  if (error) {
	LOG_INFO("Found an error at byte %d\n", j);
  } else {
	LOG_INFO("Encryption succesful!\n");
  }

}

int main(void) {
	uart_init(UART_BAUD_RATE);
	//aes_test_trigger();
	aes_test_automatic();
	return 0;
}


