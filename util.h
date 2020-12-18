#ifndef UTIL_H
#define UTIL_H

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/kdf.h>
#include <openssl/ssl.h>

void hexprint(char *out, int len);
char *hexstring(char *out, int len);

size_t base64_decode_length(const char *b64input);
void base64_decode(const char *b64input, char *outbuf);
char *base64_encode(const char *in, int len);

void calculate_mac(unsigned char *nonce, const unsigned char *key,
                   unsigned char *data, int data_len, unsigned char *mac);
#endif
