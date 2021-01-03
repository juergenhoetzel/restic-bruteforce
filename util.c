#include <assert.h>
#include <string.h>

#include "util.h"
#include <openssl/evp.h>
/* FIXME: use meson to setup */
#include "poly1305-donna/poly1305-donna.h"

void hexprint(char *out, int len) {
  for (int i = 0; i < len; i++) {
    printf("%02X", (unsigned char)out[i]);
  }
  printf("\n");
}

char *hexstring(char *out, int len) {
  char *s = malloc(len * 2 + 1);
  for (int i = 0; i < len; i++)
    sprintf(s + i * 2, "%02X", (unsigned char)out[i]);
  return strdup(s);
}

size_t base64_decode_length(const char *b64input) {
  size_t len = strlen(b64input), padding = 0;
  if (b64input[len - 1] == '=' && b64input[len - 2] == '=')
    padding = 2;
  else if (b64input[len - 1] == '=')
    padding = 1;
  return (len * 3) / 4 - padding;
}

void base64_decode(const char *b64input, char *outbuf) {
  BIO *bio_in = BIO_new_mem_buf(b64input, strlen(b64input));
  BIO *b64_filter = BIO_new(BIO_f_base64());
  BIO *bio = BIO_push(b64_filter, bio_in);
  /* FIXME : FIXED BUFFER SIZE */
  BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
  BIO_read(bio, outbuf, base64_decode_length(b64input));
  BIO_free_all(bio);
}

/*
Freeing return string is up to the caller
 */
char *base64_encode(const char *in, int len) {
  BIO *bmem = BIO_new(BIO_s_mem());
  BIO *b64 = BIO_new(BIO_f_base64());
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  BIO_push(b64, bmem);
  BIO_write(b64, in, len);
  BIO_flush(b64);
  BIO_set_close(bmem, BIO_NOCLOSE);
  BUF_MEM *bufferPtr;
  BIO_get_mem_ptr(bmem, &bufferPtr);
  BIO_free_all(b64);
  return strndup(bufferPtr->data, bufferPtr->length);
}

static unsigned char poly1305_key_mask[16] __attribute__((aligned(8))) = {
    0xff, 0xff, 0xff, 0x0f, 0xfc, 0xff, 0xff, 0x0f, 0xfc, 0xff, 0xff, 0x0f, 0xfc, 0xff, 0xff, 0x0f};

void poly1305_preparekey(unsigned char *nonce, unsigned char *key, unsigned char *prepared_key) {

  /* mask key */
  unsigned char masked_key[32] __attribute__((aligned(8)));
  memcpy(masked_key, key, 32);

  ((uint64_t *)masked_key)[2] &= ((uint64_t *)poly1305_key_mask)[0];
  ((uint64_t *)masked_key)[3] &= ((uint64_t *)poly1305_key_mask)[1];
  /* FIXME Use k as aes key */
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  assert(ctx);
  assert(EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, masked_key, NULL) == 1);
  int out_len;
  assert(1 == EVP_EncryptUpdate(ctx, prepared_key + 16, &out_len, nonce, 16));
  assert(out_len == 16);
  memcpy(prepared_key, masked_key + 16, 16);
}

/* key = k | r (32 bytes)*/
void calculate_mac(unsigned char *nonce, const unsigned char *key, unsigned char *data, int data_len,
                   unsigned char *mac) {
  unsigned char prepared_key[32];
  poly1305_preparekey(nonce, (unsigned char *)key, prepared_key);
  poly1305_auth(mac, data, data_len, prepared_key);
}
