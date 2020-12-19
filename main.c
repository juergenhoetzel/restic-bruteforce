#define _GNU_SOURCE /* pthread_timedjoin_np */
#include "util.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define PLEN 128

typedef struct {
  int N, r, p;
  char *salt_bytes;
  int salt_length;
  char *data;
  int data_length;
  pthread_mutex_t get_work_lock;
  int count;
} work;

int valid(EVP_PKEY_CTX *pctx, work *work, char *password) {
  size_t keylen = 64;
  char key[64];
  assert(EVP_PKEY_CTX_set1_pbe_pass(pctx, password, strlen(password)) > 0);
  assert(EVP_PKEY_CTX_set1_scrypt_salt(pctx, work->salt_bytes, work->salt_length) > 0);
  assert(EVP_PKEY_CTX_set_scrypt_N(pctx, work->N) > 0);
  assert(EVP_PKEY_CTX_set_scrypt_r(pctx, work->r) > 0);
  assert(EVP_PKEY_CTX_set_scrypt_p(pctx, work->p) > 0);
  assert(EVP_PKEY_derive(pctx, (unsigned char *)key, &keylen) > 0);
  char *poly1305_key = key + 32;

  char mac[16];

  const char *ciphertext = work->data + 16;
  const char *nonce = work->data;
  int ciphertext_length = work->data_length - 32;
  calculate_mac((unsigned char *)nonce, (unsigned char *)poly1305_key, (unsigned char *)ciphertext, ciphertext_length,
                (unsigned char *)mac);
  if (memcmp(mac, work->data + work->data_length - 16, 16) == 0) {
    return 1;
  }
  return 0;
}

void *do_work(void *arg) {
  work *w = (work *)arg;
  EVP_PKEY_CTX *pctx = pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_SCRYPT, NULL);
  assert(EVP_PKEY_derive_init(pctx) > 0);
  char *password = malloc(PLEN);
  /* loop stdin*/
  size_t n = PLEN;
  do {
    pthread_mutex_lock(&w->get_work_lock);
    n = getline(&password, &n, stdin);
    w->count++;
    pthread_mutex_unlock(&w->get_work_lock);
    if (n == -1)
      return 0; /* EOF */
    password[n - 1] = 0;
    if (valid(pctx, w, password)) {
      printf("Found: %s\n", password);
      /* FIXME: Conditional variables */
      exit(0);
    }
  } while (1);
  return 0;
}

void usage() {
  fprintf(stderr, "Usage: restic-bruteforce [options] \n");
  fprintf(stderr, "Bruteforce words on STDIN\n\n"
                  "scryptoptions:\n\n"
                  "  -n int\t(32768)\n"
                  "  -r int\t(8)\n"
                  "  -p int\t(7)\n\n"
                  "  -v\t verbose output\n");
}
int main(int argc, char *argv[]) {
  int n = 32768;
  int r = 8;
  int p = 7;

  int c;
  int verbose = 0;
  while ((c = getopt(argc, argv, "hn:r:p:v")) != -1)
    switch (c) {
    case 'h':
      usage();
      exit(0);
    case 'n':
      n = atoi(optarg);
      break;
    case 'r':
      r = atoi(optarg);
      break;
    case 'p':
      p = atoi(optarg);
      break;
    case 'v':
      verbose = 1;
      break;
    case '?':
      usage();
      exit(1);
    }
  if (argc - optind != 2) {
    usage();
    exit(1);
  }

  const char *salt = argv[optind];
  const char *data_base64 = argv[optind + 1];
  if (((strlen(salt) * 3) % 4) > 0) {
    printf("Invalid Salt Padding: %s", salt);
    exit(1);
  }
  if (((strlen(data_base64) * 3) % 4) > 0) {
    printf("Invalid Data_Base64 Padding: %s", data_base64);
    exit(1);
  }
  /* decode salt */
  size_t salt_length = base64_decode_length(salt);
  char *salt_bytes = malloc(salt_length);
  base64_decode(salt, salt_bytes);

  /* decode data_base64 */
  size_t data_length = base64_decode_length(data_base64);
  char *data = malloc(data_length);
  base64_decode(data_base64, data);

  work w = {.N = n,
            .r = r,
            .p = p,
            .salt_length = salt_length,
            .salt_bytes = salt_bytes,
            .data = data,
            .data_length = data_length,
            .get_work_lock = PTHREAD_MUTEX_INITIALIZER,
            .count = 0};

  int n_cpus = sysconf(_SC_NPROCESSORS_ONLN);
  printf("Using parameters (N=%d, r=%d, p=%d) on %d Threads\n", w.N, w.r, w.p, n_cpus);
  pthread_t *workers = malloc(sizeof(pthread_t) * n_cpus);
  int result;
  for (int i = 0; i < n_cpus; i++)
    pthread_create(workers + i, NULL, do_work, &w);
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  ts.tv_sec += 5;
  int i = i;
  for (int i = 0; i < n_cpus; i++) {
    while (pthread_timedjoin_np(workers[i], (void *)&result, &ts) == ETIMEDOUT) {
      if (verbose) {
        pthread_mutex_lock(&w.get_work_lock);
        printf("Checked %d passwords\n", w.count);
        pthread_mutex_unlock(&w.get_work_lock);
      }
      clock_gettime(CLOCK_REALTIME, &ts);
      ts.tv_sec += 5;
    }
  }
  /* if we reach this: No password was found */
  fprintf(stderr, "unlucky\n");
  exit(1);
}
