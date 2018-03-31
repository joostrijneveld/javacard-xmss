#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>

#include "smartcard-xmss.h"

#include "xmss-reference/xmss_core.h"
#include "xmss-reference/params.h"
#include "xmss-reference/randombytes.h"
#include "prepstate.h"

#define XMSS_MLEN 32

double elapsed(const long t0) {
    struct timeval timecheck;
    long t;

    gettimeofday(&timecheck, NULL);
    t = (long)timecheck.tv_sec * 1000 + (long)timecheck.tv_usec / 1000;
    return ((double)t - t0) / 1000;
}

int main() {
    struct timeval timecheck;
    gettimeofday(&timecheck, NULL);
    long t0 = (long)timecheck.tv_sec * 1000 + (long)timecheck.tv_usec / 1000;

    xmss_params params;
    int ret = 0;

    params.func = XMSS_SHA2;
    params.d = 5;
    params.n = 32;
    params.full_height = 20;

    params.tree_height = params.full_height / params.d;
    params.wots_w = 16;
    params.wots_log_w = 4;
    params.wots_len1 = 8 * params.n / params.wots_log_w;
    /* len_2 = floor(log(len_1 * (w - 1)) / log(w)) + 1 */
    params.wots_len2 = 3;
    params.wots_len = params.wots_len1 + params.wots_len2;
    params.wots_sig_bytes = params.wots_len * params.n;
    /* Round index_bytes up to nearest byte. */
    params.index_bytes = (params.full_height + 7) / 8;
    params.sig_bytes = (params.index_bytes + params.n
                         + params.d * params.wots_sig_bytes
                         + params.full_height * params.n);

    params.pk_bytes = 2 * params.n;
    params.sk_bytes = xmssmt_core_sk_bytes(&params);

    unsigned char pk[params.pk_bytes];
    unsigned char pkout[params.pk_bytes];
    unsigned char sk[params.sk_bytes];
    unsigned char *m = malloc(XMSS_MLEN);
    unsigned char *sm = malloc(params.sig_bytes + XMSS_MLEN);
    unsigned char *mout = malloc(params.sig_bytes + XMSS_MLEN);
    unsigned long long smlen;
    unsigned long long mlen;
    unsigned char nodes[params.n * params.d * (1 << params.tree_height)];
    unsigned char wots[(params.d - 1) * params.wots_sig_bytes];

    printf("[%.3f] Sampling message.. \n", elapsed(t0));
    randombytes(m, XMSS_MLEN);

    printf("[%.3f] Generating keys..\n", elapsed(t0));
    xmssmt_core_keypair(&params, pk, sk);

    printf("[%.3f] Generating state..\n", elapsed(t0));
    prepstate(&params, nodes, wots, pk, sk);

    smartcard_connect();

    printf("[%.3f] Uploading keys and state..\n", elapsed(t0));
    smartcard_xmss_upload_keypair_nodes_wots(&params, pk, sk, nodes, wots);

    printf("[%.3f] Retrieving public key.. ", elapsed(t0));
    smartcard_xmss_get_pk(&params, pkout);

    if (memcmp(pk, pkout, params.n * 2)) {
        printf("does not match!\n");
    }
    else {
        printf("matches!\n");
    }

    for (int i = 0; i < 2; i++) {
        printf("[%.3f] Signing on the card (#%d)..\n", elapsed(t0), i);
        smartcard_xmss_sign(&params, sm, &smlen, m, XMSS_MLEN);
        printf("[%.3f] .. done!\n", elapsed(t0));

        if (xmssmt_core_sign_open(&params, mout, &mlen, sm, smlen, pk)) {
            printf("[%.3f] Verification failed!\n", elapsed(t0));
        }
        else {
            printf("[%.3f] Verification successful!\n", elapsed(t0));
        }

        printf("[%.3f] Preparing new nodes..\n", elapsed(t0));
        smartcard_xmss_prep();
    }

    printf("[%.3f] Disconnecting..\n", elapsed(t0));

    smartcard_disconnect();
    printf("[%.3f] Disconnected\n", elapsed(t0));

    return ret;
}