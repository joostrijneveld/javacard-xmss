/*
 * Made available under the CC0 1.0 Universal Public domain dedication
 * Joost Rijneveld, Radboud University, 2017
 */

#ifndef _SMARTCARD_H_
#define _SMARTCARD_H_

#ifdef __APPLE__
    #include <PCSC/winscard.h>
    #include <PCSC/wintypes.h>
#else
    #include <winscard.h>
#endif

#include "xmss-reference/params.h"

int smartcard_connect();
int smartcard_disconnect();

int smartcard_xmss_upload_keypair_nodes_wots(const xmss_params *params,
                                             const unsigned char *pk,
                                             const unsigned char *sk,
                                             const unsigned char *nodes,
                                             const unsigned char *wots);

int smartcard_xmss_get_pk(const xmss_params *params, unsigned char *pk);

int smartcard_xmss_sign(const xmss_params *params,
                        unsigned char *sm, unsigned long long *smlen,
                        const unsigned char *m, unsigned long long mlen);

int smartcard_xmss_prep();

#endif
