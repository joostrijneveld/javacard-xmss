/*
 * Made available under the CC0 1.0 Universal Public domain dedication
 * Joost Rijneveld, Radboud University, 2018
 */

#ifdef __APPLE__
    #include <PCSC/winscard.h>
    #include <PCSC/wintypes.h>
#else
    #include <winscard.h>
#endif

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "smartcard-xmss.h"
#include "xmss-reference/params.h"

#ifdef WIN32
static char *pcsc_stringify_error(LONG rv)
{
    static char out[20];
    sprintf_s(out, sizeof(out), "0x%08X", rv);

    return out;
}
#endif

#define check(f, rv) \
    if (SCARD_S_SUCCESS != rv) \
    { \
        printf("[PCSC]: " f ": %s\n", pcsc_stringify_error(rv)); \
        return -1; \
    }

#define apdu_cla(apdu, cla) \
    apdu[0] = cla;

#define apdu_ins(apdu, ins) \
    apdu[1] = ins;

#define apdu_p12(apdu, p1, p2) \
    apdu[2] = p1;\
    apdu[3] = p2;

#define apdu_lc(apdu, lc) \
    apdu[4] = lc;

#define send_apdu(apdu, apdu_len, recv_buffer, recv_len_ptr) \
    SCardTransmit(smartcard_handle, &pio_send_pci, apdu, apdu_len, \
                  NULL, recv_buffer, recv_len_ptr);

#define SMARTCARD_CLA 0x80

#define SMARTCARD_INS_XMSS_KEYGEN 0x50
#define SMARTCARD_INS_XMSS_INIT_KEYS 0x51
#define SMARTCARD_INS_XMSS_GET_PK 0x52
#define SMARTCARD_INS_XMSS_SIGN_INIT 0x53
#define SMARTCARD_INS_XMSS_SIGN_WOTS 0x54
#define SMARTCARD_INS_XMSS_SIGN_AUTHPATH 0x55
#define SMARTCARD_INS_XMSS_SIGN_PREP 0x56
#define SMARTCARD_INS_XMSS_INIT_KEYS_NO_COMPUTE 0x57
#define SMARTCARD_INS_XMSS_INIT_NODES 0x58
#define SMARTCARD_INS_XMSS_INIT_WOTS 0x59

#define ISO7816_SW_NO_ERROR 0x9000

SCARDCONTEXT smartcard_ctx;
LPTSTR mszReaders;
SCARDHANDLE smartcard_handle;
SCARD_IO_REQUEST pio_send_pci;
static bool connected;

void check_sw(char *f, BYTE *buf) {
    if (ISO7816_SW_NO_ERROR != (buf[0] << 8) + buf[1]) {
        printf("[PCSC]: %s : Got return code %04X", f, (buf[0] << 8) + buf[1]);
    }
}

int smartcard_connect()
{
    long r;
    DWORD readers, active_protocol;
    DWORD recv_len;
    BYTE recv_buffer[258];
    BYTE apdu_select[] = {0x00, 0xA4, 0x04, 0x00, 0x0C,
                          0x58, 0x4D, 0x53, 0x53, 0x43, 0x41, 0x52, 0x44,
                          0x58, 0x4D, 0x53, 0x53};

    r = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &smartcard_ctx);
    check("SCardEstablishContext", r)

#ifdef SCARD_AUTOALLOCATE
    readers = SCARD_AUTOALLOCATE;

    r = SCardListReaders(smartcard_ctx, NULL, (LPTSTR)&mszReaders, &readers);
    check("SCardListReaders", r)
#else
    r = SCardListReaders(smartcard_ctx, NULL, NULL, &readers);
    check("SCardListReaders", r)

    mszReaders = calloc(readers, sizeof(char));
    r = SCardListReaders(smartcard_ctx, NULL, mszReaders, &readers);
    check("SCardListReaders", r)
#endif

    r = SCardConnect(smartcard_ctx, mszReaders, SCARD_SHARE_SHARED,
                     SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
                     &smartcard_handle, &active_protocol);
    check("SCardConnect", r)

    switch(active_protocol)
    {
        case SCARD_PROTOCOL_T0:
            pio_send_pci = *SCARD_PCI_T0;
            break;
        case SCARD_PROTOCOL_T1:
            pio_send_pci = *SCARD_PCI_T1;
            break;
    }

    recv_len = sizeof(recv_buffer);
    r = send_apdu(apdu_select, sizeof(apdu_select), recv_buffer, &recv_len);
    check("SCardTransmit", r)
    check_sw("select", recv_buffer);

    // TODO be smarter about trying other readers if this fails!

    if (!r) {
        connected = true;
    }

    return r;
}

int smartcard_disconnect()
{
    long r;

    if (!connected) {
        printf("Attempted to disconnect already disconnected smart card");
        return -1;
    }

    r = SCardDisconnect(smartcard_handle, SCARD_LEAVE_CARD);
    check("SCardDisconnect", r)

#ifdef SCARD_AUTOALLOCATE
    r = SCardFreeMemory(smartcard_ctx, mszReaders);
    check("SCardFreeMemory", r)
#else
    free(mszReaders);
#endif

    r = SCardReleaseContext(smartcard_ctx);
    check("SCardReleaseContext", r)

    connected = false;

    return r;
}

int smartcard_xmss_upload_keypair_nodes_wots(const xmss_params *params,
                                             const unsigned char *pk,
                                             const unsigned char *sk,
                                             const unsigned char *nodes,
                                             const unsigned char *wots)
{
    long r;
    BYTE apdu_buffer[5 + params->n*3];
    BYTE recv_buffer[258];
    DWORD recv_len;
    int i;

    apdu_cla(apdu_buffer, SMARTCARD_CLA);
    apdu_ins(apdu_buffer, SMARTCARD_INS_XMSS_INIT_KEYS_NO_COMPUTE);
    apdu_p12(apdu_buffer, 0, 0);
    apdu_lc(apdu_buffer, params->n * 3);

    memcpy(apdu_buffer + 5, sk + params->index_bytes, 2 * params->n);
    memcpy(apdu_buffer + 5 + 2*params->n, pk + params->n, params->n);

    recv_len = 2;
    r = send_apdu(apdu_buffer, 5 + params->n*3, recv_buffer, &recv_len);
    check("upload key", r);
    check_sw("upload key", recv_buffer);

    /* TODO: this can be done more optimal by packing more nodes per APDU */
    apdu_ins(apdu_buffer, SMARTCARD_INS_XMSS_INIT_NODES);
    apdu_lc(apdu_buffer, params->n);
    for (i = 0; (unsigned int)i < params->d * (1 << params->tree_height); i++) {
        memcpy(apdu_buffer + 5, nodes, params->n);
        nodes += params->n;

        recv_len = 2;
        r |= send_apdu(apdu_buffer, 5 + params->n, recv_buffer, &recv_len);
        check("upload nodes", r);
        check_sw("upload nodes", recv_buffer);
    }

    /* TODO: this can be done more optimal by packing more nodes per APDU */
    apdu_ins(apdu_buffer, SMARTCARD_INS_XMSS_INIT_WOTS);
    apdu_lc(apdu_buffer, params->n);
    for (i = 0; (unsigned int)i < (params->d - 1) * params->wots_len; i++) {
        memcpy(apdu_buffer + 5, wots, params->n);
        wots += params->n;

        recv_len = 2;
        r |= send_apdu(apdu_buffer, 5 + params->n, recv_buffer, &recv_len);
        check("upload wots signature part", r);
        check_sw("upload wots signature part", recv_buffer);
    }

    return r;
}

int smartcard_xmss_sign(const xmss_params *params,
                        unsigned char *sm, unsigned long long *smlen,
                        const unsigned char *m, unsigned long long mlen)
{
    long r;
    int i, j;
    BYTE recv_buffer[258];
    DWORD recv_len;
    // Assumes that mlen <= 255
    BYTE apdu_buffer[5 + mlen];

    apdu_cla(apdu_buffer, SMARTCARD_CLA);
    apdu_ins(apdu_buffer, SMARTCARD_INS_XMSS_SIGN_INIT);
    apdu_p12(apdu_buffer, 0, 0);
    apdu_lc(apdu_buffer, mlen);
    memcpy(apdu_buffer + 5, m, mlen);

    recv_len = 2 + params->n + params->index_bytes;
    r = send_apdu(apdu_buffer, 5 + mlen, recv_buffer, &recv_len);
    check("signature init", r);
    check_sw("signature init", recv_buffer + recv_len - 2);

    memcpy(sm, recv_buffer, params->n + params->index_bytes);
    sm += params->n + params->index_bytes;

    for (i = 0; (unsigned int)i < params->d; i++) {
        /* Get all the WOTS chains */
        for (j = 0; (unsigned int)j < 8 + 1; j++) {
            apdu_ins(apdu_buffer, SMARTCARD_INS_XMSS_SIGN_WOTS);
            apdu_lc(apdu_buffer, 0);

            recv_len = 2 + (j < 8 ? 8 : 3)*params->n;
            r |= send_apdu(apdu_buffer, 5, recv_buffer, &recv_len);
            check("wots chain", r);
            check_sw("wots chain", recv_buffer + recv_len - 2);

            memcpy(sm, recv_buffer, recv_len - 2);
            sm += recv_len - 2;
        }

        /* Get the authentication path */
        apdu_ins(apdu_buffer, SMARTCARD_INS_XMSS_SIGN_AUTHPATH);
        apdu_lc(apdu_buffer, 0);

        recv_len = 2 + params->tree_height*params->n;
        r |= send_apdu(apdu_buffer, 5, recv_buffer, &recv_len);
        check("authentication path", r);
        check_sw("authentication path", recv_buffer + recv_len - 2);

        memcpy(sm, recv_buffer, recv_len - 2);
        sm += recv_len - 2;
    }

    memcpy(sm, m, mlen);
    *smlen = mlen + params->sig_bytes;

    return r;
}

int smartcard_xmss_get_pk(const xmss_params *params, unsigned char *pk)
{
    long r;
    BYTE recv_buffer[258];
    DWORD recv_len;
    BYTE apdu_buffer[5];

    apdu_cla(apdu_buffer, SMARTCARD_CLA);
    apdu_ins(apdu_buffer, SMARTCARD_INS_XMSS_GET_PK);
    apdu_p12(apdu_buffer, 0, 0);
    apdu_lc(apdu_buffer, 0);

    recv_len = params->n * 2 + 2;
    r = send_apdu(apdu_buffer, 5, recv_buffer, &recv_len);
    check("get public key", r);
    check_sw("get public key", recv_buffer + recv_len - 2);

    memcpy(pk, recv_buffer, params->n * 2);

    return r;
}

int smartcard_xmss_prep()
{
    long r;
    BYTE recv_buffer[258];
    DWORD recv_len;
    BYTE apdu_buffer[5];

    apdu_cla(apdu_buffer, SMARTCARD_CLA);
    apdu_ins(apdu_buffer, SMARTCARD_INS_XMSS_SIGN_PREP);
    apdu_p12(apdu_buffer, 0, 0);
    apdu_lc(apdu_buffer, 0);

    recv_len = 2;
    r = send_apdu(apdu_buffer, 5, recv_buffer, &recv_len);
    check("prepare for next signature", r);
    check_sw("prepare for next signature", recv_buffer + recv_len - 2);

    return r;
}
