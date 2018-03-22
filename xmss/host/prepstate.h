#ifndef XMSS_PREPSTATE_H
#define XMSS_PREPSTATE_H

int prepstate(const xmss_params *params,
              unsigned char *nodes, unsigned char *wots_signatures,
              const unsigned char *pk, const unsigned char *sk);

#endif