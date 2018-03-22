#include <string.h>

#include "xmss-reference/xmss_core.h"
#include "xmss-reference/hash_address.h"
#include "xmss-reference/params.h"
#include "xmss-reference/xmss_commons.h"
#include "xmss-reference/wots.h"
#include "xmss-reference/hash.h"

int prepstate(const xmss_params *params,
              unsigned char *nodes, unsigned char *wots_signatures,
              const unsigned char *pk, const unsigned char *sk)
{
    unsigned int i, j, idx;
    const unsigned char *sk_seed = sk + params->index_bytes;
    const unsigned char *pub_seed = pk + params->n;

    uint32_t addr[8] = {0};
    set_tree_addr(addr, 0);

    unsigned char tmpnodes[params->n * (1 << params->tree_height)];
    unsigned char ots_seed[params->n];

    for (i = 0; i < params->d; i++) {
        set_layer_addr(addr, i);

        uint32_t ots_addr[8] = {0};
        uint32_t ltree_addr[8] = {0};

        set_type(ots_addr, XMSS_ADDR_TYPE_OTS);
        set_type(ltree_addr, XMSS_ADDR_TYPE_LTREE);

        /* Select the required subtree. */
        copy_subtree_addr(ots_addr, addr);
        copy_subtree_addr(ltree_addr, addr);

        for (idx = 0; idx < (unsigned int)(1 << params->tree_height); idx++) {
            set_ltree_addr(ltree_addr, idx);
            set_ots_addr(ots_addr, idx);

            gen_leaf_wots(params,
                nodes + params->n * (i * (1 << params->tree_height) + idx),
                sk_seed, pub_seed, ltree_addr, ots_addr);
        }

        if (i == params->d - 1) {
            /* No need to prepare a WOTS signature on the root */
            continue;
        }

        memcpy(tmpnodes, nodes + params->n * (i * (1 << params->tree_height)),
                                 params->n * (1 << params->tree_height));

        set_type(addr, XMSS_ADDR_TYPE_HASHTREE);

        for (j = 0; j < params->tree_height; j++) {
            set_tree_height(addr, j);
            for (idx = 0; idx < (unsigned int)(1 << (params->tree_height - (j + 1))); idx++) {
                set_tree_index(addr, idx);
                thash_h(params,
                        tmpnodes + idx*params->n,
                        tmpnodes + (idx * 2) * params->n,
                        pub_seed, addr);
            }
        }

        /* Get the address of the left-most WOTS leaf on the next layer */
        set_layer_addr(ots_addr, i + 1);
        set_tree_addr(ots_addr, 0);
        set_ots_addr(ots_addr, 0);

        /* Get a seed for the WOTS keypair. */
        get_seed(params, ots_seed, sk_seed, ots_addr);

        /* Compute a WOTS signature. */
        wots_sign(params, wots_signatures + i*params->wots_sig_bytes,
                  tmpnodes, ots_seed, pub_seed, ots_addr);
    }

    return 0;
}
