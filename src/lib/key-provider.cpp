/*
 * Copyright (c) 2017, [Ribose Inc](https://www.ribose.com).
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1.  Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *
 * 2.  Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <assert.h>
#include <string.h>
#include "key-provider.h"
#include "pgp-key.h"
#include "fingerprint.h"
#include "types.h"
#include "utils.h"
#include <rekey/rnp_key_store.h>

static bool
key_try(const pgp_key_t *seckey, const pgp_key_search_t *search)
{
    auto try_dec_ctx = &search->by.try_decrypt_cb;

    /* Decrypt key */
    const pgp_key_pkt_t *decrypted_seckey = NULL;
    if (seckey->encrypted()) {
        pgp_password_ctx_t pass_ctx{.op = PGP_OP_DECRYPT, .key = seckey};
        decrypted_seckey = pgp_decrypt_seckey(*seckey, *(const pgp_password_provider_t*)try_dec_ctx->password_provider, pass_ctx);
        if (!decrypted_seckey) {
            return false; //RNP_ERROR_BAD_PASSWORD;
        }
    } else {
        decrypted_seckey = &seckey->pkt();
    }

    /* Try to initialize the decryption */
    rnp_result_t errcode = RNP_ERROR_NO_SUITABLE_KEY;
    //pgp_key_pkt_t mutable_decrypted_seckey(*decrypted_seckey); // maybe this is why it doesn't decrypt
    pgp_key_pkt_t *mutable_decrypted_seckey = const_cast<pgp_key_pkt_t*>(decrypted_seckey);
    if (try_dec_ctx->encrypted_try_key_wrapper(try_dec_ctx, mutable_decrypted_seckey)) {
        return true;
    } else {
        return false;
    }

    // TODO pass up the decrypted key
#if 0
    /* Destroy decrypted key */
    if (seckey->encrypted()) {
        delete decrypted_seckey;
    }
#endif
}

bool
rnp_key_matches_search(const pgp_key_t *key, const pgp_key_search_t *search)
{
    if (!key) {
        return false;
    }
    switch (search->type) {
    case PGP_KEY_SEARCH_KEYID:
        return key->keyid() == search->by.keyid;
    case PGP_KEY_SEARCH_FINGERPRINT:
        return key->fp() == search->by.fingerprint;
    case PGP_KEY_SEARCH_GRIP:
        return key->grip() == search->by.grip;
    case PGP_KEY_SEARCH_USERID:
        if (key->has_uid(search->by.userid)) {
            return true;
        }
        break;
    case PGP_KEY_SEARCH_CAN_DECRYPT:
        return key_try(key, search);
    default:
        assert(false);
        break;
    }
    return false;
}

pgp_key_t *
pgp_request_key(const pgp_key_provider_t *provider, const pgp_key_request_ctx_t *ctx)
{
    pgp_key_t *key = NULL;
    if (!provider || !provider->callback || !ctx) {
        return NULL;
    }
    if (!(key = provider->callback(ctx, provider->userdata))) {
        return NULL;
    }
    // confirm that the key actually matches the search criteria
    if (!rnp_key_matches_search(key, &ctx->search) && key->is_secret() == ctx->secret) {
        return NULL;
    }
    return key;
}

pgp_key_t *
rnp_key_provider_key_ptr_list(const pgp_key_request_ctx_t *ctx, void *userdata)
{
    std::vector<pgp_key_t *> *key_list = (std::vector<pgp_key_t *> *) userdata;
    for (auto key : *key_list) {
        if (rnp_key_matches_search(key, &ctx->search) && (key->is_secret() == ctx->secret)) {
            return key;
        }
    }
    return NULL;
}

pgp_key_t *
rnp_key_provider_chained(const pgp_key_request_ctx_t *ctx, void *userdata)
{
    for (pgp_key_provider_t **pprovider = (pgp_key_provider_t **) userdata;
         pprovider && *pprovider;
         pprovider++) {
        pgp_key_provider_t *provider = *pprovider;
        pgp_key_t *         key = NULL;
        if ((key = provider->callback(ctx, provider->userdata))) {
            return key;
        }
    }
    return NULL;
}

pgp_key_t *
rnp_key_provider_store(const pgp_key_request_ctx_t *ctx, void *userdata)
{
    rnp_key_store_t *ks = (rnp_key_store_t *) userdata;

    for (pgp_key_t *key = rnp_key_store_search(ks, &ctx->search, NULL); key;
         key = rnp_key_store_search(ks, &ctx->search, key)) {
        if (key->is_secret() == ctx->secret) {
            return key;
        }
    }
    return NULL;
}
