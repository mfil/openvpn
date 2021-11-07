/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2021 Fox Crypto B.V. <openvpn@foxcrypto.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/**
 * @file mbedtls compatibility stub
 *
 * This file provide compatibility stubs for mbedtls libararies
 * prior to version 3.0.0. This version introduces many changes in the
 * library interface, including the fact that various objects and
 * structures are not fully opaque.
 */

#ifndef MBEDTLS_COMPAT_H_
#define MBEDTLS_COMPAT_H_

#include <mbedtls/cipher.h>
#include <mbedtls/pem.h>
#include <mbedtls/version.h>

#if MBEDTLS_VERSION_NUMBER < 0x03000000

/**
 * \brief               This function returns the cipher info structure used by
 *                      the context.
 *
 * \param ctx           The context of the cipher. This must be initialized.
 *
 * \return              The cipher info structure.
 */
static inline const mbedtls_cipher_info_t *mbedtls_cipher_info_from_ctx(
    const mbedtls_cipher_context_t *ctx)
{
    return ctx != NULL ? ctx->cipher_info : NULL;
}

/**
 * \brief               Retrieve the key size for a cipher info structure.
 *
 * \param[in] info      The cipher info structure to query.
 *                      This may be \c NULL.
 *
 * \return              The key length in bits.
 *                      For variable-sized ciphers, this is the default length.
 *                      For DES, this includes the parity bits.
 * \return              \c 0 if \p info is \c NULL.
 */
static inline size_t mbedtls_cipher_info_get_key_bitlen(
    const mbedtls_cipher_info_t *info )
{
    return info != NULL ? info->key_bitlen : 0;
}

/**
 * \brief               Retrieve the human-readable name for a
 *                      cipher info structure.
 *
 * \param[in] info      The cipher info structure to query.
 *                      This may be \c NULL.
 *
 * \return              The cipher name, which is a human readable string,
 *                      with static storage duration.
 * \return              \c NULL if \c info is \p NULL.
 */
static inline const char *mbedtls_cipher_info_get_name(const mbedtls_cipher_info_t *info)
{
    return info->name;
}

/**
 * \brief               Retrieve the identifier for a cipher info structure.
 *
 * \param[in] info      The cipher info structure to query.
 *                      This may be \c NULL.
 *
 * \return              The full cipher identifier (\c MBEDTLS_CIPHER_xxx).
 * \return              #MBEDTLS_CIPHER_NONE if \p info is \c NULL.
 */
static inline mbedtls_cipher_type_t mbedtls_cipher_info_get_type(const mbedtls_cipher_info_t *info )
{
    return info != NULL ? info->type : MBEDTLS_CIPHER_NONE;
}

/**
 * \brief               Retrieve the operation mode for a cipher info structure.
 *
 * \param[in] info      The cipher info structure to query.
 *                      This may be \c NULL.
 *
 * \return              The cipher mode (\c MBEDTLS_MODE_xxx).
 * \return              #MBEDTLS_MODE_NONE if \p info is \c NULL.
 */
static inline mbedtls_cipher_mode_t mbedtls_cipher_info_get_mode(const mbedtls_cipher_info_t *info)
{
    return info != NULL ? info->mode : MBEDTLS_MODE_NONE;
}

/**
 * \brief       This function returns the size of the IV or nonce
 *              for the cipher info structure, in bytes.
 *
 * \param ctx   The cipher info structure. This may be \c NULL.
 *
 * \return      The recommended IV size if no IV has been set.
 * \return      \c 0 for ciphers not using an IV or a nonce.
 * \return      The actual size if an IV has been set.
 */
static inline int mbedtls_cipher_info_get_iv_size(const mbedtls_cipher_info_t *info)
{
    return info != NULL ? (int)info->iv_size : 0;
}

/**
 * \brief        This function returns the block size of the given
 *               cipher info structure.
 *
 * \param info   The cipher info structure. This may be \c NULL.
 *
 * \return       The block size of the cipher.
 */
static inline unsigned int mbedtls_cipher_info_get_block_size(const mbedtls_cipher_info_t *info)
{
    return info != NULL ? (int)info->block_size : 0;
}

/**
 * \brief           This function returns the message-digest information
 *                  associated with the given context.
 *
 * \param ctx       The context to extract the message-digest information from.
 *                  This must be initialized.
 *
 * \return          The message-digest information associated with \p ctx.
 * \return          NULL if the associated message-digest information is not found.
 */
const mbedtls_md_info_t *mbedtls_md_info_from_ctx(const mbedtls_md_context_t *ctx )
{
    return ctx != NULL ? ctx->md_info : NULL;
}


/**
 * \brief       Get the decoded data from a PEM context.
 *
 * \param ctx       Context to get data from.
 *
 * \return          0 on success, 1 on error.
 */
static inline int mbedtls_pem_get_der_data( mbedtls_pem_context *ctx,
                     const unsigned char **der_data, size_t *size )
{
    if (ctx->buf == NULL)
    {
        *der_data = NULL;
        return 1;
    }
    *der_data = ctx->buf;
    *size = ctx->buflen;
    return 0;
}

#endif /* MBEDTLS_VERSION_NUMBER < 0x0300000000 */

#endif /* MBEDTLS_COMPAT_H_ */
