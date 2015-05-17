/**
* Base64 encoding and decoding, taken from XySSL 0.9 (c) Christopher Devine
* 
* \file base64.h
*/
#ifndef tf_base64_h
#define tf_base64_h
#include <stdint.h>
#include <stdlib.h>

#define XYSSL_ERR_BASE64_BUFFER_TOO_SMALL               -0x0010
#define XYSSL_ERR_BASE64_INVALID_CHARACTER              -0x0012

#ifdef __cplusplus
extern "C" {
#endif

/**
* @brief          Encode a buffer into base64 format
*
* @return         0 if successful, or XYSSL_ERR_BASE64_BUFFER_TOO_SMALL.
*                 *dlen is always updated to reflect the amount
*                 of data that has (or would have) been written.
*
* @note           Call this function with *dlen = 0 to obtain the
*                 required buffer size in *dlen
*/
int
base64_encode(
    unsigned char *         dst,        // (O) Destination buffer
    size_t *                dlen,       // (O) Destination size
    unsigned char const *   src,        // (I) Source buffer
    size_t                  slen        // (I) Amount of data to be encoded
);

/**
* @brief          Decode a base64-formatted buffer
*
* @return         0 if successful, XYSSL_ERR_BASE64_BUFFER_TOO_SMALL, or
*                 XYSSL_ERR_BASE64_INVALID_DATA if the input data is not
*                 correct. *dlen is always updated to reflect the amount
*                 of data that has (or would have) been written.
*
* @note           Call this function with *dlen = 0 to obtain the
*                 required buffer size in *dlen
*/
int
base64_decode(
    uint8_t *               dst,        // (O) Destination buffer
    size_t *                dlen,       // (O) Destination size
    char const *            src,        // (I) Source buffer
    size_t                  slen        // (I) Amount of data to be decoded
);


#ifdef __cplusplus
}

#include <vector>
#include <istream>

std::vector<uint8_t> base64_decode(std::istream& ifs);

#endif

#endif /* base64.h */
