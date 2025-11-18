/*
 * SPDX-FileCopyrightText: Copyright 2025 Siemens
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _GTAOSSL_PROVIDER_DILITHIUM_TYPES_H_
#define _GTAOSSL_PROVIDER_DILITHIUM_TYPES_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/bn.h>
#include <openssl/core_dispatch.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/params.h>
#include <openssl/types.h>

/*
 * Example Structure for Dilithium public key:
 *
 * SubjectPublicKeyInfo SEQUENCE (2 elem)Offset: 0
 *   algorithm AlgorithmIdentifier SEQUENCE (1 elem)
 *      algorithm OBJECT IDENTIFIER 1.3.6.1.4.1.2.267.7.4.4
 *   subjectPublicKey BIT STRING (10494 bit) 1000110110010100101101111100011110000001...
 *
 * Reverted structure:
 * https://lapo.it/asn1js/#MIIFNDANBgsrBgEEAQKCCwcEBAOCBSECjZS3x4F1Mu5AXw2IjvLZDtiXPDUa7xDUj289OJze3QEB8yNPDx_te5QB-JfE0Ghu93R1Udthd0_5WJAG_JDHfv5CVQp05FfeRK02DRZARf-rvgN9SZxOtPxGLjDUQ-VqH-KvSQ7umfOdv7fkWKXLkXyiqx4sE5ftZt9NMlJGRz96VTkW9yUkGb3fICIq47Tx5LXK3h88YocNcaJXza0qjobocm4lRFmiWtRNdTjnuhwf6sip8yzFzRg7atEApJpwEB8lNgcYUeYyKdSbrppgV7XrbSzDl5mbedLxDpowsdy1zJHeDpyUrG495P7SgEfvGb8pYnQvf2FQVGlblaIDOMwwaSZmN0oOO1LoQLv1YBWl54ZZkn4V4d5udOKy9BugAi4X-wPfZI6_BiNkOFEQRo4JaYhTpbBZHZuNNSssiAZ5BsZGreN-1RSdLRnm8zJyvjgnd7SliXjIV5b8rdDPlI-Uip1rTN-XtIe0r3-wsp5gOjMsQdrfNSFUf09MTr8VaAv4CuwDAfrFTXZB0y_eaNK3Jpb6MHoMYk8kDWW6ZBb2r9F7pz_JGP95bh4whz51B7l82hkF4dKT6sVgeqs_dzuDnGb3YOOo79xW-0mwm99W5ipwFdSwiOy1dd2acAc8ug4vhfJkDf606WtNLWCS0rOCY921Fmqm6Xcv2lUf_AvHHRvX9YDIYkFGu2whhVOzxM3sx03jQb-6djetYkzdOBjCcRdu79X49WvIQpctD7Oga6WXkTVEBLu4IFaKsfkdTwzF49NwNLRhoEfqtmSg2nsc1R3uH_hxgofKZ4LoekDU8Jvt4TtWRYkO7eCn5I4uQCzfOjDUq_d26ezMPIiy62sG8i3YrlR_01KW0N3oQparZIVkPfyPAPMQ_lEkZH4FIJ0AeZr86lAlSqwJnngGv5R6_oIiUMkbPVKuxs80u6HY4CL6mp-H4NA8ILvfauQFhZAN3CSwbQvGmnM35l5goFBvaC6_0dIYWfjK_YCzo_FXEO5H5Pq4duq86e0rmWP6R3o2IZkV3yL9xHT4dgcXHtrCaRlr-kz6Sdj122JD3tD58G2Gw-G3C_GV8flYaAezNcFa6zTxR2hjDth4fSlxnWXm2iKk_vWR3tjeLV5Wu8EbaIt-kDF80FoDEXE6rHy8v2YMDSd4sB2CTHC53jLRrn6b4uDhqwrPE04ocxgNOS12vEq5Dd7BMgmm9YY8pPkeGLZnxxyyzuT6ZJYShs-uNxLs_iC6oirzVpDLlsEynR5P8cZJyRj8WfRgLLjiMXVD2Bx85Ka12yXk5803t4Rc-q5kWgvd6-jCye5SINJxgiiGpg98iQDLISm8BCTqpRjaczQwGXg6qNbVdHfnRxc9Ylimewh4woZu3lEGEUd16r630hAx97jd665E1fwmYUJDRzcoaKfCOeTgliEeyYoyln1uN0i2ySx38DcRMDUS4LIUBTA-CL30Vkq52E_kZb9rzrR45r--UHGWTx0TcxAX1k3kCpIOyqT2nBLZMSz5YerpVqF69ivkzkI2lm-3J27IG2AE36h8P70KLz6TOWITkOb4kiwrjzFOrkClGLKON0eBFgS30Pjx37HJ7QjHPRFayk5Nbn21jguOxcGl6Ww4OEXZT3Ayd79sJOBXB079T37wHw4_YtiY-KyxxUno2SYnDW1YvBr19USqOLouSnPOe1SSQIOKdqujZ80RxNvTweTmAN3T3GClYzVsu9Axymo8EYSVen2SSyruhoaYpNn1lA
 */
typedef struct AlgorithmIdentifier_Dilithium_st {
    ASN1_OBJECT * algorithm;
} AlgorithmIdentifierDilithium;
DECLARE_ASN1_FUNCTIONS(AlgorithmIdentifierDilithium)

typedef struct PublicKeyInfo_Dilithium_st {
    AlgorithmIdentifierDilithium * algorithm;
    ASN1_BIT_STRING * public_key_data;
} SubjectPublicKeyInfoDilithium;
DECLARE_ASN1_FUNCTIONS(SubjectPublicKeyInfoDilithium)

#ifdef __cplusplus
}
#endif

#endif /* _GTAOSSL_PROVIDER_DILITHIUM_TYPES_H_ */
