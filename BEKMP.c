#include <stdio.h>
#include <string.h>

#include "micro-ecc/uECC.c"
#include "BEKMP.h"
#include "sha.h"
#include <time.h>

void _mulPoint(uECC_word_t *_mul,
               const uECC_word_t *_s,
               const uECC_word_t *_p,
               const uECC_Curve curve);

void _addPoint(uECC_word_t *_sum,
               const uECC_word_t *_p1,
               const uECC_word_t *_p2,
               const uECC_Curve curve);

void vli_print(char *str,
               const uint8_t *vli, 
               unsigned int size) {

    printf("%s ", str);
    for(unsigned i=0; i<size; ++i) {
        printf("%02X", (unsigned)vli[i]);
    }
    printf("\n");
}

void _vli_print_pt(char *str, 
                   const uECC_word_t *_p, 
                   const uECC_Curve curve) {
    
    wordcount_t num_words = curve->num_words;
    wordcount_t num_bytes = curve->num_bytes;
    
    uint8_t p[PUBLIC_SIZE] = { 0 };
    
    uECC_vli_nativeToBytes(p,  num_bytes, _p);
    uECC_vli_nativeToBytes(p + num_bytes, num_bytes, _p + num_words);

    printf("%s ", str);
    for(unsigned i=0; i<PUBLIC_SIZE; ++i) {
        printf("%02X", (unsigned)p[i]);
    }
    printf("\n");
}

void _vli_print_s(char *str, 
                  const uECC_word_t *_s, 
                  const uECC_Curve curve) {

    uint8_t s[PRIVATE_SIZE] = { 0 };
    
    uECC_vli_nativeToBytes(s, BITS_TO_BYTES(curve->num_n_bits), _s);

    printf("%s ", str);
    for(unsigned i=0; i<PRIVATE_SIZE; ++i) {
        printf("%02X", (unsigned)s[i]);
    }
    printf("\n");
}

int csr_request(struct csr_t *csr, 
                uint8_t *private, 
                const uint8_t id[ID_SIZE],
                const uECC_Curve curve) {
                
    uint8_t public[PUBLIC_SIZE] = {0x5B, 0xA3, 0x54, 0x29, 0xDD, 0xBD, 0x9D, 0xC9, 0x27, 0x41, 0x44, 0x94, 0x6C, 0xB7, 0xA6, 0xC9, 0x20, 0x1E, 0x9B, 0xB1, 0x63, 0x02, 0x89, 0x49, 0x5C, 0x21, 0xA1, 0x2D, 0x0F, 0x5D, 0xEA, 0x3B, 0x6D, 0x3E, 0x7E, 0x3F, 0xC0, 0xC0, 0xD1, 0xBA, 0x6E, 0x62, 0x4D, 0xD1, 0x10, 0x90, 0x40, 0x96};  
    //uint8_t public[] = {0x3A, 0x51, 0x78, 0x32, 0xB5, 0xBB, 0xD0, 0xC9, 0x5C, 0x52, 0x1E, 0xD9, 0xB1, 0xC0, 0xF3, 0x95, 0xFD, 0x27, 0x60, 0x2B, 0x37, 0xBC, 0xBA, 0x3C, 0x78, 0x4C, 0x80, 0x2E, 0xFE, 0x9F, 0x38, 0x24, 0x2D, 0x42, 0x1E, 0xAB, 0xBE, 0x00, 0x23, 0x83, 0x92, 0x30, 0x26, 0xC8, 0x43, 0x67, 0x47, 0x8E};          
    uint8_t compressed[PT_COMPRESSED_SIZE] = {0};

    // Generate key-pair
    if (! uECC_make_key(public, private, curve)) {
        return 0;
    }

    // Compress point
    uECC_compress(public, compressed, curve);

    memcpy(csr->id, id, ID_SIZE);
    memcpy(csr->point, compressed, PT_COMPRESSED_SIZE);

    return 1;
}

int crt_generation(uint8_t *r,
                   uint8_t *crt, 
                   const struct csr_t *csr, 
                   const uint8_t *private_ca, 
                   const uint8_t *public_ca,
                   const uECC_Curve curve) {

    wordcount_t num_words = curve->num_words;
    wordcount_t num_bytes = curve->num_bytes;

    uint8_t public[PUBLIC_SIZE] = {0};
    uint8_t k[PRIVATE_SIZE]     = {0};
    uint8_t K[PUBLIC_SIZE]      = {0};
    uint8_t PU[PUBLIC_SIZE]     = {0};
    uint8_t compressed[PT_COMPRESSED_SIZE] = {0};
    uint8_t hash[32];

    uECC_word_t _e[uECC_MAX_WORDS];
    uECC_word_t _ek[uECC_MAX_WORDS];
    uECC_word_t _Pu[uECC_MAX_WORDS * 2];
    uECC_word_t _ePu[uECC_MAX_WORDS * 2];
    uECC_word_t _ePuQca[uECC_MAX_WORDS * 2];

    #if uECC_VLI_NATIVE_LITTLE_ENDIAN
    uECC_word_t *_public     = (uECC_word_t *)public;
    uECC_word_t *_public_ca  = (uECC_word_t *)public_ca;
    uECC_word_t *_private_ca = (uECC_word_t *)private_ca;
    uECC_word_t *_K          = (uECC_word_t *)K;
    uECC_word_t *_k          = (uECC_word_t *)k;
    uECC_word_t *_r          = (uECC_word_t *)r;
    #else
    uECC_word_t _public[uECC_MAX_WORDS * 2];
    uECC_word_t _public_ca[uECC_MAX_WORDS * 2];
    uECC_word_t _private_ca[uECC_MAX_WORDS];
    uECC_word_t _K[uECC_MAX_WORDS * 2];
    uECC_word_t _k[uECC_MAX_WORDS];
    uECC_word_t _r[uECC_MAX_WORDS];
    #endif    

    // Extract and decompress the point from the csr
    uECC_decompress(csr->point, public, curve);

    // Validate the extracted public key
    if (!uECC_valid_public_key(public, curve)) {
        return 0;       
    }

    #if uECC_VLI_NATIVE_LITTLE_ENDIAN
    bcopy((uint8_t *) _public,     public,     num_bytes*2);
    bcopy((uint8_t *) _public_ca,  public_ca,  num_bytes*2);
    bcopy((uint8_t *) _private_ca, private_ca, num_bytes);
    #else
    uECC_vli_bytesToNative(_public, public, num_bytes);
    uECC_vli_bytesToNative(_public + num_words, public + num_bytes, num_bytes);
    uECC_vli_bytesToNative(_public_ca, public_ca, num_bytes);
    uECC_vli_bytesToNative(_public_ca + num_words, public_ca + num_bytes, num_bytes);
    uECC_vli_bytesToNative(_private_ca, private_ca, BITS_TO_BYTES(curve->num_n_bits));
    #endif

    do {
        // Generate a new key-pair k, kG
        if (! uECC_make_key(K, k, curve)) {
            return 0;
        }

        //uint8_t variable1[] = {0x8F, 0x39, 0x78, 0x54, 0xF9, 0xE6, 0x1B, 0x52, 0xC9, 0x94, 0x94, 0xBA, 0x8B, 0x98, 0xB8, 0x86, 0xBE, 0x61, 0x51, 0x22, 0x97, 0xF8, 0xB9, 0x20, 0x81, 0xD1, 0xCF, 0x7C, 0xAF, 0xE6, 0x18, 0x26, 0x82, 0x2B, 0xAA, 0x42, 0x72, 0xEB, 0x41, 0xB4, 0xFA, 0x66, 0xAF, 0x24, 0x57, 0xB8, 0x70, 0xD4};
        //uint8_t variable2[] = {0xCA, 0x55, 0xDE, 0xFB, 0x7B, 0xBF, 0xEA, 0x73, 0xFD, 0x5C, 0x95, 0x8F, 0xFB, 0xD7, 0xF5, 0x4D, 0x3, 0xBF, 0x6F, 0x3B, 0x60, 0xE, 0x20, 0x95};
        //uint8_t var1[] = {0x2E, 0x67, 0xBE, 0xF3, 0x79, 0x40, 0xB4, 0x79, 0x5F, 0x05, 0x6B, 0x09, 0x02, 0x07, 0xF8, 0x1E, 0x98, 0x17, 0x55, 0xD5, 0xA8, 0x82, 0x39, 0x4E, 0x75, 0x16, 0x69, 0x15, 0x34, 0x36, 0xF4, 0xD2, 0x3C, 0x55, 0xE0, 0x0D, 0x83, 0x2B, 0x4B, 0x4F, 0xD3, 0x4C, 0xE9, 0x14, 0xF7, 0x28, 0x74, 0x05};
        //uint8_t var2[] = {0x7D, 0x3B, 0x46, 0xF4, 0xA8, 0xAE, 0xF0, 0x18, 0x80, 0x75, 0x6F, 0xF8, 0xAF, 0xF7, 0x65, 0xFE, 0x31, 0xDE, 0x5F, 0xAD, 0x0C, 0x98, 0xE8, 0x51};

        //memcpy(K, var1, sizeof(var1));
        //memcpy(k, var2, sizeof(var2));


        #if uECC_VLI_NATIVE_LITTLE_ENDIAN
        bcopy((uint8_t *) _K,  K, num_bytes*2);
        bcopy((uint8_t *) _k,  k, num_bytes);
        #else
        uECC_vli_bytesToNative(_K, K, num_bytes);
        uECC_vli_bytesToNative(_K + num_words, K + num_bytes, num_bytes);
        uECC_vli_bytesToNative(_k, k, BITS_TO_BYTES(curve->num_n_bits));
        #endif
        
        // Compute Pu = Ru + K
        _addPoint(_Pu, _public, _K, curve);

        #if uECC_VLI_NATIVE_LITTLE_ENDIAN
        bcopy((uint8_t *) PU, (uint8_t *) _Pu, num_bytes);
        #else
        uECC_vli_nativeToBytes(PU, num_bytes, _Pu);
        uECC_vli_nativeToBytes(PU + num_bytes, num_bytes, _Pu + num_words);
        #endif

        // Compress PU
        uECC_compress(PU, compressed, curve);

        // Encode the CRT
        memcpy(crt, compressed, PT_COMPRESSED_SIZE);
        memcpy(crt+PT_COMPRESSED_SIZE, csr->id, ID_SIZE);

        // HASH mod curve_n
        //uSHA256(hash, crt, CRT_SIZE);
        //uSHA256(hashed, crt, CRT_SIZE);
        custom_hash(hash, crt, CRT_SIZE);
        bits2int(_e, hash, sizeof(hash), curve);
        
        // e*Pu
        _mulPoint(_ePu, _e, _Pu, curve);

        // ePU + Qca
        _addPoint(_ePuQca, _ePu, _public_ca, curve);
    }
    while (EccPoint_isZero(_ePuQca, curve)); // Check if ePU + Qca = 0

    // Compute r = ek + dca
    uECC_vli_modMult(_ek, _e, _k, curve->n, num_words);
    uECC_vli_modAdd(_r, _ek, _private_ca, curve->n, num_words);

    #if uECC_VLI_NATIVE_LITTLE_ENDIAN
    bcopy((uint8_t *) r, (uint8_t *) _r, num_bytes);
    #else
    uECC_vli_nativeToBytes(r, BITS_TO_BYTES(curve->num_n_bits), _r);
    #endif

    return 1;
}

void custom_hash(uint8_t *output, const uint8_t *input, uint8_t input_len) {
    uint8_t state[32] = {0};
    uint8_t counter = 0;
    uint8_t i, j;

    // Initialize state array with some "random" values
    for (i = 0; i < 32; ++i) {
        state[i] = (i * 59 + 31) ^ (i * 7 + 3);
    }

    // Mixing input into the state
    for (i = 0; i < input_len; ++i) {
        for (j = 0; j < 32; ++j) {
            state[j] ^= (input[i] + counter);
            state[j] = (state[j] << 3) | (state[j] >> 5);
            counter = (uint8_t)(counter + state[j] + j + i);
        }
    }

    // Additional rounds to make the output more "random"
    for (i = 0; i < 32; ++i) {
        for (j = 0; j < 32; ++j) {
            state[j] ^= counter;
            state[j] = (state[j] << 4) | (state[j] >> 4);
            counter = (uint8_t)(counter + state[j] + state[(j + 1) % 32]);
        }
    }

    // Copy the final state to the output
    for (i = 0; i < 32; ++i) {
        output[i] = state[i];
    }
}


void multiplyPrivates(uint8_t *res,
            const uint8_t *a,
            const uint8_t *b,
            const uECC_Curve curve) 
{
    uint8_t hash[32];
    uint8_t crt[25] = { 0xA2, 0x15, 0xF8, 0x9C, 0x71, 0xE3, 0x4D, 0xB6, 0x29, 0x87, 0x62, 0x95, 0x0E, 0x46, 0x5A, 0x7B, 0x3F, 0xD4, 0x9E, 0x10, 0xC2, 0x55, 0x88, 0x66, 0x77 };
    uSHA256(hash, crt, 25);
    wordcount_t num_words = curve->num_words;
    //wordcount_t num_bytes = curve->num_bytes;

    uECC_word_t _a[uECC_MAX_WORDS];
    uECC_word_t _b[uECC_MAX_WORDS]; 
    uECC_word_t _res[uECC_MAX_WORDS]; 
    uECC_word_t _ab[uECC_MAX_WORDS]; 
    uECC_word_t _e[uECC_MAX_WORDS]; 

    bits2int(_e, crt, sizeof(crt), curve);

    uECC_vli_bytesToNative(_a, a, BITS_TO_BYTES(curve->num_n_bits));
    uECC_vli_bytesToNative(_b, b, BITS_TO_BYTES(curve->num_n_bits));

    uECC_vli_modMult(_ab, _a, _e, curve->n, num_words);
    uECC_vli_modAdd(_res, _ab, _b, curve->n, num_words);

    uECC_vli_nativeToBytes(res, BITS_TO_BYTES(curve->num_n_bits), _res);
}

int crt_pk_extract(uint8_t *extracted,
                   const uint8_t *crt, 
                   const uint8_t *public_ca,
                   const uECC_Curve curve) {

    wordcount_t num_words = curve->num_words;
    wordcount_t num_bytes = curve->num_bytes;

    uint8_t hash[32]; // TODO

    uECC_word_t _e[uECC_MAX_WORDS]          = { 0 };
    uECC_word_t _ePu[uECC_MAX_WORDS * 2]    = { 0 };
    uECC_word_t _ePuQca[uECC_MAX_WORDS * 2] = { 0 };

    uint8_t compressed[PT_COMPRESSED_SIZE] = { 0 };
    uint8_t public[PUBLIC_SIZE] = { 0 };

    #if uECC_VLI_NATIVE_LITTLE_ENDIAN
    uECC_word_t *_public_ca = (uECC_word_t *)public_ca;
    uECC_word_t *_public  = (uECC_word_t *)public;

    bcopy((uint8_t *) _public_ca, _public_ca, num_bytes*2);
    #else
    uECC_word_t _public_ca[uECC_MAX_WORDS * 2];
    uECC_word_t _public[uECC_MAX_WORDS * 2];

    uECC_vli_bytesToNative(_public_ca, public_ca, num_bytes);
    uECC_vli_bytesToNative(_public_ca + num_words, public_ca + num_bytes, num_bytes);
    #endif

    // Extract and decompress the point from the crt
    memcpy(compressed, crt, PT_COMPRESSED_SIZE);
    uECC_decompress(compressed, public, curve);

    // Validate the extracted public key
    if (!uECC_valid_public_key(public, curve)) {
        return 0;
    }

    #if uECC_VLI_NATIVE_LITTLE_ENDIAN
    bcopy((uint8_t *) _public, _public, num_bytes*2);
    #else
    uECC_vli_bytesToNative(_public, public, num_bytes);
    uECC_vli_bytesToNative(_public + num_words, public + num_bytes, num_bytes);
    #endif

    // e = H(crt) mod n
    //uSHA256(hash, crt, CRT_SIZE);
    custom_hash(hash, crt, CRT_SIZE);
    bits2int(_e, hash, sizeof(hash), curve);

    // e*PU
    _mulPoint(_ePu, _e, _public, curve);

    // ePU + Qca
    _addPoint(_ePuQca, _ePu, _public_ca, curve);

    #if uECC_VLI_NATIVE_LITTLE_ENDIAN
    bcopy((uint8_t *) extracted, (uint8_t *) _ePuQca, num_bytes*2);
    #else
    uECC_vli_nativeToBytes(extracted, num_bytes, _ePuQca);
    uECC_vli_nativeToBytes(extracted + num_bytes, num_bytes, _ePuQca + num_words);
    #endif

    return 1;
}

int crt_validation(uint8_t *extracted,
                   uint8_t *private,
                   const uint8_t *crt, 
                   const uint8_t *r,
                   const uint8_t *private_csr,
                   const uint8_t *public_ca,
                   const uECC_Curve curve) {

    wordcount_t num_words = curve->num_words;
    wordcount_t num_bytes = curve->num_bytes;

    uint8_t extracted_test[PUBLIC_SIZE];
    unsigned char hash[32]; // TODO

    uECC_word_t _e[uECC_MAX_WORDS]          = { 0 };
    uECC_word_t _ek[uECC_MAX_WORDS]         = { 0 };
    uECC_word_t _ePu[uECC_MAX_WORDS * 2]    = { 0 };
    uECC_word_t _ePuQca[uECC_MAX_WORDS * 2] = { 0 };

    uint8_t compressed[PT_COMPRESSED_SIZE] = { 0 };
    uint8_t public[PUBLIC_SIZE] = { 0 };

    #if uECC_VLI_NATIVE_LITTLE_ENDIAN
    uECC_word_t *_private   = (uECC_word_t *)private;
    uECC_word_t *_r         = (uECC_word_t *)r;
    uECC_word_t *_ku        = (uECC_word_t *)private_csr;
    uECC_word_t *_public_ca = (uECC_word_t *)public_ca;
    uECC_word_t *_public  = (uECC_word_t *)public;

    bcopy((uint8_t *) _public_ca, public_ca, num_bytes*2);
    bcopy((uint8_t *) _ku, private_csr, num_bytes);
    bcopy((uint8_t *) _r, r, num_bytes);
    #else
    uECC_word_t _private[uECC_MAX_WORDS];
    uECC_word_t _r[uECC_MAX_WORDS];
    uECC_word_t _ku[uECC_MAX_WORDS];
    uECC_word_t _public_ca[uECC_MAX_WORDS * 2];
    uECC_word_t _public[uECC_MAX_WORDS * 2];

    uECC_vli_bytesToNative(_public_ca, public_ca, num_bytes);
    uECC_vli_bytesToNative(_public_ca + num_words, public_ca + num_bytes, num_bytes);
    uECC_vli_bytesToNative(_ku, private_csr, num_bytes);
    uECC_vli_bytesToNative(_r, r, num_bytes);
    #endif

    // Extract and decompress the point from the crt
    memcpy(compressed, crt, PT_COMPRESSED_SIZE);
    uECC_decompress(compressed, public, curve);

    // Validate the extracted public key
    if (!uECC_valid_public_key(public, curve)) {
        return 0;       
    }

    #if uECC_VLI_NATIVE_LITTLE_ENDIAN
    bcopy((uint8_t *) _public, public, num_bytes*2);
    #else
    uECC_vli_bytesToNative(_public, public, num_bytes);
    uECC_vli_bytesToNative(_public + num_words, public + num_bytes, num_bytes);
    #endif

    // e = H(crt) mod n
    //uSHA256(hash, crt, CRT_SIZE);
    custom_hash(hash, crt, CRT_SIZE);
    bits2int(_e, hash, sizeof(hash), curve);

    // e*PU
    _mulPoint(_ePu, _e, _public, curve);

    // ePU + Qca
    _addPoint(_ePuQca, _ePu, _public_ca, curve);

    // du = r + eku mod n
    uECC_vli_modMult(_ek, _e, _ku, curve->n, num_words);
    uECC_vli_modAdd(_private, _ek, _r, curve->n, num_words);

     #if uECC_VLI_NATIVE_LITTLE_ENDIAN
     bcopy((uint8_t *) extracted, (uint8_t *) _ePuQca, num_bytes*2);
     bcopy((uint8_t *) private, (uint8_t *) _private, num_bytes);
     #else
     uECC_vli_nativeToBytes(extracted, num_bytes, _ePuQca);
     uECC_vli_nativeToBytes(extracted + num_bytes, num_bytes, _ePuQca + num_words);
     uECC_vli_nativeToBytes(private, BITS_TO_BYTES(curve->num_n_bits), _private);
     #endif

     // Qu' = du * G
     if (!uECC_compute_public_key(private, extracted_test, curve)) {
         return 0;
     }

     // Qu' == Qu ?
     if (!memcmp(extracted, extracted_test, PUBLIC_SIZE))
         return 1;
     else
         return 0;

}

int homqv_generate_key(uint8_t *key,
                       uint8_t *Y,
                       uint8_t *extracted, 
                       const uint8_t *crt,
                       const uint8_t *private_ca, 
                       const uint8_t *public_ca,
                       const uint8_t *id_cluster,
                       int x509,
                       const uECC_Curve curve) {

    if(!x509) {
        crt_pk_extract(extracted, crt, public_ca, curve);
    }

    wordcount_t num_words = curve->num_words;
    wordcount_t num_bytes = curve->num_bytes;

    uint8_t y[PRIVATE_SIZE]                              = {0};
    uint8_t id[ID_SIZE]                                  = {0};
    uint8_t Yid[PUBLIC_SIZE + ID_SIZE]                   = {0};
    uint8_t sigma[PUBLIC_SIZE]                           = {0};
    uint8_t sigmaId1Id2Y[PUBLIC_SIZE + ID_SIZE + ID_SIZE + PUBLIC_SIZE] = {0};
    
    uint8_t hash[32];

    uECC_word_t _e[uECC_MAX_WORDS]          = { 0 };
    uECC_word_t _eb[uECC_MAX_WORDS]         = { 0 };
    uECC_word_t _yeb[uECC_MAX_WORDS]         = { 0 };
    uECC_word_t _sigma[uECC_MAX_WORDS * 2]    = { 0 };
	    
    #if uECC_VLI_NATIVE_LITTLE_ENDIAN
    uECC_word_t *_extracted  = (uECC_word_t *)extracted;
    uECC_word_t *_public_ca  = (uECC_word_t *)public_ca;
    uECC_word_t *_private_ca = (uECC_word_t *)private_ca;
    uECC_word_t *_Y          = (uECC_word_t *)Y;
    uECC_word_t *_y          = (uECC_word_t *)y;
    #else
    uECC_word_t _extracted[uECC_MAX_WORDS * 2];
    uECC_word_t _public_ca[uECC_MAX_WORDS * 2];
    uECC_word_t _private_ca[uECC_MAX_WORDS];
    uECC_word_t _Y[uECC_MAX_WORDS * 2];
    uECC_word_t _y[uECC_MAX_WORDS];
    #endif

    #if uECC_VLI_NATIVE_LITTLE_ENDIAN
    bcopy((uint8_t *) _extracted,     extracted,     num_bytes*2);
    bcopy((uint8_t *) _public_ca,  public_ca,  num_bytes*2);
    bcopy((uint8_t *) _private_ca, private_ca, num_bytes);
    #else
    uECC_vli_bytesToNative(_extracted, extracted, num_bytes);
    uECC_vli_bytesToNative(_extracted + num_words, extracted + num_bytes, num_bytes);
    uECC_vli_bytesToNative(_public_ca, public_ca, num_bytes);
    uECC_vli_bytesToNative(_public_ca + num_words, public_ca + num_bytes, num_bytes);
    uECC_vli_bytesToNative(_private_ca, private_ca, BITS_TO_BYTES(curve->num_n_bits));
    #endif
	
	// Generate a new key-pair y, yG
	if (! uECC_make_key(Y, y, curve)) {
		return 0;
	}  

    //uint8_t var1[] = {0x4C, 0xF2, 0xD6, 0x6C, 0x0B, 0x83, 0xA8, 0x7B, 0x28, 0x08, 0x43, 0xDD, 0x44, 0x89, 0x8A, 0x35, 0xDF, 0x6A, 0xF0, 0x8D, 0xF0, 0xAC, 0x6B, 0xC3, 0xB6, 0xF4, 0x18, 0x8C, 0xD8, 0x3F, 0xA3, 0xF3, 0x15, 0xDF, 0x7B, 0x82, 0xF7, 0xD9, 0xEC, 0xF3, 0x3F, 0x6B, 0x21, 0xE6, 0x2A, 0xD4, 0x04, 0x13};
    //uint8_t var2[] = {0xED, 0x46, 0x13, 0xF2, 0x91, 0xA9, 0xE8, 0x17, 0xC6, 0xB3, 0xCA, 0x3C, 0xA7, 0x1F, 0x1C, 0x49, 0xE1, 0xFA, 0x68, 0xB1, 0x4F, 0x1C, 0xFB, 0x1D};;


    //memcpy(Y, var1, sizeof(var1));
    //memcpy(y, var2, sizeof(var2));

    #if uECC_VLI_NATIVE_LITTLE_ENDIAN
    bcopy((uint8_t *) _Y,  Y, num_bytes*2);
    bcopy((uint8_t *) _y,  y, num_bytes);
    #else
    uECC_vli_bytesToNative(_Y, Y, num_bytes);
    uECC_vli_bytesToNative(_Y + num_words, Y + num_bytes, num_bytes);
    uECC_vli_bytesToNative(_y, y, BITS_TO_BYTES(curve->num_n_bits));
    #endif

    memcpy(id, crt+PT_COMPRESSED_SIZE, ID_SIZE);
    memcpy(Yid, Y, PUBLIC_SIZE);
    memcpy(Yid+PUBLIC_SIZE, id, ID_SIZE);
    
    // e = H(Y, IDnode)
    //uSHA256(hash, Yid, PUBLIC_SIZE + ID_SIZE);
    custom_hash(hash, Yid, PUBLIC_SIZE + ID_SIZE);
    bits2int(_e, hash, sizeof(hash), curve);

    // y + eb (mod n)
    uECC_vli_modMult(_eb, _e, _private_ca, curve->n, num_words);
    uECC_vli_modAdd(_yeb, _eb, _y, curve->n, num_words);

    // (y + eb)*extracted_public
    _mulPoint(_sigma, _yeb, _extracted, curve);

    #if uECC_VLI_NATIVE_LITTLE_ENDIAN
    bcopy((uint8_t *) sigma, (uint8_t *) _sigma, num_bytes*2);
    #else
    uECC_vli_nativeToBytes(sigma, num_bytes, _sigma);
    uECC_vli_nativeToBytes(sigma + num_bytes, num_bytes, _sigma + num_words);
    #endif

    memcpy(sigmaId1Id2Y, sigma, PUBLIC_SIZE);
    memcpy(sigmaId1Id2Y+PUBLIC_SIZE, id, ID_SIZE);
    memcpy(sigmaId1Id2Y+PUBLIC_SIZE+ID_SIZE, id_cluster, ID_SIZE);
    memcpy(sigmaId1Id2Y+PUBLIC_SIZE+ID_SIZE+ID_SIZE, Y, PUBLIC_SIZE);

    //uSHA256(key, sigmaId1Id2Y, PUBLIC_SIZE + ID_SIZE + ID_SIZE);
    custom_hash(key, sigmaId1Id2Y, PUBLIC_SIZE + ID_SIZE + ID_SIZE);

    return 1;

}

int homqv_regenerate_key(uint8_t *key,
                   const uint8_t *Y, 
                   const uint8_t *public_ca,
                   const uint8_t *private,
                   const uint8_t *id_cluster,
                   const uint8_t *id,
                   const uECC_Curve curve) {

    wordcount_t num_words = curve->num_words;
    wordcount_t num_bytes = curve->num_bytes;

    uint8_t sigma[PUBLIC_SIZE]                                          = {0};
    uint8_t hash[32];
    uint8_t Yid[PUBLIC_SIZE + ID_SIZE]                                  = {0};
    uint8_t sigmaId1Id2Y[PUBLIC_SIZE + ID_SIZE + ID_SIZE + PUBLIC_SIZE] = {0};

    uECC_word_t _e[uECC_MAX_WORDS]          = { 0 };
    uECC_word_t _ePu[uECC_MAX_WORDS * 2]    = { 0 };
    uECC_word_t _ePuY[uECC_MAX_WORDS * 2]    = { 0 };
    uECC_word_t _sigma[uECC_MAX_WORDS * 2]    = { 0 };


    #if uECC_VLI_NATIVE_LITTLE_ENDIAN
    uECC_word_t *_public_ca  = (uECC_word_t *)public_ca;
    uECC_word_t *_Y          = (uECC_word_t *)Y;
    uECC_word_t *_private = (uECC_word_t *)private;
    #else
    uECC_word_t _public_ca[uECC_MAX_WORDS * 2];
    uECC_word_t _Y[uECC_MAX_WORDS * 2];
    uECC_word_t _private[uECC_MAX_WORDS];
    #endif

    #if uECC_VLI_NATIVE_LITTLE_ENDIAN
    bcopy((uint8_t *) _public_ca,  public_ca,  num_bytes*2);
    bcopy((uint8_t *) _Y,  Y,  num_bytes*2);
    bcopy((uint8_t *) _private, private, num_bytes);
    #else
    uECC_vli_bytesToNative(_public_ca, public_ca, num_bytes);
    uECC_vli_bytesToNative(_public_ca + num_words, public_ca + num_bytes, num_bytes);
    uECC_vli_bytesToNative(_Y, Y, num_bytes);
    uECC_vli_bytesToNative(_Y + num_words, Y + num_bytes, num_bytes);
    uECC_vli_bytesToNative(_private, private, BITS_TO_BYTES(curve->num_n_bits));
    #endif

    memcpy(Yid, Y, PUBLIC_SIZE);
    memcpy(Yid+PUBLIC_SIZE, id, ID_SIZE);

    // e = H(Y, IDnode)
    //uSHA256(hash, Yid, PUBLIC_SIZE + ID_SIZE);
    custom_hash(hash, Yid, PUBLIC_SIZE + ID_SIZE);
    bits2int(_e, hash, sizeof(hash), curve);

    // e*Pubca
    _mulPoint(_ePu, _e, _public_ca, curve);

    // ePU + Y
    _addPoint(_ePuY, _ePu, _Y, curve);

    _mulPoint(_sigma, _private, _ePuY, curve);

    #if uECC_VLI_NATIVE_LITTLE_ENDIAN
    bcopy((uint8_t *) sigma, (uint8_t *) _sigma, num_bytes*2);
    #else
    uECC_vli_nativeToBytes(sigma, num_bytes, _sigma);
    uECC_vli_nativeToBytes(sigma + num_bytes, num_bytes, _sigma + num_words);
    #endif

    memcpy(sigmaId1Id2Y, sigma, PUBLIC_SIZE);
    memcpy(sigmaId1Id2Y+PUBLIC_SIZE, id, ID_SIZE);
    memcpy(sigmaId1Id2Y+PUBLIC_SIZE+ID_SIZE, id_cluster, ID_SIZE);
    memcpy(sigmaId1Id2Y+PUBLIC_SIZE+ID_SIZE+ID_SIZE, Y, PUBLIC_SIZE);

    //uSHA256(key, sigmaId1Id2Y, PUBLIC_SIZE + ID_SIZE + ID_SIZE);
    custom_hash(key, sigmaId1Id2Y, PUBLIC_SIZE + ID_SIZE + ID_SIZE);

    return 1;

}


int csr_standard_request(struct CertificationRequest *csr, 
                uint8_t *private, 
                const uint8_t id[ID_SIZE],
                const uECC_Curve curve) {
                
    uint8_t public[PUBLIC_SIZE] = {0};             
    uint8_t compressed[PT_COMPRESSED_SIZE] = {0};

    // Generate key-pair
    if (! uECC_make_key(public, private, curve)) {
        return 0;
    }

    // Compress point
    uECC_compress(public, compressed, curve);

    memcpy(csr->id, id, ID_SIZE);
    memcpy(csr->sensor_public_key, public, PUBLIC_SIZE);
    strcpy(csr->sensor_name, "Sensor 1");
    strcpy(csr->attributes, "Sensor A");

    return 1;
}

int crt_standard_generation(struct CertificationRequest *csr,
                   struct Certificate *cert, 
                   const uint8_t *private_standard_ca, 
                   const uint8_t *public_standard_ca,
                   const uECC_Curve curve) {
 
  uint8_t certForHash[NAME_SIZE + ID_SIZE + PUBLIC_SIZE + ATTRIB_SIZE]                                  = {0};
  uint8_t hash[32] = {0};

  strcpy(cert->sensor_name, csr->sensor_name);
  strcpy(cert->attributes, csr->attributes);
  memcpy(cert->sensor_public_key, csr->sensor_public_key, PUBLIC_SIZE);
  memcpy(cert->id, csr->id, ID_SIZE);
  //memcpy(cert->signature, signature, sizeof(signature));  

  memcpy(certForHash, cert->sensor_name, NAME_SIZE);
  memcpy(certForHash + NAME_SIZE, cert->id, ID_SIZE);
  memcpy(certForHash + NAME_SIZE + ID_SIZE, cert->sensor_public_key, PUBLIC_SIZE);
  memcpy(certForHash + NAME_SIZE + ID_SIZE + PUBLIC_SIZE, cert->attributes, ATTRIB_SIZE);

  uSHA256(hash, certForHash, NAME_SIZE + ID_SIZE + PUBLIC_SIZE + ATTRIB_SIZE);
  memcpy(cert->hash, hash, 32);

  if(!uECC_sign(private_standard_ca, cert->hash, 32, cert->signature, curve)) {
    printf("uECC_sign() failed\n");
    return 0;
  }
  return 1;
}

int crt_standard_verify(struct Certificate *cert, 
                   const uint8_t *private_standard_ca, 
                   const uint8_t *public_standard_ca,
                   const uECC_Curve curve) {

  uint8_t hash[32]; 
  uint8_t certForHash[NAME_SIZE + PUBLIC_SIZE + ID_SIZE + ATTRIB_SIZE]                                  = {0};

  memcpy(certForHash, cert->sensor_name, NAME_SIZE);
  memcpy(certForHash + NAME_SIZE, cert->id, ID_SIZE);
  memcpy(certForHash+NAME_SIZE+ID_SIZE, cert->sensor_public_key, PUBLIC_SIZE);
  memcpy(certForHash+NAME_SIZE+ID_SIZE+PUBLIC_SIZE, cert->attributes, ATTRIB_SIZE);

  uSHA256(hash, certForHash, NAME_SIZE + ID_SIZE + PUBLIC_SIZE + ATTRIB_SIZE);

  if (uECC_verify(public_standard_ca, hash, 32, cert->signature, curve)) {
    //printf("signature verify success\n");
    return 1;
  }
  else {
    return 0;
  }

}

int crt_selfsign_generation(uint8_t *private_key,
                            uint8_t *crt,
                            const uint8_t *id,
                            const uECC_Curve curve) {

    wordcount_t num_words = curve->num_words;
    wordcount_t num_bytes = curve->num_bytes;

    uint8_t public_tmp[PUBLIC_SIZE];
    uint8_t private_tmp[PRIVATE_SIZE];
    uint8_t compressed[PT_COMPRESSED_SIZE];
    uint8_t hash[32];

    uECC_word_t _e[uECC_MAX_WORDS];
    uECC_word_t _private_key[uECC_MAX_WORDS];

    // Generate key-pair
    if (! uECC_make_key(public_tmp, private_tmp, curve)) {
        return 0;
    }

#if uECC_VLI_NATIVE_LITTLE_ENDIAN
    uECC_word_t *_private_tmp = (uECC_word_t *)private_tmp;
#else
    uECC_word_t _private_tmp[uECC_MAX_WORDS];
    uECC_vli_bytesToNative(_private_tmp, private_tmp, num_bytes);
#endif

    // Compress PU
    uECC_compress(public_tmp, compressed, curve);

    // Encode the CRT
    memcpy(crt, compressed, PT_COMPRESSED_SIZE);
    memcpy(crt+PT_COMPRESSED_SIZE, id, ID_SIZE);

    // HASH mod curve_n
    uSHA256(hash, crt, CRT_SIZE);
    bits2int(_e, hash, sizeof(hash), curve);

    // Compute du = eku
    uECC_vli_modMult(_private_key, _e, _private_tmp, curve->n, num_words);

#if uECC_VLI_NATIVE_LITTLE_ENDIAN
    bcopy((uint8_t *) private_key, (uint8_t *) _private_key, num_bytes);
#else
    uECC_vli_nativeToBytes(private_key, BITS_TO_BYTES(curve->num_n_bits), _private_key);
#endif

    return 1;
}

int selfcrt_pk_extract(uint8_t *public_key,
                       const uint8_t *self_crt,
                       const uECC_Curve curve) {

    wordcount_t num_words = curve->num_words;
    wordcount_t num_bytes = curve->num_bytes;

    uint8_t compressed[PT_COMPRESSED_SIZE];
    uint8_t public_tmp[PUBLIC_SIZE];
    uint8_t hash[32];

    uECC_word_t _e[uECC_MAX_WORDS];
    uECC_word_t _ePu[uECC_MAX_WORDS * 2];
    uECC_word_t _public_tmp[uECC_MAX_WORDS * 2];

    // Extract and decompress the point from the crt
    memcpy(compressed, self_crt, PT_COMPRESSED_SIZE);
    uECC_decompress(compressed, public_tmp, curve);

    // Validate the extracted public key
    if (!uECC_valid_public_key(public_tmp, curve)) {
        return 0;
    }

#if uECC_VLI_NATIVE_LITTLE_ENDIAN
    bcopy((uint8_t *) _public_tmp, public_tmp, num_bytes*2);
#else
    uECC_vli_bytesToNative(_public_tmp, public_tmp, num_bytes);
    uECC_vli_bytesToNative(_public_tmp + num_words, public_tmp + num_bytes, num_bytes);
#endif

    // HASH mod curve_n
    uSHA256(hash, self_crt, CRT_SIZE);
    bits2int(_e, hash, sizeof(hash), curve);

    // e*PU
    _mulPoint(_ePu, _e, _public_tmp, curve);

#if uECC_VLI_NATIVE_LITTLE_ENDIAN
    bcopy((uint8_t *) public_key, (uint8_t *) _ePu, num_bytes*2);
#else
    uECC_vli_nativeToBytes(public_key, num_bytes, _ePu);
    uECC_vli_nativeToBytes(public_key + num_bytes, num_bytes, _ePu + num_words);
#endif

    return 1;
}

void addPoint(uint8_t *sum,
             const uint8_t *p1,
             const uint8_t *p2,
             const uECC_Curve curve) {
    
    wordcount_t num_words = curve->num_words;
    wordcount_t num_bytes = curve->num_bytes;

    #if uECC_VLI_NATIVE_LITTLE_ENDIAN
    uECC_word_t *_p1 = (uECC_word_t *)p1;
    uECC_word_t *_p2 = (uECC_word_t *)p2;
    uECC_word_t *_sum = (uECC_word_t *)sum;


    bcopy((uint8_t *) _p1, p1, num_bytes*2);
    bcopy((uint8_t *) _p2, p2, num_bytes*2);
    bcopy((uint8_t *) _sum, sum, num_bytes*2);
    #else
    uECC_word_t _p1[uECC_MAX_WORDS * 2];
    uECC_word_t _p2[uECC_MAX_WORDS * 2];
    uECC_word_t _sum[uECC_MAX_WORDS * 2];

    uECC_vli_bytesToNative(_p1, p1, num_bytes);
    uECC_vli_bytesToNative(_p1 + num_words, p1 + num_bytes, num_bytes);
    uECC_vli_bytesToNative(_p2, p2, num_bytes);
    uECC_vli_bytesToNative(_p2 + num_words, p2 + num_bytes, num_bytes);
    uECC_vli_bytesToNative(_sum, sum, num_bytes);
    uECC_vli_bytesToNative(_sum + num_words, sum + num_bytes, num_bytes);
    #endif

    _addPoint(_sum, _p1, _p2, curve);

    #if uECC_VLI_NATIVE_LITTLE_ENDIAN
    bcopy((uint8_t *) sum, (uint8_t *) _sum, num_bytes*2);
    #else
    uECC_vli_nativeToBytes(sum, curve->num_bytes, _sum);
    uECC_vli_nativeToBytes(sum + curve->num_bytes, curve->num_bytes, _sum + curve->num_words);
    #endif
}

void mulPoint(uint8_t *mul,
             const uint8_t *s,
             const uint8_t *p,
             const uECC_Curve curve) {

    wordcount_t num_words = curve->num_words;
    wordcount_t num_bytes = curve->num_bytes;

    #if uECC_VLI_NATIVE_LITTLE_ENDIAN
    uECC_word_t *_p = (uECC_word_t *)p;
    uECC_word_t *_mul = (uECC_word_t *)mul;
    uECC_word_t *_s = (uECC_word_t *)s;

    bcopy((uint8_t *) _p, p, num_bytes*2);
    bcopy((uint8_t *) _mul, mul, num_bytes*2);
    bcopy((uint8_t *) _s, s, num_bytes);
    #else
    uECC_word_t _p[uECC_MAX_WORDS * 2];
    uECC_word_t _mul[uECC_MAX_WORDS * 2];
    uECC_word_t _s[uECC_MAX_WORDS];

    uECC_vli_bytesToNative(_p, p, num_bytes);
    uECC_vli_bytesToNative(_p + num_words, p + num_bytes, num_bytes);
    uECC_vli_bytesToNative(_mul, mul, num_bytes);
    uECC_vli_bytesToNative(_mul + num_words, mul + num_bytes, num_bytes);
    uECC_vli_bytesToNative(_s, s, BITS_TO_BYTES(curve->num_n_bits));
    #endif

    _mulPoint(_mul, _s, _p, curve);

    #if uECC_VLI_NATIVE_LITTLE_ENDIAN
    bcopy((uint8_t *) mul, (uint8_t *) _mul, num_bytes*2);
    #else
    uECC_vli_nativeToBytes(mul, curve->num_bytes, _mul);
    uECC_vli_nativeToBytes(mul + curve->num_bytes, curve->num_bytes, _mul + curve->num_words);
    #endif
}

void _addPoint(uECC_word_t *_sum,
              const uECC_word_t *_p1,  
              const uECC_word_t *_p2,
              const uECC_Curve curve) {

    wordcount_t num_words = curve->num_words;

    uECC_word_t _kx[uECC_MAX_WORDS];
    uECC_word_t _ky[uECC_MAX_WORDS];
    uECC_word_t _z[uECC_MAX_WORDS];

    uECC_vli_set(_sum, _p1, num_words);
    uECC_vli_set(_sum + num_words, _p1 + num_words, num_words);
    uECC_vli_set(_kx, _p2, num_words);
    uECC_vli_set(_ky, _p2 + num_words, num_words);
    uECC_vli_modSub(_z, _sum, _kx, curve->p, num_words);
    XYcZ_add(_kx, _ky, _sum, _sum + num_words, curve);
    uECC_vli_modInv(_z, _z, curve->p, num_words);
    apply_z(_sum, _sum + num_words, _z, curve);
}

void _mulPoint(uECC_word_t *_mul,
              const uECC_word_t *_s,  
              const uECC_word_t *_p,
              const uECC_Curve curve) {
    
    uECC_word_t tmp1[uECC_MAX_WORDS];
    uECC_word_t tmp2[uECC_MAX_WORDS];
    uECC_word_t *p2[2] = {tmp1, tmp2};
    uECC_word_t carry = regularize_k(_s, tmp1, tmp2, curve);

    EccPoint_mult(_mul, _p, p2[!carry], 0, curve->num_n_bits + 1, curve);
}

void pack_timestamp(uint8_t *buffer, time_t timestamp) {
    buffer[0] = (timestamp >> 24) & 0xFF;
    buffer[1] = (timestamp >> 16) & 0xFF;
    buffer[2] = (timestamp >> 8) & 0xFF;
    buffer[3] = timestamp & 0xFF;
}

int reg_request(uint8_t *req, uint8_t *id) {
    uint8_t buffer[4];
    time_t current_time;
    
    time(&current_time);
    pack_timestamp(buffer, current_time);
    
    memcpy(req, id, ID_SIZE);
    memcpy(req+ID_SIZE, buffer, 4);
    return 1;
}

int register_device(uint8_t *private_key, 
                    uint8_t *public_key, 
                    uint8_t *m, 
                    uint8_t *id,
                    uint8_t *private_ca,
                    uint8_t *l,
                    const uECC_Curve curve) {
    uint8_t part1[PRIVATE_SIZE + ID_SIZE] = {0};
    uint8_t part2[PRIVATE_SIZE + ID_SIZE] = {0};
    uint8_t hash1[32];
    uint8_t hash2[32];

    // Generate key-pair
    if (! uECC_make_key(public_key, private_key, curve)) {
        return 0;
    }

    memcpy(part1, private_key, PRIVATE_SIZE);
    memcpy(part1 + PRIVATE_SIZE, id, ID_SIZE);

    memcpy(part2, private_ca, PRIVATE_SIZE);
    memcpy(part2 + PRIVATE_SIZE, id, ID_SIZE);

    custom_hash(hash1, part1, PRIVATE_SIZE + ID_SIZE);
    custom_hash(hash2, part2, PRIVATE_SIZE + ID_SIZE);

    memcpy(m, hash2, 32);

    for (int i = 0; i < 32; ++i) {
        l[i] = hash1[i] ^ hash2[i];
    }

    return 1;
}

int hashAuth(uint8_t *auth, 
             uint8_t *r1, 
             uint8_t *tobu, 
             uint8_t *id, 
             uint8_t *private_key,
             uint8_t *m,
             const uECC_Curve curve) {

    time_t current_time;
    uint8_t R2[PUBLIC_SIZE];
    uint8_t part1[PRIVATE_SIZE + ID_SIZE] = {0};
    uint8_t part2[PUBLIC_SIZE + ID_SIZE + 4 + 32] = {0};
    wordcount_t num_words = curve->num_words;
    wordcount_t num_bytes = curve->num_bytes;

    uECC_word_t _pkey[uECC_MAX_WORDS]          = { 0 };
    uECC_word_t _R2[uECC_MAX_WORDS * 2]        = { 0 };
    uECC_word_t _R1[uECC_MAX_WORDS * 2]        = { 0 };
    uECC_vli_bytesToNative(_pkey, private_key, num_bytes);


    uint8_t R1[PUBLIC_SIZE];
    // Generate key-pair
    if (! uECC_make_key(R1, r1, curve)) {
        return 0;
    }

    time(&current_time);
    pack_timestamp(tobu, current_time);

    uECC_vli_bytesToNative(_R1, R1, num_bytes);
    uECC_vli_bytesToNative(_R1 + num_words, R1 + num_bytes, num_bytes);

    // e*PU
    _mulPoint(_R2, _pkey, _R1, curve);

    uECC_vli_nativeToBytes(R2, num_bytes, _R2);
    uECC_vli_nativeToBytes(R2 + num_bytes, num_bytes, _R2 + num_words);

    uint8_t hash1[32];
    memcpy(part1, private_key, PRIVATE_SIZE);
    memcpy(part1 + PRIVATE_SIZE, id, ID_SIZE);
    custom_hash(hash1, part1, PRIVATE_SIZE + ID_SIZE);

    uint8_t token[32];
    for (int i = 0; i < 32; ++i) {
        token[i] = hash1[i] ^ m[i];
    }
    memcpy(part2, R2, PUBLIC_SIZE);
    memcpy(part2 + PUBLIC_SIZE, id, ID_SIZE);
    memcpy(part2 + PUBLIC_SIZE + ID_SIZE, tobu, 4);
    memcpy(part2 + PUBLIC_SIZE + ID_SIZE + 4, token, 32);

    custom_hash(auth, part2, PUBLIC_SIZE + ID_SIZE + 4 + 32);
    return 1;
}

int checkAuth(uint8_t *auth,
              uint8_t *compressed, 
              uint8_t *r1, 
              uint8_t *id, 
              uint8_t *tobu, 
              uint8_t *l,
              const uECC_Curve curve) {

    uint8_t public_key[PUBLIC_SIZE];
    uint8_t RES[PUBLIC_SIZE];
    uint8_t part[PUBLIC_SIZE + ID_SIZE + 4 + 32] = {0};
    uint8_t authnew[32];

    uECC_decompress(compressed, public_key, curve);


    wordcount_t num_words = curve->num_words;
    wordcount_t num_bytes = curve->num_bytes;

    uECC_word_t _r1[uECC_MAX_WORDS]          = { 0 };
    uECC_word_t _public_key[uECC_MAX_WORDS * 2]        = { 0 };
    uECC_word_t _RES[uECC_MAX_WORDS * 2]        = { 0 };
    uECC_vli_bytesToNative(_r1, r1, num_bytes);   

    uECC_vli_bytesToNative(_public_key, public_key, num_bytes);
    uECC_vli_bytesToNative(_public_key + num_words, public_key + num_bytes, num_bytes);

    _mulPoint(_RES, _r1, _public_key, curve);

    uECC_vli_nativeToBytes(RES, num_bytes, _RES);
    uECC_vli_nativeToBytes(RES + num_bytes, num_bytes, _RES + num_words);

    memcpy(part, RES, PUBLIC_SIZE);
    memcpy(part + PUBLIC_SIZE, id, ID_SIZE);
    memcpy(part + PUBLIC_SIZE + ID_SIZE, tobu, 4);
    memcpy(part + PUBLIC_SIZE + ID_SIZE + 4, l, 32);

    custom_hash(authnew, part, PUBLIC_SIZE + ID_SIZE + 4 + 32);

      if (!memcmp(authnew, auth, 32))
         return 1;
     else
         return 0;   
}
int computeAuth(uint8_t *authsm, 
                uint8_t *r2, 
                uint8_t *private_ca,
                uint8_t *id, 
                uint8_t *tobu, 
                uint8_t *tsm, 
                uint8_t *l, 
                uint8_t *shared_key1, 
                const uECC_Curve curve) {

    time_t current_time;
    uint8_t R4[PUBLIC_SIZE];
    uint8_t part1[PUBLIC_SIZE + 4 + 32] = {0};
    uint8_t part2[ID_SIZE + 32 + 4 + 4] = {0};
    wordcount_t num_words = curve->num_words;
    wordcount_t num_bytes = curve->num_bytes;

    uECC_word_t _private_ca[uECC_MAX_WORDS]          = { 0 };
    uECC_word_t _R4[uECC_MAX_WORDS * 2]        = { 0 };
    uECC_word_t _R3[uECC_MAX_WORDS * 2]        = { 0 };
    uECC_vli_bytesToNative(_private_ca, private_ca, num_bytes);


    uint8_t R3[PUBLIC_SIZE];
    // Generate key-pair
    if (! uECC_make_key(R3, r2, curve)) {
        return 0;
    }

    time(&current_time);
    pack_timestamp(tsm, current_time);

    uECC_vli_bytesToNative(_R3, R3, num_bytes);
    uECC_vli_bytesToNative(_R3 + num_words, R3 + num_bytes, num_bytes);

    // e*PU
    _mulPoint(_R4, _private_ca, _R3, curve);

    uECC_vli_nativeToBytes(R4, num_bytes, _R4);
    uECC_vli_nativeToBytes(R4 + num_bytes, num_bytes, _R4 + num_words);

    memcpy(part1, R4, PUBLIC_SIZE);
    memcpy(part1 + PUBLIC_SIZE, tsm, 4);
    memcpy(part1 + PUBLIC_SIZE + 4, l, 32);
    custom_hash(authsm, part1, PUBLIC_SIZE + 4 + 32);

    memcpy(part2, id, ID_SIZE);
    memcpy(part2 + ID_SIZE, l, 32);
    memcpy(part2 + ID_SIZE + 4, tobu, 4);
    memcpy(part2 + ID_SIZE + 4 + 4, tsm, 4);

    custom_hash(shared_key1, part2, ID_SIZE + 32 + 4 + 4);
    return 1;

}

int checkAuthSM(uint8_t *authsm, 
                uint8_t *public_ca, 
                uint8_t *r2, 
                uint8_t *tobu, 
                uint8_t *tsm, 
                uint8_t *l, 
                const uECC_Curve curve) {

    uint8_t RES[PUBLIC_SIZE];
    uint8_t part[PUBLIC_SIZE + 4 + 32] = {0};
    uint8_t authsmnew[32];

    wordcount_t num_words = curve->num_words;
    wordcount_t num_bytes = curve->num_bytes;

    uECC_word_t _r2[uECC_MAX_WORDS]          = { 0 };
    uECC_word_t _public_key[uECC_MAX_WORDS * 2]        = { 0 };
    uECC_word_t _RES[uECC_MAX_WORDS * 2]        = { 0 };
    uECC_vli_bytesToNative(_r2, r2, num_bytes);   

    uECC_vli_bytesToNative(_public_key, public_ca, num_bytes);
    uECC_vli_bytesToNative(_public_key + num_words, public_ca + num_bytes, num_bytes);

    _mulPoint(_RES, _r2, _public_key, curve);

    uECC_vli_nativeToBytes(RES, num_bytes, _RES);
    uECC_vli_nativeToBytes(RES + num_bytes, num_bytes, _RES + num_words);

    memcpy(part, RES, PUBLIC_SIZE);
    memcpy(part + PUBLIC_SIZE, tsm, 4);
    memcpy(part + PUBLIC_SIZE + 4, l, 32);

    custom_hash(authsmnew, part, PUBLIC_SIZE + 4 + 32);

      if (!memcmp(authsmnew, authsm, 32))
         return 1;
     else
         return 0; 

}
int computeKey(uint8_t *shared_key2, 
           uint8_t *device, 
           uint8_t *l, 
           uint8_t *tobu, 
           uint8_t *tsm, 
           const uECC_Curve curve) {

    uint8_t part2[ID_SIZE + 32 + 4 + 4] = {0};

    memcpy(part2, device, ID_SIZE);
    memcpy(part2 + ID_SIZE, l, 32);
    memcpy(part2 + ID_SIZE + 4, tobu, 4);
    memcpy(part2 + ID_SIZE + 4 + 4, tsm, 4);

    custom_hash(shared_key2, part2, ID_SIZE + 32 + 4 + 4);
    return 1;
}
