#ifndef PARAMS_H_   
#define PARAMS_H_

#define ID_SIZE 3 
#define MESSAGE_TYPE 1
#define NAME_SIZE 64
#define ATTRIB_SIZE 64

#if uECC_SUPPORTS_secp160r1
    #ifdef MULTI_CURVE 
        #error "Multi curve not supported yet :(" 
    #endif  
    #define MULTI_CURVE

    #define NUM_WORDS 20
    #define NUM_BYTES 20
    #define PRIVATE_SIZE 20
    #define PUBLIC_SIZE 40
    #define PT_COMPRESSED_SIZE 20+1
    
    #define CRT_SIZE PT_COMPRESSED_SIZE+ID_SIZE
#endif

#if uECC_SUPPORTS_secp192r1
    #ifdef MULTI_CURVE
        #error "Multi curve not supported yet :("
    #endif
    #define MULTI_CURVE

    #define NUM_WORDS 24
    #define NUM_BYTES 24
    #define PRIVATE_SIZE 24
    #define PUBLIC_SIZE 48
    #define PT_COMPRESSED_SIZE 24+1

    #define CRT_SIZE PT_COMPRESSED_SIZE+ID_SIZE
#endif

#if uECC_SUPPORTS_secp224r1
    #ifdef MULTI_CURVE
        #error "Multi curve not supported yet :("
    #endif
    #define MULTI_CURVE

    #define NUM_WORDS 28
    #define NUM_BYTES 28
    #define PRIVATE_SIZE 28
    #define PUBLIC_SIZE 56
    #define PT_COMPRESSED_SIZE 29

    #define CRT_SIZE PT_COMPRESSED_SIZE+ID_SIZE
#endif

#if uECC_SUPPORTS_secp256r1
    #ifdef MULTI_CURVE
        #error "Multi curve not supported yet :("
    #endif
    #define MULTI_CURVE

    #define NUM_WORDS 32
    #define NUM_BYTES 32
    #define PRIVATE_SIZE 32
    #define PUBLIC_SIZE 64
    #define PT_COMPRESSED_SIZE 33

    #define CRT_SIZE PT_COMPRESSED_SIZE+ID_SIZE
#endif

#if uECC_SUPPORTS_secp256k1
    #ifdef MULTI_CURVE
        #error "Multi curve not supported yet :("
    #endif
    #define MULTI_CURVE

    #define NUM_WORDS 32
    #define NUM_BYTES 32
    #define PRIVATE_SIZE 32
    #define PUBLIC_SIZE 64
    #define PT_COMPRESSED_SIZE 32+1

    #define CRT_SIZE PT_COMPRESSED_SIZE+ID_SIZE
#endif


#ifndef MULTI_CURVE
#error You must select 1 curve: gcc [...] -DuECC_SUPPORTS_secpXXXX1=1
#endif

#endif 
