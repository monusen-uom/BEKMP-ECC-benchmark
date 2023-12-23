#ifndef _uECQV_H_
#define _uECQV_H_

#include <stdint.h>
#include "params.h"

void vli_print(char *str, const uint8_t *vli, unsigned int size);

struct csr_t {
    uint8_t id[ID_SIZE];
    uint8_t point[PT_COMPRESSED_SIZE];
};

struct CertificationRequest {
  char sensor_name[NAME_SIZE];
  uint8_t id[ID_SIZE];
  uint8_t sensor_public_key[PUBLIC_SIZE];
  char attributes[ATTRIB_SIZE];
};

struct Certificate {
  char sensor_name[NAME_SIZE];
  uint8_t id[ID_SIZE];
  uint8_t sensor_public_key[PUBLIC_SIZE];
  char attributes[ATTRIB_SIZE];
  uint8_t signature[PUBLIC_SIZE];
  uint8_t hash[32];
};

int csr_request(struct csr_t *csr,
                uint8_t *private, 
                const uint8_t id[ID_SIZE],
                const uECC_Curve curve);

int crt_generation(uint8_t *r,
                   uint8_t *crt, 
                   const struct csr_t *csr, 
                   const uint8_t *private_ca, 
                   const uint8_t *public_ca,
                   const uECC_Curve curve);

int crt_pk_extract(uint8_t *public,
                   const uint8_t *crt, 
                   const uint8_t *public_ca,
                   const uECC_Curve curve);

int crt_validation(uint8_t *extracted,
                   uint8_t *private,
                   const uint8_t *crt, 
                   const uint8_t *r,
                   const uint8_t *private_csr,
                   const uint8_t *public_ca,
                   const uECC_Curve curve);

int crt_selfsign_generation(uint8_t *private_key,
                            uint8_t *crt,
                            const uint8_t *id,
                            const uECC_Curve curve);

int homqv_generate_key(uint8_t *key,
                   uint8_t *Y,
                   uint8_t *public,
                   const uint8_t *crt, 
                   const uint8_t *private_ca, 
                   const uint8_t *public_ca,
                   const uint8_t *id_cluster,
                   int x509,
                   const uECC_Curve curve);

int homqv_regenerate_key(uint8_t *key,
                   const uint8_t *Y, 
                   const uint8_t *public_ca,
                   const uint8_t *private,
                   const uint8_t *id_cluster,
                   const uint8_t *id,
                   const uECC_Curve curve);

int csr_standard_request(struct CertificationRequest *csr,
                uint8_t *private, 
                const uint8_t id[ID_SIZE],
                const uECC_Curve curve);

int crt_standard_generation(struct CertificationRequest *csr,
                   struct Certificate *cert, 
                   const uint8_t *private_standard_ca, 
                   const uint8_t *public_standard_ca,
                   const uECC_Curve curve);

int crt_standard_verify(struct Certificate *cert, 
                   const uint8_t *private_standard_ca, 
                   const uint8_t *public_standard_ca,
                   const uECC_Curve curve);

int selfcrt_pk_extract(uint8_t *public_key,
                       const uint8_t *self_crt,
                       const uECC_Curve curve);

void addPoint(uint8_t *sum,
             const uint8_t *p1,
             const uint8_t *p2,
             const uECC_Curve curve);

void mulPoint(uint8_t *mul,
             const uint8_t *s,
             const uint8_t *p,
             const uECC_Curve curve);

void multiplyPrivates(uint8_t *res,
            const uint8_t *a,
            const uint8_t *b,
            const uECC_Curve curve);

void custom_hash(uint8_t *output, const uint8_t *input, uint8_t input_len);

int reg_request(uint8_t *req, uint8_t *id);
int register_device(uint8_t *private_key, 
                    uint8_t *public_key, 
                    uint8_t *m, 
                    uint8_t *id,
                    uint8_t *private_ca,
                    uint8_t *l,
                    const uECC_Curve curve);

int hashAuth(uint8_t *auth, 
             uint8_t *r1, 
             uint8_t *tobu, 
             uint8_t *id, 
             uint8_t *private_key,
             uint8_t *m,
             const uECC_Curve curve);

             
int checkAuth(uint8_t *auth, 
              uint8_t *compressed, 
              uint8_t *r1, 
              uint8_t *id, 
              uint8_t *tobu, 
              uint8_t *l,
              const uECC_Curve curve);
int computeAuth(uint8_t *authsm, 
                uint8_t *r2, 
                uint8_t *private_ca,
                uint8_t *id, 
                uint8_t *tobu, 
                uint8_t *tsm, 
                uint8_t *l, 
                uint8_t *shared_key1, 
                const uECC_Curve curve);

int checkAuthSM(uint8_t *authsm, 
                uint8_t *public_ca, 
                uint8_t *r2, 
                uint8_t *tobu, 
                uint8_t *tsm, 
                uint8_t *l, 
                const uECC_Curve curve);

int computeKey(uint8_t *shared_key2, 
           uint8_t *device, 
           uint8_t *l, 
           uint8_t *tobu, 
           uint8_t *tsm, 
           const uECC_Curve curve);
#endif
