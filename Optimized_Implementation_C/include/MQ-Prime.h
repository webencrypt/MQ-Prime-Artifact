#ifndef MQ_Prime
#define MQ_Prime

#include <stdint.h>

// 函数声明
void mq_prime_evaluate_core(const uint8_t *s, const uint32_t *q_polys, const uint32_t *linear_terms, const uint32_t *constants, int output_dim, uint32_t *y);

#endif // MQ_Prime