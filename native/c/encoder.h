/*
 * Basilisk Payload Encoder — C Header
 */

#ifndef BASILISK_ENCODER_H
#define BASILISK_ENCODER_H

#ifdef __cplusplus
extern "C" {
#endif

/* Base64 */
char *basilisk_base64_encode(const unsigned char *data, int len);
unsigned char *basilisk_base64_decode(const char *input, int *out_len);

/* Hex */
char *basilisk_hex_encode(const unsigned char *data, int len);
unsigned char *basilisk_hex_decode(const char *input, int *out_len);

/* ROT13 */
char *basilisk_rot13(const char *input);

/* URL encode */
char *basilisk_url_encode(const char *input);

/* Unicode escape */
char *basilisk_unicode_escape(const char *input);

/* String reversal */
char *basilisk_reverse(const char *input);

/* Memory */
void basilisk_free(void *ptr);

#ifdef __cplusplus
}
#endif

#endif /* BASILISK_ENCODER_H */
