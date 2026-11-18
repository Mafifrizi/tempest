#ifndef TEMPEST_CONTRACT_H
#define TEMPEST_CONTRACT_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <linux/keyctl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TEMPEST_VERSION "1.0.0"

/* Semantic exit codes aligned with Tanuki CLI contract */
#define TEMPEST_EXIT_OK          0
#define TEMPEST_EXIT_USAGE       1
#define TEMPEST_EXIT_POLICY_STOP 2
#define TEMPEST_EXIT_MISSING     3
#define TEMPEST_EXIT_PARSE_ERR   4

#define RFC4120_MAX_CLOCK_SKEW_SEC 300
#define TEMPEST_POSSESSOR_ONLY_PERM 0x3f000000U

/* Direct Linux kernel keyctl syscall wrapper (avoids external libkeyutils-dev dependency) */
static inline long tempest_keyctl(
    int cmd,
    unsigned long arg2,
    unsigned long arg3,
    unsigned long arg4,
    unsigned long arg5
) {
    return syscall(SYS_keyctl, cmd, arg2, arg3, arg4, arg5);
}

static inline uint16_t tempest_read_be16(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static inline uint32_t tempest_read_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  |
           (uint32_t)p[3];
}

static inline void tempest_fprint_json_str(FILE *out, const char *s) {
    fputc('"', out);
    if (s) {
        for (const unsigned char *p = (const unsigned char *)s; *p; ++p) {
            unsigned char c = *p;
            switch (c) {
                case '"':  fputs("\\\"", out); break;
                case '\\': fputs("\\\\", out); break;
                case '\b': fputs("\\b", out);  break;
                case '\f': fputs("\\f", out);  break;
                case '\n': fputs("\\n", out);  break;
                case '\r': fputs("\\r", out);  break;
                case '\t': fputs("\\t", out);  break;
                default:
                    if (c < 0x20) {
                        fprintf(out, "\\u%04x", (unsigned int)c);
                    } else {
                        fputc((int)c, out);
                    }
                    break;
            }
        }
    }
    fputc('"', out);
}

static inline const char *tempest_enctype_name(int32_t etype) {
    switch (etype) {
        case 1:  return "des-cbc-crc";
        case 3:  return "des-cbc-md5";
        case 16: return "des3-cbc-sha1";
        case 17: return "aes128-cts-hmac-sha1-96";
        case 18: return "aes256-cts-hmac-sha1-96";
        case 19: return "aes128-cts-hmac-sha256-128";
        case 20: return "aes256-cts-hmac-sha384-192";
        case 23: return "rc4-hmac";
        default: return "unknown";
    }
}

#ifdef __cplusplus
}
#endif

#endif /* TEMPEST_CONTRACT_H */
