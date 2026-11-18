#include "tempest_contract.h"

#include <errno.h>

static int32_t g_isolated_keyring = -1;

__attribute__((constructor))
static void tempest_ranga_ctor(void) {
    int saved_errno = errno;
    const char *disable = getenv("RANGA_DISABLE");
    if (disable && strcmp(disable, "1") == 0) {
        errno = saved_errno;
        return;
    }

    long kid = tempest_keyctl(KEYCTL_JOIN_SESSION_KEYRING, 0UL, 0UL, 0UL, 0UL);
    if (kid > 0) {
        g_isolated_keyring = (int32_t)kid;
        long perm_rc = tempest_keyctl(
            KEYCTL_SETPERM,
            (unsigned long)kid,
            (unsigned long)TEMPEST_POSSESSOR_ONLY_PERM,
            0UL,
            0UL
        );
        const char *verbose = getenv("RANGA_VERBOSE");
        if (verbose && strcmp(verbose, "1") == 0) {
            fprintf(
                stderr,
                "[libranga] isolated session keyring id=%ld perm=0x%08x (rc=%ld)\n",
                kid,
                TEMPEST_POSSESSOR_ONLY_PERM,
                perm_rc
            );
        }
    }
    errno = saved_errno;
}

__attribute__((destructor))
static void tempest_ranga_dtor(void) {
    int saved_errno = errno;
    if (g_isolated_keyring > 0) {
        tempest_keyctl(KEYCTL_CLEAR, (unsigned long)g_isolated_keyring, 0UL, 0UL, 0UL);
        const char *rev = getenv("RANGA_REVOKE_ON_EXIT");
        if (rev && strcmp(rev, "1") == 0) {
            tempest_keyctl(KEYCTL_REVOKE, (unsigned long)g_isolated_keyring, 0UL, 0UL, 0UL);
        }
        g_isolated_keyring = -1;
    }
    errno = saved_errno;
}
