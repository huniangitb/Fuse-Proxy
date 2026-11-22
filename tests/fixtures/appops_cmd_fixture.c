#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 4 || strcmp(argv[1], "appops") || strcmp(argv[2], "get")) return 90;
    const char *mode = getenv("APPOPS_CASE");
    const char *payload = getenv("APPOPS_PAYLOAD");
    if (!mode || !payload) return 91;
    int started = atoi(getenv("APPOPS_STARTED_FD"));
    int gate = atoi(getenv("APPOPS_GATE_FD"));
    bool hold = !strcmp(argv[3], "com.repro.hold") &&
                (!strcmp(mode, "A") || !strcmp(mode, "B") || !strcmp(mode, "D") || !strcmp(mode, "E") ||
                  (getenv("APPOPS_HOLD") && !strcmp(getenv("APPOPS_HOLD"), "1")));
    if (!strcmp(payload, "fail")) return 7;
    if (hold && !strcmp(mode, "B")) close(STDOUT_FILENO);
    else if (!strcmp(payload, "allow")) {
        const char output[] = "MANAGE_EXTERNAL_STORAGE: allow\nREQUEST_INSTALL_PACKAGES: allow\n";
        if (write(STDOUT_FILENO, output, sizeof output - 1) != sizeof output - 1) return 92;
    } else if (!strcmp(payload, "uidmode")) {
        const char output[] = "Uid mode: MANAGE_EXTERNAL_STORAGE: allow\n";
        if (write(STDOUT_FILENO, output, sizeof output - 1) != sizeof output - 1) return 92;
    } else if (!strcmp(payload, "installer")) {
        const char output[] = "INSTALL_PACKAGES: allow\n";
        if (write(STDOUT_FILENO, output, sizeof output - 1) != sizeof output - 1) return 92;
    } else {
        const char output[] = "MANAGE_EXTERNAL_STORAGE: deny\nREQUEST_INSTALL_PACKAGES: ignore\n";
        if (write(STDOUT_FILENO, output, sizeof output - 1) != sizeof output - 1) return 92;
    }
    if (hold) {
        if (write(started, "s", 1) != 1) return 93;
        if (!strcmp(mode, "E")) {
            char buffer[8192];
            memset(buffer, 'x', sizeof buffer);
            for (;;) {
                ssize_t got = write(STDOUT_FILENO, buffer, sizeof buffer);
                if (got < 0 && errno == EINTR) continue;
                if (got <= 0) return 95;
            }
        }
        char byte;
        ssize_t rc;
        do { rc = read(gate, &byte, 1); } while (rc < 0 && errno == EINTR);
        if (rc != 1) return 94;
    }
    return 0;
}
