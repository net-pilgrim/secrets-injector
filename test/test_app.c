#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void check_var(const char *name, const char *expected) {
    char *val = getenv(name);
    char *sec_val = secure_getenv(name);

    printf("[test_app] getenv(\"%s\") = %s\n", name, val ? val : "(null)");

    if (expected == NULL || strcmp(expected, "__NULL__") == 0) {
        if (val != NULL) {
            fprintf(stderr, "FAIL: Expected %s to be NULL, but got '%s'\n", name, val);
            exit(1);
        }
    } else {
        if (val == NULL || strcmp(val, expected) != 0) {
            fprintf(stderr, "FAIL: Expected %s to be '%s', but got '%s'\n", name, expected, val ? val : "(null)");
            exit(1);
        }
        if (sec_val == NULL || strcmp(sec_val, expected) != 0) {
            fprintf(stderr, "FAIL: secure_getenv(\"%s\") expected '%s', got '%s'\n", name, expected, sec_val ? sec_val : "(null)");
            exit(1);
        }
    }
}

int main(int argc, char **argv) {
    printf("=== Test App Started (argc=%d) ===\n", argc);

    // If arguments are provided, test a specific key and expected value
    if (argc >= 3) {
        check_var(argv[1], argv[2]);
        printf("=== Test App Passed ===\n");
        return 0;
    }

    // Default test suite
    check_var("DATABASE_URL", "postgresql://dbuser:supersecretpass@db.internal:5432/production");
    check_var("API_KEY", "sk_live_9876543210abcdef");
    check_var("JWT_SECRET", "my-ultra-secure-jwt-signing-key");
    check_var("FEATURE_FLAG_ENABLED", "true");

    // Check that SECRETS_FETCH_KEY was scrubbed
    check_var("SECRETS_FETCH_KEY", NULL);

    // Check that normal environment variables still work
    char *path = getenv("PATH");
    if (!path) {
        fprintf(stderr, "FAIL: PATH environment variable was lost!\n");
        return 1;
    }
    printf("[test_app] getenv(\"PATH\") exists (len=%zu)\n", strlen(path));

    printf("=== All Test App Checks Passed! ===\n");
    return 0;
}
