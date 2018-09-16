#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/evp.h>

typedef int bool;

#define true 1
#define false 0

/*
 * Converts string representation of hex number into actual hex sequence of bytes.
 */
void fromHex(unsigned char *hexSalt, unsigned char *out, int length) {
    unsigned char hexNumber[2];
    unsigned char *hex = hexSalt;

    int i;
    for (i = 0; i < length; i++) {
        memcpy(hexNumber, hex, 2);
        char number = strtoul(hexNumber, NULL, 16);
        out[i] = number;

        hex += 2;
    }
}

int main(int argc, char **argv) {
    int option;
    bool convertHex;

    int iterations;
    int length;
    unsigned char *salt_str;
    const char *pass;

    convertHex = false;

    while ((option = getopt(argc, argv, "i:s:p:l:h")) != -1) {
        switch (option) {
            case 'i':
                iterations = atoi(optarg);
                break;
            case 's':
                salt_str = optarg;
                break;
            case 'p':
                pass = optarg;
                break;
            case 'l':
                length = atoi(optarg);
                break;
            case 'h':
                convertHex = true;
                break;
            default:
                fprintf(stderr, "unknown parameter\n");
                return 1;
        }
    }

    if (pass == NULL) {
        fprintf(stderr, "password not specified\n");
        return 1;
    }
    if (salt_str == NULL) {
        fprintf(stderr, "salt not specified\n");
        return 1;
    }

    unsigned char *salt;
    int saltLength;

    if (convertHex) {
        // for now not handling hex sequences with odd number of symbols
        saltLength = strlen(salt_str) / 2;
        salt = (unsigned char *) malloc(sizeof(unsigned char) * saltLength);

        fromHex(salt_str, salt, saltLength);
    } else {
        salt = salt_str;
        saltLength = strlen(salt);
    }

    unsigned char *out = (unsigned char *) malloc(sizeof(unsigned char) * length);

    if (PKCS5_PBKDF2_HMAC_SHA1(pass, strlen(pass), salt, saltLength, iterations, length, out) != 0) {
        int i;
        for (i = 0; i < length; i++) { 
            printf("%02x%s", out[i], (i == length - 1 ? "" : " ")); 
        }
        printf("\n");
    } else {
        fprintf(stderr, "computation failed\n");
    }

    if (convertHex) {
        free(salt);
    }
    free(out);

    return 0;
}

