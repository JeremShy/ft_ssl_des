#include <stdio.h>
#include <string.h>
#include <openssl/hmac.h>
#include <ctype.h>
static void print_as_char(const char *start, size_t size, size_t max)
{
    size_t  i;

    i = 0;
    printf("|");
    while (i < size && i < max)
    {
        if (isprint(start[i]))
            printf("%c", start[i]);
        else
            printf(".");
        i++;
    }
    printf("|");
}

static void print_as_bytes(unsigned const char *start, size_t size, size_t max)
{
    size_t  i;

    i = 0;
    while (i < size && i < max)
    {
        printf("%02x ", start[i]);
        i++;
        if (i % 8 == 0)
            printf(" ");
    }
    if (max < size)
    {
        if (max < 8)
            printf("%*c", ((int)size - (int)max) * 3 + 2, ' ');
        else
            printf("%*c", ((int)size - (int)max) * 3 + 1, ' ');
    }
}

void print_memory(const void *start, size_t size)
{
    size_t  i;

    i = 0;
    while (i < size)
    {
        printf("%08lx ", (unsigned long int)(start + i));
        print_as_bytes((unsigned char*)start + i, 16, size - i);
        print_as_char(start + i, 16, size - i);
        i += 16;
        printf("\n");
    }
    printf("%08lx \n", (unsigned long int)(start + size));
}

int main()
{
    // The key to hash
    unsigned char key[8];

    memcpy(key, "salt\x00\x00\x00\x01", 8);

    // The data that we're going to hash using HMAC
    char data[] = "password";
    
    unsigned char* digest;
    
    // Using sha1 hash engine here.
    // You may use other hash engines. e.g EVP_md5(), EVP_sha224, EVP_sha512, etc
    print_memory(key, 8);
    print_memory(data, 8);
    digest = HMAC(EVP_sha1(), key, 8, (unsigned char*)data, strlen(data), NULL, NULL);    

    // Be careful of the length of string with the choosen hash engine. SHA1 produces a 20-byte hash value which rendered as 40 characters.
    // Change the length accordingly with your choosen hash engine
    char mdString[40];
    for(int i = 0; i < 20; i++)
         sprintf(&mdString[i*2], "%02x", (unsigned int)digest[i]);

    printf("HMAC digest: %s\n", mdString);

    return 0;
}