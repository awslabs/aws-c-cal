#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static uint8_t d[] = {
    0xc9, 0x80, 0x68, 0x98, 0xa0, 0x33, 0x49, 0x16, 0xc8, 0x60, 0x74, 0x88, 0x80, 0xa5, 0x41, 0xf0,
    0x93, 0xb5, 0x79, 0xa9, 0xb1, 0xf3, 0x29, 0x34, 0xd8, 0x6c, 0x36, 0x3c, 0x39, 0x80, 0x03, 0x57,
};

static uint8_t s_preamble = 0x04;
static uint8_t s_zero = 0x00;

int main() {
    CFAllocatorRef allocator = kCFAllocatorMalloc;

    size_t key_len = 32;
    /* allocate the buffer with 0x04 || x || y || k */
    size_t buffer_len = 3 * key_len + 1;
    uint8_t *buffer = malloc(buffer_len);
    memcpy(buffer, &s_preamble, 1);
    /* Fill X and Y with all zeros */
    for (size_t i = 0; i < key_len; i++) {
        memcpy(buffer + sizeof(s_preamble) + i, &s_zero, 1);
    }
    for (size_t i = 0; i < key_len; i++) {
        memcpy(buffer + sizeof(s_preamble) + key_len + i, &s_zero, 1);
    }
    /* Fill private key with real value */
    memcpy(buffer + sizeof(s_preamble) + key_len + key_len, d, sizeof(d));

    CFDataRef private_key_data = NULL;
    private_key_data = CFDataCreate(allocator, buffer, buffer_len);
    CFMutableDictionaryRef key_attributes = NULL;
    key_attributes = CFDictionaryCreateMutable(allocator, 6, NULL, NULL);
    if (private_key_data == NULL || key_attributes == NULL) {
        fprintf(stderr, "error allocating\n");
        exit(-1);
    }
    CFDictionaryAddValue(key_attributes, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
    CFDictionaryAddValue(key_attributes, kSecAttrKeyClass, kSecAttrKeyClassPrivate);
    CFIndex key_size_bits = key_len * 8;
    CFDictionaryAddValue(key_attributes, kSecAttrKeySizeInBits, &key_size_bits);
    CFDictionaryAddValue(key_attributes, kSecAttrCanSign, kCFBooleanTrue);
    CFDictionaryAddValue(key_attributes, kSecAttrCanVerify, kCFBooleanFalse);
    CFDictionaryAddValue(key_attributes, kSecAttrCanDerive, kCFBooleanTrue);
    CFErrorRef error = NULL;
    SecKeyRef key_ref = SecKeyCreateWithData(private_key_data, key_attributes, &error);

    if (error) {
        CFIndex error_code = CFErrorGetCode(error);
        fprintf(stderr, "error out from SecKeyCreateWithData. Error code is: %ld\n", error_code);
        exit(-1);
    }
    fprintf(stderr, "Succeed without error \n");
    return 0;
}
