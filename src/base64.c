/* 
 * Base64 encode and decode.
 * Author: flygoast(flygoast@126.com)
 * CREATED AT:  2012-04-26
 * MODIFIED AT: 2012-04-27
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char base64_enctbl[] = {
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/="
};

static unsigned char base64_dectbl[] = {
    255,  255,  255,  255,  255,  255,  255,  255,
    255,  255,  255,  255,  255,  255,  255,  255,
    255,  255,  255,  255,  255,  255,  255,  255,
    255,  255,  255,  255,  255,  255,  255,  255,
    255,  255,  255,  255,  255,  255,  255,  255,
    255,  255,  255,   62,  255,  255,  255,   63,
     52,   53,   54,   55,   56,   57,   58,   59,
     60,   61,  255,  255,  255,   64,  255,  255,
    255,    0,    1,    2,    3,    4,    5,    6,
      7,    8,    9,   10,   11,   12,   13,   14,
     15,   16,   17,   18,   19,   20,   21,   22,
     23,   24,   25,  255,  255,  255,  255,  255,
    255,   26,   27,   28,   29,   30,   31,   32,
     33,   34,   35,   36,   37,   38,   39,   40,
     41,   42,   43,   44,   45,   46,   47,   48,
     49,   50,   51,  255,  255,  255,  255,  255,
};

int base64_decode(const unsigned char *src, int len,
        unsigned char *dst) {
    const unsigned char *ptr1 = src;
    unsigned char *ptr2 = dst;
    unsigned char index1 = 0, index2 = 0;

    if (len % 4 != 0) {
        return -1;
    }

    while (ptr1 + 3 < src + len) {
        if (*ptr1 >= 128 || *(ptr1 + 1) >= 128 
                || *(ptr1 + 2) >= 128 || *(ptr1 + 3) >= 128) {
            return -1;
        }

        if ((index1 = base64_dectbl[*ptr1]) == 0xff) {
            return -1;
        }
        if ((index2 = base64_dectbl[*(ptr1 + 1)]) == 0xff) {
            return -1;
        }

        *ptr2++ = index1 << 2 | ((index2 & 0x3f) >> 4);
        if ((index1 = base64_dectbl[*(ptr1 + 2)]) == 0xff) {
            return -1;
        }

        if (index1 == 64) { /* pad character */
           return ptr2 - dst; 
        } 

        *ptr2++ = ((index2 & 0x0f) << 4) | (index1 >> 2);
        if ((index2 = base64_dectbl[*(ptr1 + 3)]) == 0xff) {
            return -1;
        }

        if (index2 == 64) { /* pad character */
            return ptr2 - dst;
        }

        *ptr2++ = (index1 << 6) | index2;
        ptr1 += 4;
    }
    return ptr2 - dst;
}

/* The caller should provide a buffer of at least "(len+2)/3*4" size. */
int base64_encode(const unsigned char *src, int len, 
        unsigned char *dst) {
    const unsigned char *ptr1 = src;
    unsigned char *ptr2 = dst;

    while (ptr1 + 2 < src + len) {
        *ptr2++ = base64_enctbl[*ptr1 >> 2];
        *ptr2++ = base64_enctbl[((*ptr1 & 0x03) << 4) | 
            (*(ptr1 + 1) >> 4)];
        *ptr2++ = base64_enctbl[((*(ptr1 + 1) & 0x0f) << 2) | 
            (*(ptr1 + 2) >> 6)];
        *ptr2++ = base64_enctbl[*(ptr1 + 2) & 0x3f];
        ptr1 += 3;
    }

    if (ptr1 == src + len) {
        return (ptr2 - dst);
    }
    
    *ptr2++ = base64_enctbl[*ptr1 >> 2];
    if (ptr1 + 1 == src + len) {
        *ptr2++ = base64_enctbl[(*ptr1 & 0x03) << 4];
        *ptr2++ = base64_enctbl[64]; /* Pad */
        *ptr2++ = base64_enctbl[64]; /* Pad */ 
        return (ptr2 - dst);
    } else {
        *ptr2++ = base64_enctbl[(*ptr1 & 0x03) << 4 | (*(ptr1 + 1) >> 4)];
        *ptr2++ = base64_enctbl[(*(ptr1 + 1) & 0x0f) << 2];
        *ptr2++ = base64_enctbl[64]; /* Pad */
        return (ptr2 - dst);
    }
}

#ifdef BASE64_TEST_MAIN
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    unsigned char *s = "Hello, world!";
    unsigned char buf[1000] = {};
    unsigned char *d = "V2hhdCBpcyBpdCB0byBncm93IG9sZD8KSXMgaXQgd"
        "G8gbG9zZSB0aGUgZ2xvcnkgb2YgdGhlIGZvcm0sClRoZSBsdXN0cmUgb"
        "2YgdGhlIGV5ZT8KSXMgaXQgZm9yIGJlYXV0eSB0byBmb3JlZ28gaGVyI"
        "HdyZWF0aD8KWWVzLCBidXQgbm90IGZvciB0aGlzIGFsb25lLg==";
    int ret = base64_encode(s, strlen((const char *)s), buf);
    printf("%d\n%s\n%d\n", (strlen(s) + 2) / 3 * 4, buf, ret);
    ret = base64_decode(d, strlen(d), buf);
    buf[ret] = '\0';

    printf("%s\nret:%d", buf, ret);

    exit(0); 
}
#endif /* BASE64_TEST_MAIN */
