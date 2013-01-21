#ifndef __BASE64_H_INCLUDED__
#define __BASE64_H_INCLUDED__

int base64_decode(const unsigned char *src, int len, unsigned char *dst);
int base64_encode(const unsigned char *src, int len, unsigned char *dst);

#endif /* __BASE64_H_INCLUDED__ */
