
#ifndef ISC_INCLUDE_COMMON_H
#include "common.h"
#endif


void ByteToStr(
     DWORD cb, 
     void* pv, 
     LPSTR sz)
{

BYTE* pb = (BYTE*) pv; // local pointer to a BYTE in the BYTE array
DWORD i;               // local loop counter
int b;                 // local variable

//--------------------------------------------------------------------
//  Begin processing loop.

for (i = 0; i<cb; i++)
{
   b = (*pb & 0xF0) >> 4;
   *sz++ = (b <= 9) ? b + '0' : (b - 10) + 'A';
   b = *pb & 0x0F;
   *sz++ = (b <= 9) ? b + '0' : (b - 10) + 'A';
   pb++;
}
*sz++ = 0;
}


void ByteToZARRAY(int len, unsigned char *buf, ZARRAYP bytestr) {
    unsigned char *p, *q;

    p = buf; 
    q = bytestr->data; 

    bytestr->len = len;
    while(len--) *q++ = *p++;

}

void ReverseByteToZARRAY(int len, unsigned char *buf, ZARRAYP bytestr) {
    unsigned char *p, *q;

    p = buf; 
    q = bytestr->data; 

    bytestr->len = len;
    while(len--) *(q + len) = *p++;

}