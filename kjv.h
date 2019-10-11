#ifndef _KJV_H
#define _KJV_H

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "miner.h"

extern void initkjv();
extern void BibleHashV2();
extern void ArgToUint256(char *arg, uint8_t uHash[]);
extern void phex(uint8_t* str, uint8_t len);
extern char *BibleMD5(char *str, int length);
extern int Base64encode(char *encoded, const char *string, int len);

#endif /* _KJV_H_ */
