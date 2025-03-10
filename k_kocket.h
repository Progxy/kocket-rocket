#ifndef _K_KOCKET_H_
#define _K_KOCKET_H_

#include "common_kocket.h"

int kocket_write(Kocket kocket, u8* data, u32 data_size, u32 type_flag);
int kocket_read(Kocket kocket, int (*handler) (KocketStruct kocket_struct), void* args);

#endif //_K_KOCKET_H_

