#ifndef _COMMON_KOCKET_H_
#define _COMMON_KOCKET_H_

typedef struct KocketStruct {
	u32 type;
	u32 payload_size;
	u8* payload;	
} KocketStruct;

// TODO: The following could leverage a KocketFeature array storing features metadata separately.
typedef struct KocketInfo {
	u32 supported_features_bitmap;
} KocketInfo;

#endif //_COMMON_KOCKET_H_

