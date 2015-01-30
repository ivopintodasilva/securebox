#ifndef _PTEID_CC_KPUB_FILE_H_
#define _PTEID_CC_KPUB_FILE_H_

#define CC_KPUB_FILE	"/etc/CC/keys"

struct pubkey_t {
    unsigned char * username;
    unsigned char * e;
    unsigned char * n;
};

struct pubkey_t * CC_loadKeys ( char * file );
int CC_storeKeys ( char * file, struct pubkey_t * keys );

#endif /* _PTEID_CC_KPUB_FILE_H_ */
