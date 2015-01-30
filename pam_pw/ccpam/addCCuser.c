/*
* addCCuser.c
*
* Description: This program extracts the auhentication public key
*              from a public key certificate of a Portuguese Citizen
*              Card and adds it to a file that associates a username
*              to the public key.
* Usage: addCCuser username [public key file]
* Restrictions: only root can run this command
* Author: André Zúquete (http://www.ieeta.pt/~avz)
* Date: May 2009
*/

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <openssl/x509.h>
#include "pteidlib.h"
#include "cryptoki.h"

#include "CCerrors.h"
#include "CCkpubFile.h"

static void
pteiderror ( char * msg, long code )
{
    fprintf ( stderr, "Error in %s: %s (%ld)\n",
    		msg, PTEID_errorString ( code ), code );
}

/*
* This function extracts the RSA authentication public key from the
* Citizens' Card
*/

static RSA *
loadCCPubKey ()
{
    long ret;
    int i;
    unsigned char * asn1cert;
    X509 * cert;
    RSA * rsaKey;
    PTEID_Certifs certs;

    ret = PTEID_Init ( 0 );
    if (ret != PTEID_OK) {
        pteiderror ( "PTEID_Init", ret );
	return 0;
    }

    /*
    * Activate CC integrity check
    */

    ret = PTEID_SetSODCAs ( 0 );
    ret = PTEID_SetSODChecking ( 1 );

    if (ret != PTEID_OK) {
        pteiderror ( "PTEID_SetSODChecking", ret );
	return 0;
    }

    /*
    * Extract all CC certificates
    */

    ret = PTEID_GetCertificates ( &certs );
    if (ret != PTEID_OK) {
        pteiderror ( "PTEID_GetCertificates", ret );
	return 0;
    }

    /*
    * Find certificate with label "CITIZEN AUTHENTICATION CERTIFICATE"
    */

    for (i = 0; i < certs.certificatesLength; i++) {
	if (strcmp ( certs.certificates[i].certifLabel,
			"CITIZEN AUTHENTICATION CERTIFICATE" ) != 0) continue;
	cert = 0;
	asn1cert = certs.certificates[i].certif;
	cert = d2i_X509 ( &cert, (const unsigned char **) &asn1cert,
			    certs.certificates[i].certifLength );
        if (cert == 0) {
	    fprintf ( stderr, "Certificate conversion error with d2i_X509\n" );
	    return 0;
	}
	
	/*
	* Extract subject's RSA key from certificate
	*/

	rsaKey = EVP_PKEY_get1_RSA ( X509_PUBKEY_get ( cert->cert_info->key ) );
	if (rsaKey == 0) {
	    fprintf ( stderr,
	    		"RSA key extraction error with EVP_PKEY_get1_RSA\n" );
	    return 0;
	}

	return rsaKey;
    }
}

int
main ( int argc, char ** argv )
{
    struct pubkey_t * keys;
    RSA * pubkey;
    int i;

    if (getuid () != 0) {
        fprintf ( stderr, "Only root can run %s\n", argv[0] ); 
	return 1;
    }

    if (argc < 2) {
        fprintf ( stderr, "Usage: %s username [file (defaults to %s)]\n",
			argv[0], CC_KPUB_FILE ); 
	return 1;
    }

    if (argv[2] == 0) argv[2] = CC_KPUB_FILE;

    /*
    * Get public key from CC
    */

    pubkey = loadCCPubKey ();
    if (pubkey == 0) {
        return 1;
    }

    /*
    * Get all keys already stored
    */

    keys = CC_loadKeys ( argv[2] );
    if (keys == 0) {
        return 1;
    }

    /*
    * Add the key to the key list for a new username
    * or replace the key for an existing username
    */

    for (i = 0; keys[i].username; i++) {
        if (strcmp ( argv[1], keys[i].username ) == 0) {
	    free ( keys[i].e );
	    free ( keys[i].n );
	    keys[i].e = BN_bn2hex ( pubkey->e );
	    keys[i].n = BN_bn2hex ( pubkey->n );
	    goto store;
	}
    }

    keys = realloc ( keys, (i + 2) * sizeof(struct pubkey_t) );
    keys[i+1].username = 0;
    keys[i].username = argv[1];
    keys[i].e = BN_bn2hex ( pubkey->e );
    keys[i].n = BN_bn2hex ( pubkey->n );

store:

    CC_storeKeys ( argv[2], keys );

    return 0;
}
