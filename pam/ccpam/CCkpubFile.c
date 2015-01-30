/*
* CCkpubFile.c
*
* Description: This module provides functions for parsing and storing
*              RSA public keys associated to usernames in a file
* Author: André Zúquete (http://www.ieeta.pt/~avz)
* Date: May 2009
*/

#include <stdio.h>
#include <memory.h>
#include <errno.h>
#include <malloc.h>
#include <fcntl.h>

#include "CCkpubFile.h"

/*
* Loads all public keys from a file
* File format: username:RSA exponent:RSA modulus, RSA values in hexa
* Comments: begin with a #
* Returns: an arrays of filled pubkey_t structures;
*	   last element with a null username
*/

struct pubkey_t *
CC_loadKeys ( char * file )
{
    int fd;
    char c;
    struct pubkey_t * new, parsing;
    int plen;
    int state;
    int keys = 0;

    new = malloc ( sizeof(*new) );
    new->username = 0;

    fd = open ( file, O_RDONLY );
    if (fd == -1) {
        return new;
    }

    state = 0;
    for (;;) {
	if (read ( fd, &c, 1 ) == 0) {
	    close ( fd );
	    return new;
	}
	switch (state) {
	case 0: /* initial */
	    if (c == '#') state = 1;	/* start of comment */
	    else if (isalnum(c)) {
	    	state = 2;		/* start of username */
		parsing.username = malloc ( 2 );
		parsing.username[0] = c;
		parsing.username[1] = 0;
		plen = 1;
	    }
	    else if (!isspace(c)) {
		close ( fd );
		return new;
	    }
	    break;
	case 1: /* comment */
	    if (c == '\n') state = 0;	/* end of comment */
	    break;
	case 2: /* username */
	    if (c == ':') {
	        state = 3;		/* end of username,
					   start of RSA exponent */
		parsing.e = malloc ( 1 );
		parsing.e[0] = 0;
		plen = 0;
	    }
	    else if (isalnum(c)) {
		parsing.username = realloc ( parsing.username, plen + 2 );
		parsing.username[plen] = c;
		parsing.username[plen+1] = 0;
		plen++;
	    }
	    else {
		close ( fd );
		return new;
	    }
	    break;
	case 3: /* e */
	    if (c == ':') {
	        state = 4;	/* end of RSA exponent,
				   start of RSA modulus */
		parsing.n = malloc ( 1 );
		parsing.n[0] = 0;
		plen = 0;
	    }
	    else if (isxdigit(c)) {
		parsing.e = realloc ( parsing.e, plen + 2 );
		parsing.e[plen] = c;
		parsing.e[plen+1] = 0;
		plen++;
	    }
	    else {
		close ( fd );
		return new;
	    }
	    break;
	case 4: /* n */
	    if (c == '\n') {
	        state = 0;	/* end of RSA modulus */
		new = realloc ( new, (keys + 2) * sizeof(struct pubkey_t ) );
		memcpy ( new + keys + 1, new + keys, sizeof(struct pubkey_t ) );
		memcpy ( new + keys, &parsing, sizeof(struct pubkey_t ) );
		keys++;
	    }
	    else if (isxdigit(c)) {
		parsing.n = realloc ( parsing.n, plen + 2 );
		parsing.n[plen] = c;
		parsing.n[plen+1] = 0;
		plen++;
	    }
	    else {
		close ( fd );
		return new;
	    }
	    break;
	}
    }
 
    return new;
}

/*
* Stores a set of public keys in a file
* File format: username:RSA exponent:RSA modulus, RSA values in hexa
* Comments: begin with a #
* Creates the file if not existing
* Overwrites the file contents
*/

#define CC_FILE_HEADER "\
# This file was automatically generated\n#\n\
# It contains the public keys of all the users that can login with a Portuguese Citizen Card\n#\n\
# Format: username:RSA exponent:RSA modulus\n#\n"

int
CC_storeKeys ( char * file, struct pubkey_t * keys )
{
    FILE * fp;
    int i;
    
    umask ( 0177 );
    fp = fopen ( file, "w" );
    if (fp == 0) {
        fprintf ( stderr, "Cannot open %s for writing: %s\n", file,
		    strerror ( errno ) );
	return -1;
    }

    /*
    * Write header and public keys
    */

    fprintf ( fp, CC_FILE_HEADER );

    for (i = 0; keys[i].username != 0; i++) {
        fprintf ( fp, "%s:%s:%s\n", keys[i].username, keys[i].e, keys[i].n );
    }

    fclose ( fp );

    return 0;
}
