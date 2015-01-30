CFLAGS = -I /usr/local/include/pteid -g
PAM_INCLUDE_FILES = $(foreach f, pam_modules.h pam_client.h _pam_macros.h, /usr/include/security/$(f))

all: addCCuser pam_pw.so

addCCuser: addCCuser.o CCkpubFile.o CCerrors.o
	$(CC) -o $@ $^ -L /usr/local/lib -lpteid -lcrypto
	strip $@

addCCuser.o: addCCuser.c CCkpubFile.h CCerrors.h
	$(CC) -o $@ -c $*.c $(CFLAGS)

pam_pw.so: pam_pw.o CCkpubFile.o
	ld -o $@ -shared $^ -L /usr/local/lib -lpam -lcrypto

CCkpubFile.o: CCkpubFile.c CCkpubFile.h
	$(CC) -o $@ -c -fPIC $*.c $(CFLAGS)

pam_pw.o: pam_pw.c CCkpubFile.h
	@for f in $(PAM_INCLUDE_FILES); do \
		if test ! -f $$f; then \
			echo "install libpam0g-dev with apt-get or with a similar tool"; \
			exit 1; \
		fi; \
	done; \
	echo $(CC) -o $@ -c -fPIC -fno-stack-protector $*.c $(CFLAGS); \
	$(CC) -o $@ -c -fPIC -fno-stack-protector $*.c $(CFLAGS)

install:
	strip pam_pw.so
	cp pam_pw.so /lib/security
	cp addCCuser /usr/local/bin
	test -d /etc/CC || mkdir /etc/CC
	
clean:
	rm *.o addCCuser pam_pw.so
