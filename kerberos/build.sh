gcc -fPIC -fno-stack-protector -c src/krb_password_pwncheck.c -lcurl -lcrypto -o bin/krb_password_pwncheck.o  && \
gcc -fPIC -fno-stack-protector -c src/config.c -lcurl -lcrypto -o bin/config.o && \
gcc -fPIC -fno-stack-protector -c src/curl.c -lcurl -lcrypto -o bin/curl.o && \
ld -x --shared -o krb_password_pwncheck.so bin/krb_password_pwncheck.o bin/config.o bin/curl.o -lcurl -lcrypto && mv krb_password_pwncheck.so /lib/security/
