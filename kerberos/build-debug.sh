#gcc -fPIC -fno-stack-protector -c src/krb_password_pwncheck.c -lcurl -lcrypto -o bin/krb_password_pwncheck.o  && \
#gcc -fPIC -fno-stack-protector -c src/config.c -lcurl -lcrypto -o bin/config.o && \
#gcc -fPIC -fno-stack-protector -c src/curl.c -lcurl -lcrypto -o bin/curl.o && \
#gcc -o harness src/harness.c -ldl
#ld -x --shared -o pwncheck.so bin/krb_password_pwncheck.o bin/config.o bin/curl.o -lcurl -lcrypto && mv pwncheck.so /lib/security/
#cp /lib/security/pwncheck.so /usr/lib/x86_64-linux-gnu/krb5/plugins/pwqual/

gcc -g -shared -fPIC -fno-stack-protector -DDEBUG -c src/krb_password_pwncheck.c -lcurl -lcrypto -o bin/krb_password_pwncheck.o  && \
gcc -g -shared -fPIC -fno-stack-protector -DDEBUG -c src/config.c -lcurl -lcrypto -o bin/config.o && \
gcc -g -shared -fPIC -fno-stack-protector -DDEBUG -c ../common/curl.c -lcurl -lcrypto -o bin/curl.o && \
gcc -g -o bin/harness src/harness.c -ldl
ld -g -x --shared -o bin/pwncheck.so bin/krb_password_pwncheck.o bin/config.o bin/curl.o -lefence -lcurl -lcrypto -lyaml
cp bin/pwncheck.so /usr/lib/x86_64-linux-gnu/krb5/plugins/pwqual/
