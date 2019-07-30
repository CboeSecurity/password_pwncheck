#gcc -fPIC -fno-stack-protector -c src/krb_password_pwncheck.c -lcurl -lcrypto -o bin/krb_password_pwncheck.o  && \
#gcc -fPIC -fno-stack-protector -c src/config.c -lcurl -lcrypto -o bin/config.o && \
#gcc -fPIC -fno-stack-protector -c src/curl.c -lcurl -lcrypto -o bin/curl.o && \
#gcc -o harness src/harness.c -ldl
#ld -x --shared -o pwncheck.so bin/krb_password_pwncheck.o bin/config.o bin/curl.o -lcurl -lcrypto && mv pwncheck.so /lib/security/
#cp /lib/security/pwncheck.so /usr/lib/x86_64-linux-gnu/krb5/plugins/pwqual/

#gcc -g -shared -fPIC -fno-stack-protector -DDEBUG -c src/krb_password_pwncheck.c -lcurl -lcrypto -o bin/krb_password_pwncheck.o  && \
#gcc -g -shared -fPIC -fno-stack-protector -c src/config.c -lcurl -lcrypto -o bin/config.o && \
#gcc -g -shared -fPIC -fno-stack-protector -c src/curl.c -lcurl -lcrypto -o bin/curl.o && \
#gcc -g -o bin/harness src/harness.c -ldl
#ld -g -x --shared -o bin/pwncheck.so bin/krb_password_pwncheck.o bin/config.o bin/curl.o -lefence -lcurl -lcrypto -lyaml
if [ ! -d bin ]; then
    mkdir bin
fi
rm bin/pam_pwncheck.so /lib/security/pam_pwncheck.so  /lib/x86_64-linux-gnu/security/pam_pwncheck.so
#cp bin/pam_pwncheck.so /usr/lib/x86_64-linux-gnu/krb5/plugins/pwqual/
gcc -fPIC -fno-stack-protector -c ../common/curl.c -lcurl -lcrypto -o bin/curl.o
gcc -fPIC -fno-stack-protector -c src/pam_password_pwncheck.c -lcurl -lcrypto -o bin/pam_pwncheck.o 
ld -x --shared -o bin/pam_pwncheck.so bin/pam_pwncheck.o bin/curl.o -lpam -lcurl -lcrypto
cp bin/pam_pwncheck.so /lib/x86_64-linux-gnu/security/
cp bin/pam_pwncheck.so /lib/security/

