CC := gcc

%.o : %.c
	$(CC) -c -o $@ $<

guomi : sm2.o sm3.o 
	$(CC) -o $@ sm2.o sm3.o -lcrypto

sm3.o : sm3.h 
	$(CC) -c sm3.c

sm2.o : sm2.h sm3.h
	$(CC) -c sm2.c

clean :
	rm guomi sm2.o sm3.o