ALL: gxp_decode

gxp_decode: gxp_decode.c aes.c aes.h key.h Makefile
	gcc -g3 gxp_decode.c aes.c -o $@

clean:
	rm -f gxp_decode

