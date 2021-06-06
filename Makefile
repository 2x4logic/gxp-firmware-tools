ALL: gxp_decode gxp_remaster

gxp_decode: gxp_decode.c aes.c aes.h key.h Makefile
	gcc -g3 gxp_decode.c aes.c -o $@

gxp_remaster: gxp_remaster.c aes.c aes.h key.h Makefile
	gcc -g3 gxp_remaster.c aes.c -o $@

clean:
	rm -f gxp_decode gxp_remaster

