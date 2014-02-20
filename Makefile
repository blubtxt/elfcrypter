elfcrypter: elfcrypter.o funcs.o
	g++ elfcrypter.o funcs.o -o elfcrypter -w -s -O2 -Os
     
elfcrypter.o: main.cpp funcs.h
	g++ main.cpp -o elfcrypter.o -c -w -s -O2 -Os -fpermissive -masm=intel
     
funcs.o: funcs.cpp funcs.h
	g++ funcs.cpp -o funcs.o -c -w -s -O2 -Os

