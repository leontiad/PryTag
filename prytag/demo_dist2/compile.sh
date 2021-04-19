gcc -o srv srv.c ../prylib/prylib.c ../prylib/ionet.c -lpaillier -lgmp -lssl -lcrypto
gcc -o cli cli.c ../prylib/prylib.c ../prylib/ionet.c -lpaillier -lgmp -lssl -lcrypto
