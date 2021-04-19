gcc -o tp tp.c ../prylib/prylib.c ../prylib/ionet.c -lpaillier -lgmp -lssl -lcrypto
gcc -o aggregator aggregator.c ../prylib/prylib.c ../prylib/ionet.c -lpaillier -lgmp -lssl -lcrypto
gcc -o users users.c ../prylib/prylib.c ../prylib/ionet.c -lpaillier -lgmp -lssl -lcrypto
gcc -o collector collector.c ../prylib/prylib.c ../prylib/ionet.c -lpaillier -lgmp -lssl -lcrypto
