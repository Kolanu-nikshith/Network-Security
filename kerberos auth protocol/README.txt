--------------------------------------Compilation----------------------------------
Run the makefile to compile the program.
$ make

The KDC program can be compiled using the command
gcc -o kdc KDC.c -lcrypto
where as client program can be compiled using the command
gcc -o client client.c -lcrypto
------------------------------------------------------------------------------------
------------------------------------------Run---------------------------------------
After successful compilation, KDC program can be run by using the command
./kdc -p <port number> -o <output filename> -f <password filename>
If client is a sender, then client program should be run by using the command
./client -n <myname> -m <type> -o <other party name> -i <inputfile> -a <kdc ipaddress> -p <kdc port>
whereas if it is a receiver, it should be run using the command
./client -n <myname> -m <type> -s <outenc> -o <outflie> -a <kdc ipaddress> -p <kdc port>
-------------------------------------------------------------------------------------
Commands used for testing the program:

terminal 1:    ./kdc -p 12345 -o out.txt -f pwd.txt
terminal 2:    ./client -n alice -m S -o bob -i in.txt -a 127.0.0.1 -p 12345
terminal 3:    ./client -n bob -m R -s outenc.txt -o out.txt -a 127.0.0.1 -p 12345

--------------------------------------------------------------------------------------

This application works fine to the best of developer knowledge.
-------------------------------------------------------------------------------------

