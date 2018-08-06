all : send_arp
    
send_arp : main.c
	gcc -o send_arp main.c -lpcap

clean :
	rm -rf *.o send_arp

