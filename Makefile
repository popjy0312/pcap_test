pcap : main.c
	gcc -o pcap main.c -lpcap


clean :
	rm pcap
