.PHONY:	all clean

all: pcap_parser

clean:
	rm pcap_parser

pcap_parser: pcap_parser.c
	gcc -Wall -O2 -o pcap_parser pcap_parser.c
