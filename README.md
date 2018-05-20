
A PCAP file parser to print PCAP headers, data and offsets

```
[+00000000] PCAP.HEADER (Little Endian) snaplen=262144
d4 c3 b2 a1 02 00 04 00  00 00 00 00 00 00 00 00  |  ................ 
00 00 04 00 01 00 00 00                           |  ........ 

[+00000018] PKT.0.HEADER [1491836569.284985] size=92
99 9e eb 58 39 59 04 00  5c 00 00 00 5c 00 00 00  |  ...X9Y..\...\... 
[+00000028] PKT.0.DATA
52 54 00 b2 9f 2c 30 52  cb 6c 9c 1b 08 00 45 00  |  RT...,0R.l....E. 
00 4e 45 79 40 00 40 11  6e a5 c0 a8 02 a2 c0 a8  |  .NEy@.@.n....... 
02 8e e1 57 00 89 00 3a  86 cc 00 ee 00 00 00 01  |  ...W...:........ 
00 00 00 00 00 00 20 43  4b 41 41 41 41 41 41 41  |  ...... CKAAAAAAA 
41 41 41 41 41 41 41 41  41 41 41 41 41 41 41 41  |  AAAAAAAAAAAAAAAA 
41 41 41 41 41 41 41 00  00 21 00 01              |  AAAAAAA..!..

[+00000084] PKT.1.HEADER [1491836569.288299] size=253
99 9e eb 58 2b 66 04 00  fd 00 00 00 fd 00 00 00  |  ...X+f.......... 
[+00000094] PKT.1.DATA
30 52 cb 6c 9c 1b 52 54  00 b2 9f 2c 08 00 45 00  |  0R.l..RT...,..E.
```

Example: `cat dump.pcap | pcap_parser`
