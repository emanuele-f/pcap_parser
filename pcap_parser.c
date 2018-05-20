/*
 * pcap_parser
 * 
 * 2018 - Emanuele Faranda
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <endian.h>
#include <arpa/inet.h>

typedef u_int32_t uint32;
typedef u_int16_t uint16;
typedef int32_t int32;

typedef struct pcap_hdr_s {
  uint32 magic_number;   /* magic number */
  uint16 version_major;  /* major version number */
  uint16 version_minor;  /* minor version number */
  int32  thiszone;       /* GMT to local correction */
  uint32 sigfigs;        /* accuracy of timestamps */
  uint32 snaplen;        /* max length of captured packets, in octets */
  uint32 network;        /* data link type */
} __attribute__((packed)) pcap_hdr_t;

typedef struct pcaprec_hdr_s {
  uint32 ts_sec;         /* timestamp seconds */
  uint32 ts_usec;        /* timestamp microseconds */
  uint32 incl_len;       /* number of octets of packet saved in file */
  uint32 orig_len;       /* actual length of packet */
} __attribute__((packed)) pcaprec_hdr_t;

static uint32_t u32_identity(uint32_t x) { return x; }

// https://gist.github.com/ccbrown/9722406
void hexdump(const void* data, size_t size) {
  char ascii[17];
  size_t i, j;
  ascii[16] = '\0';

  for (i = 0; i < size; ++i) {
    printf("%02x ", ((unsigned char*)data)[i]);

    if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~')
      ascii[i % 16] = ((unsigned char*)data)[i];
    else
      ascii[i % 16] = '.';
    
    if ((i+1) % 8 == 0 || i+1 == size) {
      printf(" ");

      if ((i+1) % 16 == 0)
        printf("|  %s \n", ascii);
      else if (i+1 == size) {
        ascii[(i+1) % 16] = '\0';

        if ((i+1) % 16 <= 8)
          printf(" ");

        for (j = (i+1) % 16; j < 16; ++j)
          printf("   ");

        printf("|  %s \n", ascii);
      }
    }
  }
}

// hexDump
int main() {
  pcap_hdr_t header;
  pcaprec_hdr_t packet;
  uint32_t (*ptohl) (uint32_t) = NULL;    /* Pcap to host long */
  uint32_t snaplen, pkt_size;
  uint64_t offset = 0;
  uint32_t pkt_num = 0;
  u_char *pkt_buf;
  int is_little_endian;

  if(read(STDIN_FILENO, &header, sizeof(header)) != sizeof(header)) {
    fprintf(stderr, "Error while reading PCAP header\n");
    return -1;
  }

  if(ntohl(header.magic_number) == 0xa1b2c3d4) {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    ptohl = ntohl;
#else
    ptohl = u32_identity;
#endif
    is_little_endian = 0;
  } else if(ntohl(header.magic_number) == 0xd4c3b2a1) {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    ptohl = u32_identity;
#else
    ptohl = ntohl;
#endif
    is_little_endian = 1;
  } else {
    fprintf(stderr, "INVALID magic number");
    exit(1);
  }

  snaplen = ptohl(header.snaplen);

  printf("\n[+%08lx] PCAP.HEADER (%s Endian) snaplen=%u\n", offset, is_little_endian ? "Little" : "Big", snaplen);
  offset += sizeof(header);
  hexdump(&header, sizeof(header));

  pkt_buf = (u_char *) malloc(snaplen);

  while(read(STDIN_FILENO, &packet, sizeof(packet)) == sizeof(packet)) {
    pkt_size = ptohl(packet.incl_len);

    printf("\n[+%08lx] PKT.%u.HEADER [%u.%u] size=%u\n", offset, pkt_num, ptohl(packet.ts_sec), ptohl(packet.ts_usec), pkt_size);
    hexdump(&packet, sizeof(packet));
    offset += sizeof(packet);

    if(pkt_size > snaplen) {
      fprintf(stderr, "ERROR: pkt_size(%u) > snaplen(%u)\n", pkt_size, snaplen);
      return 1;
    }

    printf("[+%08lx] PKT.%u.DATA\n", offset, pkt_num);

    if(read(STDIN_FILENO, pkt_buf, pkt_size) != pkt_size) {
      fprintf(stderr, "Error while reading packet data\n");
      return 1;
    }

    hexdump(pkt_buf, pkt_size);
    offset += pkt_size;
    pkt_num++;
  }

  free(pkt_buf);
  return 0;
}
