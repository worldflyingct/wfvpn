#define serverip          "192.168.56.101" // 服务器的地址，不支持域名
#define serverport        3478
#define clientip          "192.168.23.20/24"
#define password          "vCIhnEMbk9wgK4uUxCptm4bFxAAkGdTs" // 密码固定为32位

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <string.h>
#include <sys/wait.h>
// 包入tun相关的头部
#include <net/if.h>
#include <linux/if_tun.h>
// 包入网络相关的头部
#include <arpa/inet.h>
#include <sys/epoll.h>

#define MAXDATASIZE       16*1024*1024
#define MAX_EVENT         512
#define MAX_ACCEPT        512

struct PACKAGELIST {
    unsigned char* package;
    unsigned int size;
    struct PACKAGELIST *tail;
};
struct CLIENTLIST {
    int fd;
    int canwrite;
    struct PACKAGELIST* packagelisthead;
    struct PACKAGELIST* packagelisttail;
    unsigned int totalsize;
    unsigned char* remainpackage;
    unsigned int remainsize;
};
struct CLIENTLIST tun = {0, 1, NULL, NULL, 0, NULL, 0};
struct CLIENTLIST client = {0, 1, NULL, NULL, 0, NULL, 0};

int setnonblocking (int fd) {
    int flags = fcntl (fd, F_GETFL, 0);
    if (flags < 0) {
        printf ("get flags fail, fd:%d, in %s, at %d\n", fd, __FILE__, __LINE__);
        return -1;
    }
    if(fcntl (fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        printf ("set flags fail, fd:%d, in %s, at %d\n", fd, __FILE__, __LINE__);
        return -1;
    }
    return 0;
}

int connect_socketfd (unsigned char* ip, unsigned int port) {
    struct sockaddr_in sin;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        printf ("run socket function is fail, in %s, at %d\n", __FILE__, __LINE__);
        return -1;
    }
    memset (&sin, 0, sizeof (struct sockaddr_in));
    sin.sin_family = AF_INET; // ipv4
    in_addr_t _ip = inet_addr(ip); // 服务器ip地址，这里不能输入域名
    if (_ip == INADDR_NONE) {
        printf ("server ip error, in %s, at %d\n", __FILE__, __LINE__);
		return -2;
    }
    sin.sin_addr.s_addr = _ip;
    sin.sin_port = htons (port);
    if(connect (fd, (struct sockaddr*)&sin, sizeof(sin)) < 0) {
        printf ("connect server fail, in %s, at %d\n", __FILE__, __LINE__);
		return -5;
	}
    return fd;
}

int loginserver () {
    unsigned char data[37];
    data[0] = 0x10;
    memcpy (&data[1], password, 32);
    int addr = 0;
    unsigned char ipaddr = 0;
    for (int i = 0 ; i < sizeof (clientip)-1 ; i++) {
        if (clientip[i] == '.') {
            data[33+addr] = ipaddr;
            ipaddr = 0;
            addr++;
        } else if (clientip[i] == '/') {
            data[33+addr] = ipaddr;
            break;
        } else {
            ipaddr = 10 * ipaddr + (clientip[i]-'0');
        }
    }
    printf ("virtual ip:%d.%d.%d.%d, in %s, at %d\n", data[33], data[34], data[35], data[36], __FILE__, __LINE__);
    write (client.fd, data, sizeof (data));
}

int addtoepoll (int epollfd, int fd) {
    struct epoll_event ev;
    // memset (&ev, 0, sizeof (struct epoll_event));
    ev.data.fd = fd;
    ev.events = EPOLLIN | EPOLLERR | EPOLLHUP | EPOLLRDHUP; // 水平触发，保证所有数据都能读到
    return epoll_ctl (epollfd, EPOLL_CTL_ADD, fd, &ev);
}

int modepoll (int epollfd, int fd, unsigned int flags) {
    struct epoll_event ev;
    // memset (&ev, 0, sizeof (struct epoll_event));
    ev.data.fd = fd;
    ev.events = EPOLLIN | EPOLLERR | EPOLLHUP | EPOLLRDHUP | flags; // 水平触发，保证所有数据都能读到
    return epoll_ctl (epollfd, EPOLL_CTL_MOD, fd, &ev);
}

int tun_alloc () {
    int fd = open ("/dev/net/tun", O_RDWR);
    if (fd < 0) {
        printf ("open tun node fail, in %s, at %d\n", __FILE__, __LINE__);
        return -1;
    }
    struct ifreq ifr;
    memset (&ifr, 0, sizeof (ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    if (ioctl (fd, TUNSETIFF, (void *) &ifr) < 0) {
        printf ("ioctl tun node fail, in %s, at %d\n", __FILE__, __LINE__);
        close (fd);
        return -2;
    }
    printf ("tun device name is %s, in %s, at %d\n", ifr.ifr_name, __FILE__, __LINE__);
    char cmd [128];
    sprintf (cmd, "ip address add "clientip" dev %s", ifr.ifr_name);
    system (cmd);
    sprintf (cmd, "ip link set %s up", ifr.ifr_name);
    system (cmd);
    return fd;
}

int writenode (int epollfd, struct CLIENTLIST* clientlist) {
    struct PACKAGELIST* packagelist = clientlist->packagelisthead;
    unsigned char* packages = (unsigned char*) malloc (clientlist->totalsize * sizeof (unsigned char));
    if (packages == NULL) {
        printf ("malloc fail, len:%d, in %s, at %d\n", clientlist->totalsize,  __FILE__, __LINE__);
        return -6;
    }
    unsigned int offset = 0;
    while (packagelist != NULL) {
        memcpy (packages+offset, packagelist->package, packagelist->size);
        offset += packagelist->size;
        struct PACKAGELIST* tmppackagelist = packagelist;
        packagelist = packagelist->tail;
        free (tmppackagelist->package);
        free (tmppackagelist);
    }
    int len = write (clientlist->fd, packages, clientlist->totalsize);
    if (len < clientlist->totalsize) { // 缓冲区不足，已无法继续写入数据。
        if (modepoll (epollfd, clientlist->fd, EPOLLOUT)) {
            printf ("modepoll fail, in %s, at %d\n",  __FILE__, __LINE__);
            return -2;
        }
        clientlist->canwrite = 0;
        if (len > 0) {
            unsigned int size = clientlist->totalsize-len;
            unsigned char* packages2 = (unsigned char*) malloc (size * sizeof (unsigned char));
            if (packages2 == NULL) {
                printf ("malloc fail, size:%d, in %s, at %d\n", size,  __FILE__, __LINE__);
                return -6;
            }
            memcpy (packages2, packages+len, size);
            free (packages);
            packagelist = (struct PACKAGELIST*) malloc (sizeof (struct PACKAGELIST));
            if (packagelist == NULL) {
                printf ("malloc fail, in %s, at %d\n", size,  __FILE__, __LINE__);
                return -6;
            }
            packagelist->package = packages2;
            packagelist->size = size;
            packagelist->tail = NULL;
            clientlist->packagelisthead = packagelist;
            clientlist->packagelisttail = clientlist->packagelisthead;
            clientlist->totalsize = packagelist->size;
        } else {
            free (packages);
            clientlist->packagelisthead = NULL;
            clientlist->totalsize = 0;
        }
    } else {
        free (packages);
        clientlist->packagelisthead = NULL;
        clientlist->totalsize = 0;
    }
    return 0;
}

int readdata (int epollfd, int fd) {
    static unsigned char readbuf[MAXDATASIZE]; // 这里使用static关键词是为了将数据存储与数据段，减小对栈空间的压力。
    unsigned int len = read (fd, readbuf, MAXDATASIZE);
    if (len <= 0) {
        printf ("read fail, len: %d, in %s, at %d\n", len,  __FILE__, __LINE__);
        return -1;
    }
    struct CLIENTLIST* clientlist, *targetlist;
    if (fd == tun.fd) {
        clientlist = &tun;
        targetlist = &client;
    } else {
        clientlist = &client;
        targetlist = &tun;
    }
    unsigned int totalsize = clientlist->remainsize + len;
    unsigned char* buff = (unsigned char*) malloc (totalsize * sizeof (unsigned char));
    if (clientlist->remainsize) {
        memcpy (buff, clientlist->remainpackage, clientlist->remainsize);
        memcpy (buff+clientlist->remainsize, readbuf, len);
        free (clientlist->remainpackage);
        clientlist->remainsize = 0;
    } else {
        memcpy (buff, readbuf, len);
    }
    unsigned int offset = 0;
    while (offset < totalsize) {
        if ((buff[offset] & 0xf0) == 0x40) { // ipv4数据包
            if (offset + 20 > totalsize) { // ipv4数据包头部就最小20个字节
                unsigned int remainsize = totalsize-offset;
                unsigned char* remainpackage = (unsigned char*) malloc (remainsize * sizeof (unsigned char));
                memcpy (remainpackage, buff+offset, remainsize);
                clientlist->remainsize = remainsize;
                clientlist->remainpackage = remainpackage;
                break;
            }
            unsigned int packagesize = 256*buff[offset+2] + buff[offset+3]; // 数据包大小
            if (offset + packagesize > totalsize) { // 数据包不全
                unsigned int remainsize = totalsize-offset;
                unsigned char* remainpackage = (unsigned char*) malloc (remainsize * sizeof (unsigned char));
                memcpy (remainpackage, buff+offset, remainsize);
                clientlist->remainsize = remainsize;
                clientlist->remainpackage = remainpackage;
                break;
            }
            unsigned char* package = (unsigned char*) malloc (packagesize * sizeof (unsigned char));
            if (package == NULL) {
                offset += packagesize;
                printf ("malloc fail, in %s, at %d\n",  __FILE__, __LINE__);
                continue;
            }
            memcpy (package, buff + offset, packagesize);
            struct PACKAGELIST* packagelist = (struct PACKAGELIST*) malloc (sizeof (struct PACKAGELIST));
            if (packagelist == NULL) {
                free (package);
                offset += packagesize;
                printf ("malloc fail, in %s, at %d\n",  __FILE__, __LINE__);
                continue;
            }
            packagelist->package = package;
            packagelist->size = packagesize;
            packagelist->tail = NULL;
            if (targetlist->packagelisthead == NULL) {
                targetlist->packagelisthead = packagelist;
                targetlist->packagelisttail = targetlist->packagelisthead;
            } else {
                targetlist->packagelisttail->tail = packagelist;
                targetlist->packagelisttail = targetlist->packagelisttail->tail;
            }
            targetlist->totalsize += packagelist->size;
            if (targetlist->canwrite) { // 当前socket可写
                writenode (epollfd, targetlist);
            }
            offset += packagesize;
        } else if ((buff[offset] & 0xf0) == 0x60) { // ipv6数据包，不知道给谁的，直接扔
            if (offset + 40 > totalsize) { // ipv6数据包头部就最小40个字节
                unsigned int remainsize = totalsize-offset;
                unsigned char* remainpackage = (unsigned char*) malloc (remainsize * sizeof (unsigned char));
                memcpy (remainpackage, buff+offset, remainsize);
                clientlist->remainsize = remainsize;
                clientlist->remainpackage = remainpackage;
                break;
            }
            unsigned int packagesize = 256*buff[offset+4] + buff[offset+5] + 40; // 数据包大小
            if (offset + packagesize > totalsize) { // 数据包不全
                unsigned int remainsize = totalsize-offset;
                unsigned char* remainpackage = (unsigned char*) malloc (remainsize * sizeof (unsigned char));
                memcpy (remainpackage, buff+offset, remainsize);
                clientlist->remainsize = remainsize;
                clientlist->remainpackage = remainpackage;
                break;
            }
            offset += packagesize;
            printf ("ipv6 package, size:%d, in %s, at %d\n", packagesize,  __FILE__, __LINE__);
        }
    }
    free (buff);
    return 0;
}

int main () {
    static int tunfd, clientfd, epollfd;
    tunfd = tun_alloc (); // 这里使用static是因为这个变量是不会被释放的，因此将这个数据放到数据段。
    if (tunfd < 0) {
        printf ("alloc tun fail, in %s, at %d\n",  __FILE__, __LINE__);
        return -1;
    }
    if (setnonblocking (tunfd) < 0) {
        printf ("set nonblocking fail, fd:%d, in %s, at %d\n", tunfd, __FILE__, __LINE__);
        return -1;
    }
    tun.fd = tunfd;
    clientfd = connect_socketfd (serverip, serverport);
    if (clientfd < 0) {
        printf ("create socket fd fail, in %s, at %d\n",  __FILE__, __LINE__);
        return -2;
    }
    if (setnonblocking (clientfd) < 0) {
        printf ("set nonblocking fail, fd:%d, in %s, at %d\n", clientfd, __FILE__, __LINE__);
        return -1;
    }
    client.fd = clientfd;
    epollfd = epoll_create (MAX_EVENT);
    if (epollfd < 0) {
        printf ("create epoll fd fail, in %s, at %d\n",  __FILE__, __LINE__);
        return -3;
    }
    if (addtoepoll (epollfd, clientfd)) {
        printf ("clientfd addtoepoll fail, in %s, at %d\n",  __FILE__, __LINE__);
        return -4;
    }
    if (addtoepoll (epollfd, tunfd)) {
        printf ("tunfd addtoepoll fail, in %s, at %d\n",  __FILE__, __LINE__);
        return -5;
    }
    loginserver ();
    while (1) {
        static struct epoll_event evs[MAX_EVENT];
        static int wait_count;
        wait_count = epoll_wait (epollfd, evs, MAX_EVENT, -1);
        for (int i = 0 ; i < wait_count ; i++) {
            int fd = evs[i].data.fd;
            unsigned int events = evs[i].events;
            if (events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) { // 检测到数据异常
                close (tunfd);
                close (clientfd);
                close (epollfd);
                printf ("receive error event 0x%08x, in %s, at %d\n", evs[i].events,  __FILE__, __LINE__);
                return -6;
            } else if (events & EPOLLIN) {
                if (readdata (epollfd, fd)) {
                    close (tunfd);
                    close (clientfd);
                    close (epollfd);
                    return -7;
                }
            } else if (events & EPOLLOUT) {
                if (modepoll (epollfd, fd, 0)) {
                    printf ("modepoll fail, in %s, at %d\n",  __FILE__, __LINE__);
                    return -2;
                }
                if (fd == tun.fd) {
                    tun.canwrite = 1;
                    writenode (epollfd, &tun);
                } else {
                    client.canwrite = 1;
                    writenode (epollfd, &client);
                }
            } else {
                printf ("receive new event 0x%08x, in %s, at %d\n", evs[i].events,  __FILE__, __LINE__);
            }
        }
    }
    return 0;
}
