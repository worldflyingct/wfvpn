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
// 包入tun相关的头部
#include <net/if.h>
#include <linux/if_tun.h>
// 包入网络相关的头部
#include <arpa/inet.h>
#include <sys/epoll.h>

#define MAXDATASIZE       2*1024*1024
#define MAX_EVENT         1024
#define MAX_ACCEPT        1024

struct PACKAGELIST {
    unsigned char package[1500];
    unsigned int size;
    struct PACKAGELIST *tail;
};
struct PACKAGELIST* packagelisthead = NULL;
struct PACKAGELIST* packagelisttail;
struct CLIENTLIST {
    int fd;
    int canwrite;
    struct PACKAGELIST* packagelisthead;
    struct PACKAGELIST* packagelisttail;
    unsigned int totalsize;
    unsigned char remainpackage[1500];
    unsigned int remainsize;
};
struct CLIENTLIST tun;
struct CLIENTLIST client;

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
    unsigned char data[5+sizeof(password)-1];
    data[0] = 0x10;
    int addr = 0;
    unsigned char ipaddr = 0;
    for (int i = 0 ; i < sizeof (clientip)-1 ; i++) {
        if (clientip[i] == '.') {
            data[1+addr] = ipaddr;
            ipaddr = 0;
            addr++;
        } else if (clientip[i] == '/') {
            data[1+addr] = ipaddr;
            break;
        } else {
            ipaddr = 10 * ipaddr + (clientip[i]-'0');
        }
    }
    printf ("virtual ip:%d.%d.%d.%d, in %s, at %d\n", data[1], data[2], data[3], data[4], __FILE__, __LINE__);
    memcpy (data + 5, password, sizeof(password)-1);
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
    unsigned char cmd [128];
    sprintf (cmd, "ip address add "clientip" dev %s", ifr.ifr_name);
    system (cmd);
    sprintf (cmd, "ip link set %s up", ifr.ifr_name);
    system (cmd);
    return fd;
}

int writenode (int epollfd, struct CLIENTLIST* clientlist) {
    static unsigned char* packages = NULL;
    static unsigned int maxtotalsize = 0;
    if (maxtotalsize < clientlist->totalsize) {
        maxtotalsize = clientlist->totalsize;
        if (packages != NULL) {
            free (packages);
        }
        packages = (unsigned char*) malloc (maxtotalsize * sizeof (unsigned char));
    }
    struct PACKAGELIST* packagelist = clientlist->packagelisthead;
    unsigned int offset = 0;
    while (packagelist != NULL) {
        memcpy (packages+offset, packagelist->package, packagelist->size);
        offset += packagelist->size;
        if (packagelisthead == NULL) {
            packagelisthead = packagelist;
            packagelisttail = packagelisthead;
        } else {
            packagelisttail->tail = packagelist;
            packagelisttail = packagelisttail->tail;
        }
        packagelist = packagelist->tail;
        packagelisttail->tail = NULL;
    }
    int len = write (clientlist->fd, packages, clientlist->totalsize);
    if (len < clientlist->totalsize) { // 缓冲区不足，已无法继续写入数据。
        if (modepoll (epollfd, clientlist->fd, EPOLLOUT)) {
            printf ("modepoll fail, in %s, at %d\n",  __FILE__, __LINE__);
            return -2;
        }
        clientlist->canwrite = 0;
        if (len > 0) {
            unsigned int size = clientlist->totalsize - len;
            struct PACKAGELIST* packagelisthead2 = NULL;
            struct PACKAGELIST* packagelisttail2;
            while (len < clientlist->totalsize) {
                if (packagelisthead != NULL) { // 全局数据包回收站不为空
                    packagelist = packagelisthead;
                    packagelisthead = packagelisthead->tail;
                } else {
                    packagelist = (struct PACKAGELIST*) malloc (sizeof (struct PACKAGELIST));
                    if (packagelist == NULL) {
                        printf ("malloc fail, in %s, at %d\n",  __FILE__, __LINE__);
                        return -6;
                    }
                }
                unsigned int copylen = clientlist->totalsize - len;
                if (copylen > 1500) {
                    copylen = 1500;
                }
                memcpy (packagelist->package, packages+len, copylen);
                len += copylen;
                packagelist->size = copylen;
                packagelist->tail = NULL;
                if (packagelisthead2 == NULL) {
                    packagelisthead2 = packagelist;
                    packagelisttail2 = packagelisthead2;
                } else {
                    packagelisttail2->tail = packagelist;
                    packagelisttail2 = packagelisttail2->tail;
                }
            }
            clientlist->packagelisthead = packagelisthead2;
            clientlist->packagelisttail = packagelisttail2;
            clientlist->totalsize = size;
        } else {
            clientlist->packagelisthead = NULL;
            clientlist->totalsize = 0;
        }
    } else {
        clientlist->packagelisthead = NULL;
        clientlist->totalsize = 0;
    }
    return 0;
}

int readdata (int epollfd, int fd) {
    static unsigned char readbuf[MAXDATASIZE]; // 这里使用static关键词是为了将数据存储与数据段，减小对栈空间的压力。
    static unsigned char* readbuff = NULL;
    static unsigned int maxtotalsize = 0;
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
    unsigned int totalsize;
    unsigned char* buff;
    if (clientlist->remainsize) {
        totalsize = clientlist->remainsize + len;
        if (totalsize > maxtotalsize) {
            maxtotalsize = totalsize;
            if (readbuff != NULL) {
                free (readbuff);
            }
            readbuff = (unsigned char*) malloc (totalsize * sizeof (unsigned char));
        }
        buff = readbuff;
        memcpy (readbuff, clientlist->remainpackage, clientlist->remainsize);
        memcpy (readbuff+clientlist->remainsize, readbuf, len);
        clientlist->remainsize = 0;
    } else {
        totalsize = len;
        buff = readbuf;
    }
    unsigned int offset = 0;
    while (offset < totalsize) {
        if ((buff[offset] & 0xf0) == 0x40) { // ipv4数据包
            if (offset + 20 > totalsize) { // ipv4数据包头部就最小20个字节
                unsigned int remainsize = totalsize-offset;
                memcpy (clientlist->remainpackage, buff+offset, remainsize);
                clientlist->remainsize = remainsize;
                break;
            }
            unsigned int packagesize = 256*buff[offset+2] + buff[offset+3]; // 数据包大小
            if (offset + packagesize > totalsize) { // 数据包不全
                unsigned int remainsize = totalsize-offset;
                memcpy (clientlist->remainpackage, buff+offset, remainsize);
                clientlist->remainsize = remainsize;
                break;
            }
            struct PACKAGELIST* packagelist;
            if (packagelisthead != NULL) {
                packagelist = packagelisthead;
                packagelisthead = packagelisthead->tail;
            } else {
                packagelist = (struct PACKAGELIST*) malloc (sizeof (struct PACKAGELIST));
                if (packagelist == NULL) {
                    offset += packagesize;
                    printf ("malloc fail, in %s, at %d\n",  __FILE__, __LINE__);
                    continue;
                }
            }
            memcpy (packagelist->package, buff + offset, packagesize);
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
                memcpy (clientlist->remainpackage, buff+offset, remainsize);
                clientlist->remainsize = remainsize;
                break;
            }
            unsigned int packagesize = 256*buff[offset+4] + buff[offset+5] + 40; // 数据包大小
            if (offset + packagesize > totalsize) { // 数据包不全
                unsigned int remainsize = totalsize-offset;
                memcpy (clientlist->remainpackage, buff+offset, remainsize);
                clientlist->remainsize = remainsize;
                break;
            }
            offset += packagesize;
            printf ("ipv6 package, size:%d, in %s, at %d\n", packagesize,  __FILE__, __LINE__);
        } else {
            printf ("unknown package, offset:%d, fd:%d, buff:0x%02x,0x%02x,0x%02x,0x%02x,0x%02x,0x%02x,0x%02x,0x%02x, in %s, at %d\n", offset, fd, buff[offset], buff[offset+1], buff[offset+2], buff[offset+3], buff[offset+4], buff[offset+5], buff[offset+6], buff[offset+7],  __FILE__, __LINE__);
            exit (0);
        }
    }
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
    tun.canwrite = 1;
    tun.packagelisthead = NULL;
    tun.remainsize = 0;
    tun.totalsize = 0;
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
    client.canwrite = 1;
    client.packagelisthead = NULL;
    client.remainsize = 0;
    client.totalsize = 0;
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
