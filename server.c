#define tundevip          "192.168.23.1/24"
#define serverport        3478
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
#define MAX_CONNECT       256

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
    unsigned char ip[4];
    struct PACKAGELIST* packagelisthead;
    struct PACKAGELIST* packagelisttail;
    unsigned int totalsize;
    unsigned char remainpackage[1500];
    unsigned int remainsize;
    struct CLIENTLIST *head;
    struct CLIENTLIST *tail;
};
struct CLIENTLIST* clientlisthead = NULL;
struct CLIENTLIST* clientlisttail;
struct CLIENTLIST* remainclientlisthead = NULL;
struct CLIENTLIST* remainclientlisttail;

int setnonblocking (int fd) {
    int flags = fcntl (fd, F_GETFL, 0);
    if (flags < 0) {
        printf ("get flags fail, fd:%d, in %s, at %d\n", fd, __FILE__, __LINE__);
        return -1;
    }
    if(fcntl (fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        printf ("set flags fail, fd:%d, in %s, at %d\n", fd, __FILE__, __LINE__);
        return -2;
    }
    return 0;
}

int create_socketfd (unsigned int port) {
    struct sockaddr_in sin;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        printf ("run socket function is fail, in %s, at %d\n", __FILE__, __LINE__);
        return -1;
    }
    memset (&sin, 0, sizeof (struct sockaddr_in));
    sin.sin_family = AF_INET; // ipv4
    sin.sin_addr.s_addr = INADDR_ANY; // 本机任意ip
    sin.sin_port = htons (port);
    if (bind (fd, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        printf ("bind port %d fail, in %s, at %d\n", port, __FILE__, __LINE__);
        return -2;
    }
    if (listen (fd, MAX_CONNECT) < 0) {
        printf ("listen port %d fail, in %s, at %d\n", serverport, __FILE__, __LINE__);
        return -3;
    }
    return fd;
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

int removeclient (int epollfd, int fd) {
    struct epoll_event ev;
    epoll_ctl (epollfd, EPOLL_CTL_DEL, fd, &ev);
    close (fd);
    struct CLIENTLIST* clientlist;
    for (clientlist = clientlisthead ; clientlist != NULL ; clientlist = clientlist->tail) {
        if (fd == clientlist->fd) {
            break;
        }
    }
    if (clientlist == NULL) {
        printf ("client fd:%d is not found, in %s, at %d\n", fd,  __FILE__, __LINE__);
        return -1;
    }
    if (clientlist->head == NULL) {
        clientlisthead = clientlist->tail;
        if (clientlisthead != NULL) {
            clientlisthead->head = NULL;
        }
    } else if (clientlist->tail == NULL) {
        clientlisttail = clientlist->head;
        clientlisttail->tail = NULL;
    } else {
        clientlist->head->tail = clientlist->tail;
        clientlist->tail->head = clientlist->head;
    }
    if (packagelisthead == NULL) {
        packagelisthead = clientlist->packagelisthead;
        packagelisttail = packagelisthead;
    } else {
        packagelisttail->tail = clientlist->packagelisthead;
    }
    if (packagelisttail != NULL) {
        while (packagelisttail->tail != NULL) {
            packagelisttail = packagelisttail->tail;
        }
    }
    printf ("host %d.%d.%d.%d disconnect, in %s, at %d\n", clientlist->ip[0], clientlist->ip[1], clientlist->ip[2], clientlist->ip[3],  __FILE__, __LINE__);
    if (remainclientlisthead == NULL) {
        remainclientlisthead = clientlist;
        remainclientlisttail = remainclientlisthead;
    } else {
        remainclientlisttail->tail = clientlist;
        remainclientlisttail = remainclientlisttail->tail;
    }
    remainclientlisttail->tail = NULL;
    return 0;
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
    sprintf (cmd, "ip address add "tundevip" dev %s", ifr.ifr_name);
    system (cmd);
    sprintf (cmd, "ip link set %s up", ifr.ifr_name);
    system (cmd);
    printf ("tun ip is "tundevip", in %s, at %d\n", __FILE__, __LINE__);
    struct CLIENTLIST* clientlist;
    if (remainclientlisthead != NULL) {
        clientlist = remainclientlisthead;
        remainclientlisthead = remainclientlisthead->tail;
    } else {
        clientlist = (struct CLIENTLIST*) malloc (sizeof (struct CLIENTLIST));
        if (clientlist == NULL) {
            printf ("malloc fail, in %s, at %d\n",  __FILE__, __LINE__);
            return -3;
        }
    }
    clientlist->fd = fd;
    clientlist->canwrite = 1;
    clientlist->packagelisthead = NULL;
    clientlist->totalsize = 0;
    clientlist->remainsize = 0;
    int addr = 0;
    unsigned char ipaddr = 0;
    for (int i = 0 ; i < sizeof (tundevip)-1 ; i++) {
        if (tundevip[i] == '.') {
            clientlist->ip[addr] = ipaddr;
            ipaddr = 0;
            addr++;
        } else if (tundevip[i] == '/') {
            clientlist->ip[addr] = ipaddr;
            break;
        } else {
            ipaddr = 10 * ipaddr + (tundevip[i]-'0');
        }
    }
    clientlist->head = NULL;
    clientlist->tail = NULL;
    if (clientlisthead == NULL) {
        clientlisthead = clientlist;
        clientlisttail = clientlisthead;
    } else {
        clientlisttail->tail = clientlist;
        clientlisttail = clientlisttail->tail;
    }
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
            return -1;
        }
        clientlist->canwrite = 0;
        if (len > 0) { // 写入了一部分数据
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
                        return -2;
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
            return 0;
        }
    }
    clientlist->packagelisthead = NULL;
    clientlist->totalsize = 0;
    return 0;
}

int readdata (int epollfd, int fd) {
    static unsigned char readbuf[MAXDATASIZE]; // 这里使用static关键词是为了将数据存储与数据段，减小对栈空间的压力。
    static unsigned char* readbuff = NULL;
    static unsigned int maxtotalsize = 0;
    int len = read (fd, readbuf, MAXDATASIZE);
    if (len <= 0) {
        printf ("read fail, len: %d, in %s, at %d\n", len,  __FILE__, __LINE__);
        return -1;
    }
    struct CLIENTLIST* clientlist;
    for (clientlist = clientlisthead ; clientlist != NULL ; clientlist = clientlist->tail) {
        if (fd == clientlist->fd) {
            break;
        }
    }
    unsigned int offset = 0;
    if (clientlist == NULL) { // 用户没有找到
        if (readbuf[0] != 0x10) { // 只能执行登录操作
            printf ("just can run login, in %s, at %d\n",  __FILE__, __LINE__);
            return -2;
        }
        if (memcmp (readbuf+5, password, sizeof (password)-1)) { // 绑定密码错误
            printf ("password check fail, in %s, at %d\n",  __FILE__, __LINE__);
            return -3;
        }
        int canuse = 1;
        for (struct CLIENTLIST* clientlist = clientlisthead ; clientlist != NULL ; clientlist = clientlist->tail) {
            if (readbuf[1] == clientlist->ip[0] && readbuf[2] == clientlist->ip[1] && readbuf[3] == clientlist->ip[2] && readbuf[4] == clientlist->ip[3]) {
                canuse = 0;
                break;
            }
        }
        if (!canuse) {
            printf ("ip %d.%d.%d.%d is exist, in %s, at %d\n", readbuf[1], readbuf[2], readbuf[3], readbuf[4],  __FILE__, __LINE__);
            return -4;
        }
        if (remainclientlisthead != NULL) {
            clientlist = remainclientlisthead;
            remainclientlisthead = remainclientlisthead->tail;
        } else {
            clientlist = (struct CLIENTLIST*) malloc (sizeof (struct CLIENTLIST));
            if (clientlist == NULL) {
                printf ("malloc fail, in %s, at %d\n",  __FILE__, __LINE__);
                return -5;
            }
        }
        clientlist->fd = fd;
        memcpy (clientlist->ip, readbuf+1, 4);
        clientlist->canwrite = 1;
        clientlist->packagelisthead = NULL;
        clientlist->totalsize = 0;
        clientlist->remainsize = 0;
        clientlist->head = clientlisttail;
        clientlist->tail = NULL;
        clientlisttail->tail = clientlist;
        clientlisttail = clientlisttail->tail;
        offset += 5 + sizeof (password) - 1; // 绑定包长度
        printf ("add client success, client ip is %d.%d.%d.%d, in %s, at %d\n", readbuf[1], readbuf[2], readbuf[3], readbuf[4],  __FILE__, __LINE__);
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
            struct CLIENTLIST* clientlist;
            for (clientlist = clientlisthead ; clientlist != NULL ; clientlist = clientlist->tail) {
                if (fd == clientlist->fd) {
                    break;
                }
            }
            if (clientlist == NULL) {
                offset += packagesize;
                printf ("client:%d is not login, in %s, at %d\n", fd,  __FILE__, __LINE__);
                continue;
            }
            for (clientlist = clientlisthead ; clientlist != NULL ; clientlist = clientlist->tail) {
                if (buff[offset+16] == clientlist->ip[0] && buff[offset+17] == clientlist->ip[1] && buff[offset+18] == clientlist->ip[2] && buff[offset+19] == clientlist->ip[3]) {
                    break;
                }
            }
            if (clientlist == NULL) {
                offset += packagesize;
                printf ("target client %d.%d.%d.%d not found, in %s, at %d\n", buff[offset+16], buff[offset+17], buff[offset+18], buff[offset+19],  __FILE__, __LINE__);
                continue;
            }
            struct PACKAGELIST* packagelist;
            if (packagelisthead != NULL) { // 全局数据包回收站不为空
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
            if (clientlist->packagelisthead == NULL) {
                clientlist->packagelisthead = packagelist;
                clientlist->packagelisttail = clientlist->packagelisthead;
            } else {
                clientlist->packagelisttail->tail = packagelist;
                clientlist->packagelisttail = clientlist->packagelisttail->tail;
            }
            clientlist->totalsize += packagelist->size;
            if (clientlist->canwrite) { // 当前socket可写
                writenode (epollfd, clientlist);
            }
            offset += packagesize;
        } else if (buff[offset] == 0x10) { // 绑定数据包
            if (offset + 5 + sizeof (password) - 1 > totalsize) { // 绑定包长度
                unsigned int remainsize = totalsize-offset;
                memcpy (clientlist->remainpackage, buff+offset, remainsize);
                clientlist->remainsize = remainsize;
                break;
            }
            offset += 5 + sizeof (password) - 1;
            printf ("client already login, in %s, at %d\n",  __FILE__, __LINE__);
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
            printf ("ipv6 package size:%d, in %s, at %d\n", packagesize,  __FILE__, __LINE__);
        } else {
            printf ("unknown package, offset:%d, fd:%d, buff:0x%02x,0x%02x,0x%02x,0x%02x,0x%02x,0x%02x,0x%02x,0x%02x, in %s, at %d\n", offset, fd, buff[offset], buff[offset+1], buff[offset+2], buff[offset+3], buff[offset+4], buff[offset+5], buff[offset+6], buff[offset+7],  __FILE__, __LINE__);
            exit (0);
        }
    }
    return 0;
}

int main () {
    static int tunfd, serverfd, epollfd;
    tunfd = tun_alloc (); // 这里使用static是因为这个变量是不会被释放的，因此将这个数据放到数据段。
    if (tunfd < 0) {
        printf ("alloc tun fail, in %s, at %d\n",  __FILE__, __LINE__);
        return -1;
    }
    if (setnonblocking (tunfd) < 0) {
        printf ("set nonblocking fail, fd:%d, in %s, at %d\n", tunfd, __FILE__, __LINE__);
        return -2;
    }
    serverfd = create_socketfd (serverport);
    if (serverfd < 0) {
        printf ("create socket fd fail, in %s, at %d\n",  __FILE__, __LINE__);
        return -3;
    }
    if (setnonblocking (serverfd) < 0) {
        printf ("set nonblocking fail, fd:%d, in %s, at %d\n", serverfd, __FILE__, __LINE__);
        return -4;
    }
    epollfd = epoll_create (MAX_EVENT);
    if (epollfd < 0) {
        printf ("create epoll fd fail, in %s, at %d\n",  __FILE__, __LINE__);
        return -5;
    }
    if (addtoepoll (epollfd, serverfd)) {
        printf ("serverfd addtoepoll fail, in %s, at %d\n",  __FILE__, __LINE__);
        return -6;
    }
    if (addtoepoll (epollfd, tunfd)) {
        printf ("tunfd addtoepoll fail, in %s, at %d\n",  __FILE__, __LINE__);
        return -7;
    }
    printf ("init finish, server port is %d password is "password", in %s, at %d\n", serverport,  __FILE__, __LINE__);
    while (1) {
        static struct epoll_event evs[MAX_EVENT];
        static int wait_count;
        wait_count = epoll_wait (epollfd, evs, MAX_EVENT, -1);
        for (int i = 0 ; i < wait_count ; i++) {
            int fd = evs[i].data.fd;
            unsigned int events = evs[i].events;
            if (events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) { // 检测到数据异常
                printf ("connect lose:%d, EPOLLERR:%d, EPOLLHUP:%d, EPOLLRDHUP:%d, in %s, at %d\n", fd, events&EPOLLERR ? 1 : 0, events&EPOLLHUP ? 1 : 0, events&EPOLLRDHUP ? 1 : 0,  __FILE__, __LINE__);
                removeclient (epollfd, fd);
                continue;
            } else if (fd == serverfd) {
                struct sockaddr_in sin;
                socklen_t in_addr_len = sizeof (struct sockaddr_in);
                int newfd = accept (serverfd, (struct sockaddr*)&sin, &in_addr_len);
                printf ("new socket:%d, in %s, at %d\n", newfd,  __FILE__, __LINE__);
                if (newfd < 0) {
                    printf ("accept a new fd fail, in %s, at %d\n",  __FILE__, __LINE__);
                    continue;
                }
                if (setnonblocking (newfd) < 0) {
                    printf ("set nonblocking fail, fd:%d, in %s, at %d\n", newfd, __FILE__, __LINE__);
                    continue;
                }
/* 这是设置收发缓冲区大小的代码段。
                socklen_t len = sizeof(int);
                unsigned int bufsize;
                if (getsockopt(newfd, SOL_SOCKET, SO_RCVBUF, (unsigned char*)&bufsize, &len)) {
                    printf ("get receive buffer fail, in %s, at %d\n",  __FILE__, __LINE__);
                    continue;
                }
                printf ("receive buffer is %d, len:%d, in %s, at %d\n", bufsize, len,  __FILE__, __LINE__);
                len = sizeof(unsigned int);
                if (getsockopt(newfd, SOL_SOCKET, SO_SNDBUF, (unsigned char*)&bufsize, &len)) {
                    printf ("get send buffer fail, in %s, at %d\n",  __FILE__, __LINE__);
                    continue;
                }
                printf ("send buffer is %d, len:%d, in %s, at %d\n", bufsize, len,  __FILE__, __LINE__);
                bufsize = MAXDATASIZE - 1500;
                if (setsockopt(newfd, SOL_SOCKET, SO_RCVBUF, (char*)&bufsize, sizeof (int))) {
                    printf ("set receive buffer fail, in %s, at %d\n",  __FILE__, __LINE__);
                    continue;
                }
                bufsize = MAXDATASIZE - 1500;
                if (setsockopt(newfd, SOL_SOCKET, SO_SNDBUF, (unsigned char*)&bufsize, sizeof (int))) {
                    printf ("set send buffer fail, in %s, at %d\n",  __FILE__, __LINE__);
                    continue;
                }
                len = sizeof(unsigned int);
                if (getsockopt(newfd, SOL_SOCKET, SO_RCVBUF, (unsigned char*)&bufsize, &len)) {
                    printf ("get receive buffer fail, in %s, at %d\n",  __FILE__, __LINE__);
                    continue;
                }
                printf ("receive buffer is %d, len:%d, in %s, at %d\n", bufsize, len,  __FILE__, __LINE__);
                len = sizeof(unsigned int);
                if (getsockopt(newfd, SOL_SOCKET, SO_SNDBUF, (unsigned char*)&bufsize, &len)) {
                    printf ("get send buffer fail, in %s, at %d\n",  __FILE__, __LINE__);
                    continue;
                }
                printf ("send buffer is %d, len:%d, in %s, at %d\n", bufsize, len,  __FILE__, __LINE__);
*/
                if (addtoepoll (epollfd, newfd)) {
                    close (newfd);
                    printf ("add to epoll fail, in %s, at %d\n",  __FILE__, __LINE__);
                    continue;
                }
            } else if (events & EPOLLIN) { // 数据可读
                if (readdata (epollfd, fd)) {
                    removeclient (epollfd, fd);
                    continue;
                }
            } else if (events & EPOLLOUT) { // 数据可写
                if (modepoll (epollfd, fd, 0)) {
                    printf ("modepoll fail, in %s, at %d\n",  __FILE__, __LINE__);
                    return -8;
                }
                struct CLIENTLIST* clientlist;
                for (clientlist = clientlisthead ; clientlist != NULL ; clientlist = clientlist->tail) {
                    if (fd == clientlist->fd) {
                        break;
                    }
                }
                if (clientlist == NULL) { // 客户端列表没有找到
                    printf ("client not found, fd:%d, in %s, at %d\n", fd,  __FILE__, __LINE__);
                    continue;
                }
                clientlist->canwrite = 1;
                writenode (epollfd, clientlist);
            } else {
                printf ("receive new event 0x%08x, in %s, at %d\n", events,  __FILE__, __LINE__);
            }
        }
    }
    return 0;
}
