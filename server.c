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

#define MAXDATASIZE       8*1024*1024
#define MAX_EVENT         512
#define MAX_ACCEPT        512
#define MAX_CONNECT       256

struct PACKAGELIST {
    unsigned char package[1500];
    unsigned int size;
    struct PACKAGELIST *tail;
};
struct CLIENTLIST {
    int fd;
    int canwrite;
    unsigned char ip[4];
    struct PACKAGELIST* packagelisthead;
    struct PACKAGELIST* packagelisttail;
    unsigned int totalsize;
    unsigned char* remainpackage;
    unsigned int remainsize;
    struct CLIENTLIST *head;
    struct CLIENTLIST *tail;
};
struct CLIENTLIST* clientlisthead = NULL;
struct CLIENTLIST* clientlisttail;

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
        return -5;
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
        clientlisthead->head = NULL;
    } else if (clientlist->tail == NULL) {
        clientlisttail = clientlist->head;
        clientlisttail->tail = NULL;
    } else {
        clientlist->head->tail = clientlist->tail;
        clientlist->tail->head = clientlist->head;
    }
    struct PACKAGELIST* packagelist = clientlist->packagelisthead;
    while (packagelist != NULL) {
        struct PACKAGELIST* tmppackagelist = packagelist;
        packagelist = packagelist->tail;
        free (tmppackagelist);
    }
    printf ("host %d.%d.%d.%d disconnect, in %s, at %d\n", clientlist->ip[0], clientlist->ip[1], clientlist->ip[2], clientlist->ip[3],  __FILE__, __LINE__);
    free (clientlist);
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
    clientlisthead = (struct CLIENTLIST*) malloc (sizeof (struct CLIENTLIST));
    if (clientlisthead == NULL) {
        printf ("malloc fail, in %s, at %d\n",  __FILE__, __LINE__);
        return -3;
    }
    clientlisthead->fd = fd;
    clientlisthead->canwrite = 1;
    clientlisthead->packagelisthead = NULL;
    clientlisthead->totalsize = 0;
    clientlisthead->remainsize = 0;
    int addr = 0;
    unsigned char ipaddr = 0;
    for (int i = 0 ; i < sizeof (tundevip)-1 ; i++) {
        if (tundevip[i] == '.') {
            clientlisthead->ip[addr] = ipaddr;
            ipaddr = 0;
            addr++;
        } else if (tundevip[i] == '/') {
            clientlisthead->ip[addr] = ipaddr;
            break;
        } else {
            ipaddr = 10 * ipaddr + (tundevip[i]-'0');
        }
    }
    clientlisthead->head = NULL;
    clientlisthead->tail = NULL;
    clientlisttail = clientlisthead;
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
            struct PACKAGELIST* packagelisthead = NULL;
            struct PACKAGELIST* packagelisttail;
            while (len < clientlist->totalsize) {
                packagelist = (struct PACKAGELIST*) malloc (sizeof (struct PACKAGELIST));
                if (packagelist == NULL) {
                    printf ("malloc fail, in %s, at %d\n", size,  __FILE__, __LINE__);
                    return -6;
                }
                unsigned int copylen = clientlist->totalsize - len;
                if (copylen > 1500) {
                    copylen = 1500;
                }
                memcpy (packagelist->package, packages+len, copylen);
                len += copylen;
                packagelist->size = copylen;
                packagelist->tail = NULL;
                if (packagelisthead == NULL) {
                    packagelisthead = packagelist;
                    packagelisttail = packagelisthead;
                } else {
                    packagelisttail->tail = packagelist;
                    packagelisttail = packagelisttail->tail;
                }
            }
            free (packages);
            clientlist->packagelisthead = packagelisthead;
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

void saveincompletepackage (unsigned int remainsize, unsigned char* buff, struct CLIENTLIST* clientlist) {
    unsigned char* remainpackage = (unsigned char*) malloc (remainsize * sizeof (unsigned char));
    memcpy (remainpackage, buff, remainsize);
    clientlist->remainsize = remainsize;
    clientlist->remainpackage = remainpackage;
}

int readdata (int epollfd, int fd) {
    static unsigned char readbuf[MAXDATASIZE]; // 这里使用static关键词是为了将数据存储与数据段，减小对栈空间的压力。
    unsigned int len = read (fd, readbuf, MAXDATASIZE);
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
        clientlist = (struct CLIENTLIST*) malloc (sizeof (struct CLIENTLIST));
        if (clientlist == NULL) {
            printf ("malloc fail, in %s, at %d\n",  __FILE__, __LINE__);
            return -5;
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
        buff = (unsigned char*) malloc (totalsize * sizeof (unsigned char));
        memcpy (buff, clientlist->remainpackage, clientlist->remainsize);
        memcpy (buff+clientlist->remainsize, readbuf, len);
        free (clientlist->remainpackage);
        clientlist->remainsize = 0;
    } else {
        totalsize = len;
        buff = readbuf;
    }
    while (offset < totalsize) {
        if ((buff[offset] & 0xf0) == 0x40) { // ipv4数据包
            if (offset + 20 > totalsize) { // ipv4数据包头部就最小20个字节
                saveincompletepackage (totalsize-offset, buff+offset, clientlist);
                break;
            }
            unsigned int packagesize = 256*buff[offset+2] + buff[offset+3]; // 数据包大小
            if (offset + packagesize > totalsize) { // 数据包不全
                saveincompletepackage (totalsize-offset, buff+offset, clientlist);
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
            struct PACKAGELIST* packagelist = (struct PACKAGELIST*) malloc (sizeof (struct PACKAGELIST));
            if (packagelist == NULL) {
                offset += packagesize;
                printf ("malloc fail, in %s, at %d\n",  __FILE__, __LINE__);
                continue;
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
            offset += packagesize;
            if (clientlist->canwrite) { // 当前socket可写
                writenode (epollfd, clientlist);
            }
        } else if (buff[offset] == 0x10) { // 绑定数据包
            if (offset + 5 + sizeof (password) - 1 > totalsize) { // 绑定包长度
                saveincompletepackage (totalsize-offset, buff+offset, clientlist);
                break;
            }
            offset += 5 + sizeof (password) - 1;
            printf ("client already login, in %s, at %d\n",  __FILE__, __LINE__);
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
                saveincompletepackage (totalsize-offset, buff+offset, clientlist);
                break;
            }
            offset += packagesize;
            printf ("ipv6 package size:%d, in %s, at %d\n", packagesize,  __FILE__, __LINE__);
        } else {
            printf ("unknown package, offset:%d, fd:%d, buff:0x%02x,0x%02x,0x%02x,0x%02x,0x%02x,0x%02x,0x%02x,0x%02x, in %s, at %d\n", offset, fd, buff[offset], buff[offset+1], buff[offset+2], buff[offset+3], buff[offset+4], buff[offset+5], buff[offset+6], buff[offset+7],  __FILE__, __LINE__);
            exit (0);
        }
    }
    if (buff != readbuf) {
        free (buff);
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
        return -1;
    }
    serverfd = create_socketfd (serverport);
    if (serverfd < 0) {
        printf ("create socket fd fail, in %s, at %d\n",  __FILE__, __LINE__);
        return -2;
    }
    if (setnonblocking (serverfd) < 0) {
        printf ("set nonblocking fail, fd:%d, in %s, at %d\n", serverfd, __FILE__, __LINE__);
        return -1;
    }
    epollfd = epoll_create (MAX_EVENT);
    if (epollfd < 0) {
        printf ("create epoll fd fail, in %s, at %d\n",  __FILE__, __LINE__);
        return -3;
    }
    if (addtoepoll (epollfd, serverfd)) {
        printf ("serverfd addtoepoll fail, in %s, at %d\n",  __FILE__, __LINE__);
        return -4;
    }
    if (addtoepoll (epollfd, tunfd)) {
        printf ("tunfd addtoepoll fail, in %s, at %d\n",  __FILE__, __LINE__);
        return -5;
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
                    return -2;
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
