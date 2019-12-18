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
#include <netinet/in.h>
#include <sys/epoll.h>

#define MAXDATASIZE       32*1024*1024
#define MAX_EVENT         512
#define MAX_ACCEPT        512
#define MAX_CONNECT       256

struct PACKAGELIST {
    unsigned char* package;
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
    struct CLIENTLIST *head;
    struct CLIENTLIST *tail;
};
struct CLIENTLIST* clientlisthead = NULL;
struct CLIENTLIST* clientlisttail;
int epollfd, tunfd, serverfd;

int create_socketfd () {
    struct sockaddr_in sin;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        printf ("run socket function is fail, in %s, at %d\n", __FILE__, __LINE__);
        return -1;
    }
    memset (&sin, 0, sizeof (struct sockaddr_in));
    sin.sin_family = AF_INET; // ipv4
    sin.sin_addr.s_addr = INADDR_ANY; // 本机任意ip
    sin.sin_port = htons (serverport);
    if (bind (fd, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        printf ("bind port %d fail, in %s, at %d\n", serverport, __FILE__, __LINE__);
        return -2;
    }
    int flags = fcntl (fd, F_GETFL, 0);
    if (flags < 0) {
        printf ("get flags fail, in %s, at %d\n", __FILE__, __LINE__);
        return -3;
    }
    if(fcntl (fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        printf ("set flags fail, in %s, at %d\n", __FILE__, __LINE__);
        return -4;
    }
    if (listen (fd, MAX_CONNECT) < 0) {
        printf ("listen port %d fail, in %s, at %d\n", serverport, __FILE__, __LINE__);
        return -5;
    }
    return fd;
}

int addtoepoll (int fd) {
    struct epoll_event ev;
    memset (&ev, 0, sizeof (struct epoll_event));
    ev.data.fd = fd;
    ev.events = EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP | EPOLLRDHUP | EPOLLET; // 水平触发，因为每个ip数据包的大小一定小于1500，所以一定可以一次读出全部数据
    return epoll_ctl (epollfd, EPOLL_CTL_ADD, fd, &ev);
}

int removeclient (int fd) {
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
        free (tmppackagelist->package);
        free (tmppackagelist);
    }
    printf ("host %d.%d.%d.%d disconnect, in %s, at %d\n", clientlist->ip[0], clientlist->ip[1], clientlist->ip[2], clientlist->ip[3],  __FILE__, __LINE__);
    free (clientlist);
    return 0;
}

int tun_alloc () {
    int fd = open ("/dev/net/tun", O_RDWR | O_NONBLOCK);
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

int writenode (struct CLIENTLIST* clientlist) {
    unsigned char* packages = (unsigned char*) malloc (clientlist->totalsize * sizeof (unsigned char));
    if (packages == NULL) {
        printf ("malloc fail, in %s, at %d\n",  __FILE__, __LINE__);
        return -1;
    }
    unsigned int offset = 0;
    struct PACKAGELIST* packagelist = clientlist->packagelisthead;
    while (packagelist != NULL) {
        memcpy (packages + offset, packagelist->package, packagelist->size);
        offset += packagelist->size;
        struct PACKAGELIST* tmppackagelist = packagelist;
        packagelist = packagelist->tail;
        free (tmppackagelist->package);
        free (tmppackagelist);
    }
    write (clientlist->fd, packages, clientlist->totalsize);
    clientlist->packagelisthead = NULL;
    clientlist->totalsize = 0;
    clientlist->canwrite = 0;
    free (packages);
    return 0;
}

int readdata (int fd, unsigned char* readbuf, unsigned int len) {
    unsigned int offset = 0;
    while (offset < len) {
        if ((readbuf[offset] & 0xf0) == 0x40) { // ipv4数据包
            unsigned int packagesize = 256*readbuf[offset+2] + readbuf[offset+3]; // 数据包大小
            struct CLIENTLIST* clientlist;
            for (clientlist = clientlisthead ; clientlist != NULL ; clientlist = clientlist->tail) {
                if (fd == clientlist->fd) {
                    break;
                }
            }
            if (clientlist != NULL) {
                unsigned char data[] = { 0x23 };
                write (fd, data, sizeof (data));
                offset += packagesize;
                printf ("client:%d is not login, in %s, at %d\n", fd,  __FILE__, __LINE__);
                continue;
            }
            for (clientlist = clientlisthead ; clientlist != NULL ; clientlist = clientlist->tail) {
                if (readbuf[offset+16] == clientlist->ip[0] && readbuf[offset+17] == clientlist->ip[1] && readbuf[offset+18] == clientlist->ip[2] && readbuf[offset+19] == clientlist->ip[3]) {
                    break;
                }
            }
            if (clientlist != NULL) {
                offset += packagesize;
                printf ("target client %d.%d.%d.%d not found, in %s, at %d\n", readbuf[offset+16], readbuf[offset+17], readbuf[offset+18], readbuf[offset+19],  __FILE__, __LINE__);
                continue;
            }
            unsigned char* package = (unsigned char*) malloc (packagesize * sizeof (unsigned char));
            if (package == NULL) {
                offset += packagesize;
                printf ("malloc fail, in %s, at %d\n",  __FILE__, __LINE__);
                continue;
            }
            memcpy (package, readbuf + offset, packagesize);
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
            if (clientlist->packagelisthead == NULL) {
                clientlist->packagelisthead = packagelist;
                clientlist->packagelisttail = clientlist->packagelisthead;
            } else {
                clientlist->packagelisttail->tail = packagelist;
                clientlist->packagelisttail = clientlist->packagelisttail->tail;
            }
            clientlist->totalsize += packagelist->size;
            if (clientlist->canwrite) { // 当前socket可写
                writenode (clientlist);
            }
            offset += packagesize;
        } else if (readbuf[offset] == 0x10) { // 绑定数据包
            if (memcmp (readbuf + offset + 1, password, 32)) { // 绑定密码错误
                unsigned char data[] = { 0x20 };
                write (fd, data, sizeof (data));
                offset += 37; // 绑定包固定长度为37
                printf ("password check fail, in %s, at %d\n",  __FILE__, __LINE__);
                continue;
            }
            unsigned char ip[4];
            memcpy(ip, readbuf+offset+33, 4);
            int canuse = 1;
            for (struct CLIENTLIST* clientlist = clientlisthead ; clientlist != NULL ; clientlist = clientlist->tail) {
                if (readbuf[offset+33] == clientlist->ip[0] && readbuf[offset+34] == clientlist->ip[1] && readbuf[offset+35] == clientlist->ip[2] && readbuf[offset+36] == clientlist->ip[3]) {
                    canuse = 0;
                    break;
                }
            }
            if (!canuse) {
                unsigned char data[] = { 0x21 };
                write (fd, data, sizeof (data));
                offset += 37; // 绑定包固定长度为37
                printf ("ip %d.%d.%d.%d is exist, in %s, at %d\n", ip[0], ip[1], ip[2], ip[3],  __FILE__, __LINE__);
                continue;
            }
            struct CLIENTLIST* clientlist = (struct CLIENTLIST*) malloc (sizeof (struct CLIENTLIST));
            if (clientlist == NULL) {
                offset += 37; // 绑定包固定长度为37
                printf ("malloc fail, in %s, at %d\n",  __FILE__, __LINE__);
                continue;
            }
            clientlist->fd = fd;
            memcpy (clientlist->ip, readbuf+offset+33, 4);
            clientlist->canwrite = 1;
            clientlist->packagelisthead = NULL;
            clientlist->totalsize = 0;
            clientlist->head = clientlisttail;
            clientlist->tail = NULL;
            clientlisttail->tail = clientlist;
            clientlisttail = clientlisttail->tail;
            offset += 37; // 绑定包固定长度为37
            printf ("add client success, client ip is %d.%d.%d.%d, in %s, at %d\n", ip[0], ip[1], ip[2], ip[3],  __FILE__, __LINE__);
        } else if (readbuf[offset] == 0x11) { // hello包
            offset += 1; // hello包固定长度为1
        }
    }
}

int main () {
    tunfd = tun_alloc (); // 这里使用static是因为这个变量是不会被释放的，因此将这个数据放到数据段。
    if (tunfd < 0) {
        printf ("alloc tun fail, in %s, at %d\n",  __FILE__, __LINE__);
        return -1;
    }
    serverfd = create_socketfd ();
    if (serverfd < 0) {
        printf ("create socket fd fail, in %s, at %d\n",  __FILE__, __LINE__);
        return -2;
    }
    epollfd = epoll_create (MAX_EVENT);
    if (epollfd < 0) {
        printf ("create epoll fd fail, in %s, at %d\n",  __FILE__, __LINE__);
        return -3;
    }
    if (addtoepoll (serverfd)) {
        printf ("serverfd addtoepoll fail, in %s, at %d\n",  __FILE__, __LINE__);
        return -4;
    }
    if (addtoepoll (tunfd)) {
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
                printf ("connect lose, in %s, at %d\n",  __FILE__, __LINE__);
                removeclient (fd);
                continue;
            } else if (fd == serverfd) {
                printf ("new socket, in %s, at %d\n",  __FILE__, __LINE__);
                struct sockaddr_in sin;
                socklen_t in_addr_len = sizeof (struct sockaddr_in);
                int newfd = accept (serverfd, (struct sockaddr*)&sin, &in_addr_len);
                if (newfd < 0) {
                    printf ("accept a new fd fail, in %s, at %d\n",  __FILE__, __LINE__);
                    continue;
                }
                int flags = fcntl (newfd, F_GETFL, 0);
                if (flags < 0) {
                    printf ("get flags fail, in %s, at %d\n", __FILE__, __LINE__);
                    continue;
                }
                if(fcntl (newfd, F_SETFL, flags | O_NONBLOCK) < 0) {
                    printf ("set flags fail, in %s, at %d\n", __FILE__, __LINE__);
                    continue;
                }
                if (addtoepoll (newfd)) {
                    close (newfd);
                    printf ("add to epoll fail, in %s, at %d\n",  __FILE__, __LINE__);
                    continue;
                }
            } else if (events & EPOLLIN) { // 数据可读
                static unsigned char readbuf[MAXDATASIZE]; // 这里使用static关键词是为了将数据存储与数据段，减小对栈空间的压力。
                int len = read (fd, readbuf, sizeof (readbuf));
                if (len <= 0) {
                    printf ("read fail, len: %d, in %s, at %d\n", len,  __FILE__, __LINE__);
                    removeclient (fd);
                    continue;
                }
                readdata (fd, readbuf, len);
            } else if (events & EPOLLOUT) { // 数据可写
                struct CLIENTLIST* clientlist;
                for (clientlist = clientlisthead ; clientlist != NULL ; clientlist = clientlist->tail) {
                    if (fd == clientlist->fd) {
                        break;
                    }
                }
                if (clientlist == NULL) { // 客户端列表没有找到
                    continue;
                }
                if (clientlist->packagelisthead == NULL) {
                    clientlist->canwrite = 1;
                }
                writenode (clientlist);
            } else {
                printf ("receive new event 0x%08x, in %s, at %d\n", events,  __FILE__, __LINE__);
            }
        }
    }
    return 0;
}
