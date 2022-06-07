#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <string.h>
#include <errno.h>
// 包入tun相关的头部
#include <net/if.h>
#include <linux/if_tun.h>
// 包入网络相关的头部
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
// 包入路由相关的头部
#include <net/route.h>
// 包入openssl的头部
#include <openssl/ssl.h>
// 包入json解析头部
#include "yyjson.h"

#define MAXDATASIZE       2*1024*1024
#define MAX_EVENT         1024
#define MAX_CONNECT       1024
#define MTU_SIZE          1500

const char PAGE404[] =  "HTTP/1.1 404 Not Found\r\nServer: nginx/1.14.2\r\nDate: %a, %d %b %Y %H:%M:%S GMT\r\n" \
                        "Content-Type: text/html\r\nContent-Length: 169\r\nConnection: keep-alive\r\n\r\n" \
                        "<html>\r\n<head><title>404 Not Found</title></head>\r\n<body bgcolor=\"white\">\r\n<center><h1>404 Not Found</h1></center>\r\n" \
                        "<hr><center>nginx/1.14.2</center>\r\n</body>\r\n</html>\r\n";
const char PAGE400[] =  "HTTP/1.1 400 Bad Request\r\nServer: nginx/1.14.2\r\nDate: %a, %d %b %Y %H:%M:%S GMT\r\n" \
                        "Content-Type: text/html\r\nContent-Length: 173\r\nConnection: close\r\n\r\n" \
                        "<html>\r\n<head><title>400 Bad Request</title></head>\r\n<body bgcolor=\"white\">\r\n<center><h1>400 Bad Request</h1></center>\r\n" \
                        "<hr><center>nginx/1.14.2</center>\r\n</body>\r\n</html>\r\n";
const char PAGE101[] =  "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";

struct PACKAGELIST {
    unsigned char data[MTU_SIZE + 18];
    unsigned int size;
    struct PACKAGELIST *tail;
};
struct PACKAGELIST *remainpackagelisthead = NULL;
struct CLIENTLIST {
    struct FDCLIENT *fdclient; // 与自己相关联的fdclient对象
    unsigned char mac[6]; // 该端口的源mac地址
    struct PACKAGELIST *packagelisthead; // 发给自己这个端口的数据包列表头部
    struct PACKAGELIST *packagelisttail; // 发给自己这个端口的数据包列表尾部
    unsigned char remainpackage[MTU_SIZE + 18]; // 自己接收到的数据出现数据不全，将不全的数据存在这里，等待新的数据将其补全
    unsigned int remainsize; // 不全的数据大小
    unsigned char canwrite;
    struct CLIENTLIST *hashhead; // 从哈希表中寻找上一个clientlist
    struct CLIENTLIST *hashtail; // 从哈希表中寻找下一个clientlist
    struct CLIENTLIST *head; // 从remainclientlist中寻找下一个可用的clientlist
    struct CLIENTLIST *tail; // 从remainclientlist中寻找下一个可用的clientlist
    struct CLIENTLIST *writetail; // 用于存储在readdata中发现有写入过程的node
};
struct CLIENTLIST *clientlisthead = NULL;
struct CLIENTLIST *remainclientlisthead = NULL;
struct CLIENTLIST *machashlist[0x10000]; // mac地址的hash表，用于快速找到对应的mac
struct CLIENTLIST *tapclient;
struct FDCLIENT {
    int fd;
    SSL *tls;
    int tlsconnected;
    int watch;
    struct CLIENTLIST *client;
    struct FDCLIENT *tail; // 从remainclientlist中寻找下一个可用的clientlist
};
struct FDCLIENT *remainfdclienthead = NULL;
struct FDCLIENT *fdserver;
int epollfd;
SSL_CTX *ctx;
unsigned char readbuf[MAXDATASIZE];

struct KEYS {
    unsigned char key[33];
    struct KEYS *tail;
};
struct ROUTERS {
    unsigned char dstip[4];
    unsigned char dstmask[4];
    unsigned char gateway[4];
    struct ROUTERS *tail;
};
struct CONFIG {
    unsigned short bindport;
    bool tcpkeepalive;
    unsigned char tcpkeepidle;
    unsigned char tcpkeepintvl;
    unsigned char tcpkeepcnt;
    bool ssl;
    unsigned char crtpath[256];
    unsigned char keypath[256];
    unsigned char ip[4];
    unsigned char mask[4];
    unsigned char httppath[256];
    unsigned char tapname[16];
    struct KEYS *keys;
    struct ROUTERS *routers;
};
struct CONFIG c;

int setnonblocking (int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        printf("get flags fail, fd:%d, in %s, at %d\n", fd, __FILE__, __LINE__);
        return -1;
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        printf("set flags fail, fd:%d, in %s, at %d\n", fd, __FILE__, __LINE__);
        return -2;
    }
    return 0;
}

int addtoepoll (struct FDCLIENT *fdclient) {
    struct epoll_event ev;
    ev.data.ptr = fdclient;
    ev.events = EPOLLIN | EPOLLERR | EPOLLHUP | EPOLLRDHUP; // 水平触发，保证所有数据都能读到
    return epoll_ctl(epollfd, EPOLL_CTL_ADD, fdclient->fd, &ev);
}

int modepoll (struct FDCLIENT *fdclient, int flags) {
    struct epoll_event ev;
    ev.data.ptr = fdclient;
    ev.events = EPOLLIN | EPOLLERR | EPOLLHUP | EPOLLRDHUP | flags; // 水平触发，保证所有数据都能读到
    return epoll_ctl(epollfd, EPOLL_CTL_MOD, fdclient->fd, &ev);
}

int tap_alloc () {
    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) {
        printf("open tun node fail, in %s, at %d\n", __FILE__, __LINE__);
        return -1;
    }
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    strcpy(ifr.ifr_name, c.tapname);
    if (ioctl(fd, TUNSETIFF, (void*) &ifr) < 0) {
        printf("ioctl tun node fail, in %s, at %d\n", __FILE__, __LINE__);
        close(fd);
        return -2;
    }
    printf("create tap device success, in %s, at %d\n", __FILE__, __LINE__);
    int socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (ioctl(socket_fd, SIOCGIFFLAGS, (void *) &ifr) < 0) {
        printf("ioctl SIOCGIFFLAGS fail, in %s, at %d\n", __FILE__, __LINE__);
        close(socket_fd);
        close(fd);
        return -3;
    }
    ifr.ifr_flags |= IFF_UP;
    if (ioctl(socket_fd, SIOCSIFFLAGS, &ifr) < 0) {
        printf("up tap device fail, in %s, at %d\n", __FILE__, __LINE__);
        close(socket_fd);
        close(fd);
        return -4;
    }
    printf("up tap device success, in %s, at %d\n", __FILE__, __LINE__);
    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(struct sockaddr_in));
	sin.sin_family = AF_INET;
    memcpy(&sin.sin_addr, c.ip, 4);
    memcpy(&ifr.ifr_addr, &sin, sizeof(struct sockaddr));
	if (ioctl(socket_fd, SIOCSIFADDR, &ifr) < 0) {
        printf("set ip addr for tap device fail, in %s, at %d\n", __FILE__, __LINE__);
        close(socket_fd);
        close(fd);
        return -5;
    }
    printf("set ip addr for tap device to %s success, in %s, at %d\n", c.ip, __FILE__, __LINE__);
    memset(&sin, 0, sizeof(struct sockaddr_in));
	sin.sin_family = AF_INET;
    memcpy(&sin.sin_addr, c.mask, 4);
    memcpy(&ifr.ifr_netmask, &sin, sizeof(struct sockaddr));
    if (ioctl(socket_fd, SIOCSIFNETMASK, &ifr) < 0) {
        printf("set netmask for tap device fail, in %s, at %d\n", __FILE__, __LINE__);
        close(socket_fd);
        close(fd);
        return -6;
    }
    printf("set netmask for tap device to %s success, in %s, at %d\n", c.mask, __FILE__, __LINE__);
    struct rtentry rt;
    struct ROUTERS *routers = c.routers;
    while (routers != NULL) {
        memset(&rt, 0, sizeof(struct rtentry));
        memset(&sin, 0, sizeof(struct sockaddr_in));
        sin.sin_family = AF_INET;
        memcpy(&sin.sin_addr, routers->dstip, 4);
        memcpy(&rt.rt_dst, &sin, sizeof(struct sockaddr_in));
        memset(&sin, 0, sizeof(struct sockaddr_in));
        sin.sin_family = AF_INET;
        memcpy(&sin.sin_addr, routers->dstmask, 4);
        memcpy(&rt.rt_genmask, &sin, sizeof(struct sockaddr_in));
        memset(&sin, 0, sizeof(struct sockaddr_in));
        sin.sin_family = AF_INET;
        memcpy(&sin.sin_addr, routers->gateway, 4);
        memcpy(&rt.rt_gateway, &sin, sizeof(struct sockaddr_in));
        rt.rt_flags = RTF_GATEWAY;
        if (ioctl(socket_fd, SIOCADDRT, &rt) < 0) {
            printf("set static route fail, in %s, at %d\n", __FILE__, __LINE__);
            close(socket_fd);
            close(fd);
            return -7;
        }
        printf("add static route %s mask %s via %s success, in %s, at %d\n", routers->dstip, routers->dstmask, routers->gateway, __FILE__, __LINE__);
        struct ROUTERS *r = routers;
        routers = routers->tail;
        free(r);
    }
    close(socket_fd);
    if (setnonblocking(fd) < 0) {
        printf("set nonblocking fail, fd:%d, in %s, at %d\n", fd, __FILE__, __LINE__);
        close(fd);
        return -8;
    }
    printf("tap device name is %s, tapfd %d, in %s, at %d\n", ifr.ifr_name, fd, __FILE__, __LINE__);
    if (remainclientlisthead) {
        tapclient = remainclientlisthead;
        remainclientlisthead = remainclientlisthead->tail;
    } else {
        tapclient = (struct CLIENTLIST*) malloc(sizeof(struct CLIENTLIST));
        if (tapclient == NULL) {
            printf("malloc fail, in %s, at %d\n",  __FILE__, __LINE__);
            close(fd);
            return -9;
        }
    }
    memset(tapclient->mac, 0, 6);
    tapclient->packagelisthead = NULL;
    tapclient->remainsize = 0;
    tapclient->canwrite = 1;
    tapclient->hashhead = NULL;
    tapclient->hashtail = NULL;
    tapclient->head = NULL;
    if (clientlisthead) {
        clientlisthead->head = tapclient;
    }
    tapclient->tail = clientlisthead;
    clientlisthead = tapclient;
    struct FDCLIENT* fdclient;
    if (remainfdclienthead) { // 有存货，直接拿出来用
        fdclient = remainfdclienthead;
        remainfdclienthead = remainfdclienthead->tail;
    } else { // 没有存货，malloc一个
        fdclient = (struct FDCLIENT*) malloc(sizeof(struct FDCLIENT));
        if (fdclient == NULL) {
            printf("malloc fail, in %s, at %d\n",  __FILE__, __LINE__);
            clientlisthead = clientlisthead->tail;
            tapclient->tail = remainclientlisthead;
            remainclientlisthead = tapclient;
            close(fd);
            return -10;
        }
    }
    tapclient->fdclient = fdclient;
    fdclient->fd = fd;
    fdclient->tls = NULL;
    fdclient->tlsconnected = 0;
    fdclient->watch = 0;
    fdclient->client = tapclient;
    if (addtoepoll(fdclient)) {
        printf("tapfd add to epoll fail, in %s, at %d\n",  __FILE__, __LINE__);
        fdclient->tail = remainfdclienthead;
        remainfdclienthead = fdclient;
        clientlisthead = clientlisthead->tail;
        tapclient->tail = remainclientlisthead;
        remainclientlisthead = tapclient;
        close(fd);
        return -11;
    }
    fdclient->watch = 1;
    return 0;
}

int create_socketfd () {
    struct sockaddr_in sin;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        printf("run socket function is fail, fd:%d, in %s, at %d\n", fd, __FILE__, __LINE__);
        return -1;
    }
    memset(&sin, 0, sizeof(struct sockaddr_in));
    sin.sin_family = AF_INET; // ipv4
    sin.sin_addr.s_addr = INADDR_ANY; // 本机任意ip
    sin.sin_port = htons(c.bindport);
    if (bind(fd, (struct sockaddr*)&sin, sizeof(sin)) < 0) {
        printf("bind port %d fail, fd:%d, in %s, at %d\n", c.bindport, fd, __FILE__, __LINE__);
        close(fd);
        return -2;
    }
    if (listen(fd, MAX_CONNECT) < 0) {
        printf("listen port %d fail, fd:%d, in %s, at %d\n", c.bindport, fd, __FILE__, __LINE__);
        close(fd);
        return -3;
    }
    if (remainfdclienthead) { // 有存货，直接拿出来用
        fdserver = remainfdclienthead;
        remainfdclienthead = remainfdclienthead->tail;
    } else { // 没有存货，malloc一个
        fdserver = (struct FDCLIENT*) malloc(sizeof(struct FDCLIENT));
        if (fdserver == NULL) {
            printf("malloc fail, fd:%d, in %s, at %d\n", fd,  __FILE__, __LINE__);
            close(fd);
            return -5;
        }
    }
    fdserver->fd = fd;
    fdserver->watch = 0;
    fdserver->client = NULL;
    if (addtoepoll(fdserver)) {
        printf("serverfd add to epoll fail, fd:%d, in %s, at %d\n", fd,  __FILE__, __LINE__);
        fdserver->tail = remainfdclienthead;
        remainfdclienthead = fdserver;
        close(fd);
        return -6;
    }
    fdserver->watch = 1;
    return 0;
}

int addclient (int serverfd) {
    struct sockaddr_in sin;
    socklen_t in_addr_len = sizeof(struct sockaddr_in);
    int fd = accept(serverfd, (struct sockaddr*)&sin, &in_addr_len);
    if (fd < 0) {
        printf("accept a new fd fail, fd:%d, in %s, at %d\n", fd,  __FILE__, __LINE__);
        return -1;
    }
    printf("new socket:%d, in %s, at %d\n", fd,  __FILE__, __LINE__);
    if (setnonblocking(fd) < 0) { // 设置为非阻塞IO
        printf("set nonblocking fail, fd:%d, in %s, at %d\n", fd, __FILE__, __LINE__);
        close(fd);
        return -2;
    }
    unsigned int socksval = 1;
    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (unsigned char*)&socksval, sizeof(socksval))) { // 关闭Nagle协议
        printf("close Nagle protocol fail, fd:%d, in %s, at %d\n", fd, __FILE__, __LINE__);
        close(fd);
        return -3;
    }
    socksval = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &socksval, sizeof(socksval))) {
        printf("set socket reuseaddr fail, fd:%d, in %s, at %d\n", fd, __FILE__, __LINE__);
        close(fd);
        return -4;
    }
    socksval = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &socksval, sizeof(socksval))) {
        printf("set socket reuseport fail, fd:%d, in %s, at %d\n", fd, __FILE__, __LINE__);
        close(fd);
        return -5;
    }
    if (c.tcpkeepalive) {
        socksval = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (unsigned char*)&socksval, sizeof(socksval))) { // 启动tcp心跳包
            printf("set socket keepalive fail, fd:%d, in %s, at %d\n", fd, __FILE__, __LINE__);
            close(fd);
            return -6;
        }
        socksval = c.tcpkeepidle;
        if (setsockopt(fd, SOL_TCP, TCP_KEEPIDLE, (unsigned char*)&socksval, sizeof(socksval))) { // 设置tcp心跳包参数
            printf("set socket keepidle fail, fd:%d, in %s, at %d\n", fd, __FILE__, __LINE__);
            close(fd);
            return -7;
        }
        socksval = c.tcpkeepintvl;
        if (setsockopt(fd, SOL_TCP, TCP_KEEPINTVL, (unsigned char*)&socksval, sizeof(socksval))) { // 设置tcp心跳包参数
            printf("set socket keepintvl fail, fd:%d, in %s, at %d\n", fd, __FILE__, __LINE__);
            close(fd);
            return -8;
        }
        socksval = c.tcpkeepcnt;
        if (setsockopt(fd, SOL_TCP, TCP_KEEPCNT, (unsigned char*)&socksval, sizeof(socksval))) { // 设置tcp心跳包参数
            printf("set socket keepcnt fail, fd:%d, in %s, at %d\n", fd, __FILE__, __LINE__);
            close(fd);
            return -9;
        }
    }
    // 修改发送缓冲区大小
    socklen_t socksval_len = sizeof(socksval);
    if (getsockopt(fd, SOL_SOCKET, SO_SNDBUF, (unsigned char*)&socksval, &socksval_len)) {
        printf("get send buffer fail, fd:%d, in %s, at %d\n", fd,  __FILE__, __LINE__);
        close(fd);
        return -10;
    }
    printf("old send buffer is %d, socksval_len:%d, fd:%d, in %s, at %d\n", socksval, socksval_len, fd,  __FILE__, __LINE__);
    socksval = MAXDATASIZE;
    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (unsigned char*)&socksval, sizeof (socksval))) {
        printf("set send buffer fail, fd:%d, in %s, at %d\n", fd,  __FILE__, __LINE__);
        close(fd);
        return -11;
    }
    socksval_len = sizeof(socksval);
    if (getsockopt(fd, SOL_SOCKET, SO_SNDBUF, (unsigned char*)&socksval, &socksval_len)) {
        printf("get send buffer fail, fd:%d, in %s, at %d\n", fd,  __FILE__, __LINE__);
        close(fd);
        return -12;
    }
    printf("new send buffer is %d, socksval_len:%d, fd:%d, in %s, at %d\n", socksval, socksval_len, fd,  __FILE__, __LINE__);
    // 修改接收缓冲区大小
    socksval_len = sizeof(socksval);
    if (getsockopt(fd, SOL_SOCKET, SO_RCVBUF, (unsigned char*)&socksval, &socksval_len)) {
        printf("get receive buffer fail, fd:%d, in %s, at %d\n", fd,  __FILE__, __LINE__);
        close(fd);
        return -13;
    }
    printf("old receive buffer is %d, socksval_len:%d, fd:%d, in %s, at %d\n", socksval, socksval_len, fd,  __FILE__, __LINE__);
    socksval = MAXDATASIZE;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (char*)&socksval, sizeof(socksval))) {
        printf("set receive buffer fail, fd:%d, in %s, at %d\n", fd,  __FILE__, __LINE__);
        close(fd);
        return -14;
    }
    socksval_len = sizeof(socksval);
    if (getsockopt(fd, SOL_SOCKET, SO_RCVBUF, (unsigned char*)&socksval, &socksval_len)) {
        printf("get receive buffer fail, fd:%d, in %s, at %d\n", fd,  __FILE__, __LINE__);
        close(fd);
        return -15;
    }
    printf("new receive buffer is %d, socksval_len:%d, fd:%d, in %s, at %d\n", socksval, socksval_len, fd,  __FILE__, __LINE__);
    struct FDCLIENT *fdclient;
    if (remainfdclienthead) { // 有存货，直接拿出来用
        fdclient = remainfdclienthead;
        remainfdclienthead = remainfdclienthead->tail;
    } else { // 没有存货，malloc一个
        fdclient = (struct FDCLIENT*) malloc(sizeof(struct FDCLIENT));
        if (fdclient == NULL) {
            printf("malloc new fdclient object fail, fd:%d, in %s, at %d\n", fd,  __FILE__, __LINE__);
            close(fd);
            return -16;
        }
    }
    fdclient->fd = fd;
    fdclient->watch = 0;
    fdclient->client = NULL;
    if (c.ssl) {
        SSL *tls = SSL_new(ctx);
        if (tls == NULL) {
            printf("SSL new fail, fd:%d, in %s, at %d\n", fd,  __FILE__, __LINE__);
            fdclient->tail = remainfdclienthead;
            remainfdclienthead = fdclient;
            close(fd);
            return -17;
        }
        if (!SSL_set_fd(tls, fd)) {
            printf("SSL set fd fail, fd:%d, in %s, at %d\n", fd,  __FILE__, __LINE__);
            fdclient->tail = remainfdclienthead;
            remainfdclienthead = fdclient;
            SSL_shutdown(tls);
            SSL_free(tls);
            close(fd);
            return -18;
        }
        fdclient->tls = tls;
        int r_code = SSL_accept(tls);
        if (r_code < 0) {
            int errcode = SSL_get_error(tls, r_code);
            if (errcode != SSL_ERROR_WANT_READ) {
                perror("tls connect error");
                printf("errno:%d, errcode:%d, in %s, at %d\n", errno, errcode, __FILE__, __LINE__);
                fdclient->tail = remainfdclienthead;
                remainfdclienthead = fdclient;
                SSL_shutdown(tls);
                SSL_free(tls);
                close(fd);
                return -19;
            }
            fdclient->tlsconnected = 0;
        } else {
            fdclient->tlsconnected = 1;
        }
    } else {
        fdclient->tls = NULL;
        fdclient->tlsconnected = 0;
    }
    if (addtoepoll(fdclient)) {
        printf("add to epoll fail, fd:%d, in %s, at %d\n", fd,  __FILE__, __LINE__);
        fdclient->tail = remainfdclienthead;
        remainfdclienthead = fdclient;
        if (fdclient->tls) {
            SSL_shutdown(fdclient->tls);
            SSL_free(fdclient->tls);
        }
        close(fd);
        return -20;
    }
    fdclient->watch = 1;
    return 0;
}

int removeclient (struct FDCLIENT *fdclient) {
    if (!fdclient->watch) {
        return 0;
    }
    if (epoll_ctl(epollfd, EPOLL_CTL_DEL, fdclient->fd, NULL)) {
        printf("errno: %d, fd:%d, in %s, at %d\n", errno, fdclient->fd,  __FILE__, __LINE__);
        perror("EPOLL CTL DEL fail");
        return -1;
    }
    fdclient->watch = 0;
    if (fdclient->tls) {
        SSL_shutdown(fdclient->tls);
        SSL_free(fdclient->tls);
    }
    struct CLIENTLIST *client = fdclient->client;
    close(fdclient->fd);
    if (client) { // 已经注册成功
        if (client->mac[0] != 0x00 || client->mac[1] != 0x00 || client->mac[2] != 0x00 || client->mac[3] != 0x00 || client->mac[4] != 0x00 || client->mac[5] != 0x00) { // 已经学习完毕
            if (client->hashhead) {
                client->hashhead->hashtail = client->hashtail;
            } else {
                machashlist[256 * client->mac[4] + client->mac[5]] = client->hashtail;
            }
            if (client->hashtail) {
                client->hashtail->hashhead = client->hashhead;
            }
        }
        struct PACKAGELIST *package = client->packagelisthead;
        while (package) {
            struct PACKAGELIST *tmppackage = package;
            package = package->tail;
            tmppackage->tail = remainpackagelisthead;
            remainpackagelisthead = tmppackage;
        }
        if (client->head) {
            client->head->tail = client->tail;
        } else {
            clientlisthead = client->tail;
        }
        if (client->tail) {
            client->tail->head = client->head;
        }
        client->tail = remainclientlisthead;
        remainclientlisthead = client;
        printf("host %02x:%02x:%02x:%02x:%02x:%02x disconnect, in %s, at %d\n", client->mac[0], client->mac[1], client->mac[2], client->mac[3], client->mac[4], client->mac[5],  __FILE__, __LINE__);
    }
    fdclient->tail = remainfdclienthead;
    remainfdclienthead = fdclient;
    if (client == tapclient) { // 基本不可能情况
        printf("errno: %d, exit 0, in %s, at %d\n", errno, __FILE__, __LINE__);
        perror("tap driver lose");
        exit(0);
    }
    return 0;
}

int writenode (struct CLIENTLIST *writeclient) {
    for (struct CLIENTLIST *client = writeclient ; client != NULL ; client = client->writetail) {
        struct PACKAGELIST *package = client->packagelisthead;
        client->packagelisthead = NULL;
        while (package) {
            ssize_t len;
            if (client->fdclient->tls) {
                len = SSL_write(client->fdclient->tls, package->data, package->size);
            } else {
                len = write(client->fdclient->fd, package->data, package->size);
            }
            if (len < 0) {
                client->packagelisthead = package;
                if (errno != EAGAIN) {
                    printf("errno:%d, in %s, at %d\n", errno,  __FILE__, __LINE__);
                    if (client == tapclient) {
                        perror("tap write error");
                    } else {
                        perror("socket write error");
                    }
                    removeclient(client->fdclient);
                    break;
                }
                if (client->canwrite) { // 之前缓冲区是可以写入的，现在不行了
                    if (modepoll(client->fdclient, EPOLLOUT)) { // 监听可写事件
                        printf("modepoll fail, in %s, at %d\n",  __FILE__, __LINE__);
                        removeclient(client->fdclient);
                        break;
                    }
                    client->canwrite = 0;
                }
                break;
            }
            if (len < package->size) { // 缓冲区不足，已无法继续写入数据。
                unsigned int size = package->size - len;
                memcpy(package->data, package->data + len, size);
                package->size = size;
                client->packagelisthead = package;
                if (client->canwrite) { // 之前缓冲区是可以写入的，现在不行了
                    if (modepoll(client->fdclient, EPOLLOUT)) { // 监听可写事件
                        printf("modepoll fail, in %s, at %d\n",  __FILE__, __LINE__);
                        removeclient(client->fdclient);
                        break;
                    }
                    client->canwrite = 0;
                }
                break;
            }
            if (client->canwrite == 0) { // 缓冲区尚有空间，并且之前已经提示不足
                if (modepoll(client->fdclient, 0)) { // 取消监听可写事件
                    printf("modepoll fail, in %s, at %d\n",  __FILE__, __LINE__);
                    client->packagelisthead = package;
                    removeclient(client->fdclient);
                    break;
                }
                client->canwrite = 1;
            }
            struct PACKAGELIST *tmppackage = package;
            package = package->tail;
            tmppackage->tail = remainpackagelisthead;
            remainpackagelisthead = tmppackage;
        }
    }
    return 0;
}

struct CLIENTLIST* braodcastdata (struct CLIENTLIST *sourceclient, unsigned char *buff, int32_t packagesize) {
    struct CLIENTLIST *writeclient = NULL;
    for (struct CLIENTLIST *targetclient = clientlisthead ; targetclient != NULL ; targetclient = targetclient->tail) {
        if (targetclient == sourceclient) {
            continue;
        }
        struct PACKAGELIST *package;
        if (remainpackagelisthead) { // 全局数据包回收站不为空
            package = remainpackagelisthead;
            remainpackagelisthead = remainpackagelisthead->tail;
        } else {
            package = (struct PACKAGELIST*) malloc(sizeof(struct PACKAGELIST));
            if (package == NULL) {
                printf("malloc fail, in %s, at %d\n",  __FILE__, __LINE__);
                continue;
            }
        }
        if (targetclient == tapclient) {
            memcpy(package->data, buff + 2, packagesize - 2);
            package->size = packagesize - 2;
        } else {
            memcpy(package->data, buff, packagesize);
            package->size = packagesize;
        }
        package->tail = NULL;
        if (targetclient->packagelisthead == NULL) {
            targetclient->packagelisthead = package;
            targetclient->packagelisttail = targetclient->packagelisthead;
        } else {
            targetclient->packagelisttail->tail = package;
            targetclient->packagelisttail = targetclient->packagelisttail->tail;
        }
        if (targetclient->canwrite) {
            targetclient->writetail = writeclient;
            writeclient = targetclient;
        }
    }
    return writeclient;
}

int checkkeys (char *key) {
    struct KEYS *keys = c.keys;
    while (keys != NULL) {
        if (!strcmp(keys->key, key)) {
            return 1;
        }
        keys = keys->tail;
    }
    return 0;
}

int readdata (struct FDCLIENT *fdclient) {
    unsigned char *readbuff = NULL; // 这里是用于存储全部的需要写入的数据buf，
    unsigned int maxtotalsize = 0;
    struct CLIENTLIST *sourceclient = fdclient->client;
    ssize_t len;
    if (sourceclient == tapclient) { // tap驱动，原始数据，需要自己额外添加数据包长度。
        len = read(fdclient->fd, readbuf + 2, MAXDATASIZE); // 这里最大只可能是1518
        if (len < 0) {
            if (errno != EAGAIN) {
                printf("errno:%d, in %s, at %d\n", errno,  __FILE__, __LINE__);
                perror("tap read error");
                removeclient(fdclient);
            }
            return -1;
        }
        readbuf[0] = len >> 8;
        readbuf[1] = len & 0xff;
        len += 2;
    } else { // 网络套接字。
        if (fdclient->tls) {
            len = SSL_read(fdclient->tls, readbuf, MAXDATASIZE);
        } else {
            len = read(fdclient->fd, readbuf, MAXDATASIZE);
        }
        if (len < 0) {
            if (errno != EAGAIN) {
                printf("errno:%d, in %s, at %d\n", errno,  __FILE__, __LINE__);
                perror("socket read error");
                removeclient(fdclient);
            }
            return -2;
        }
    }
    readbuf[len] = '\0';
    if (sourceclient == NULL) { // 用户没有找到
        if (remainclientlisthead) {
            sourceclient = remainclientlisthead;
            remainclientlisthead = remainclientlisthead->tail;
        } else {
            sourceclient = (struct CLIENTLIST*) malloc(sizeof(struct CLIENTLIST));
            if (sourceclient == NULL) {
                printf("malloc fail, in %s, at %d\n",  __FILE__, __LINE__);
                removeclient(fdclient);
                return -3;
            }
        }
        memset(sourceclient->mac, 0, 6);
        sourceclient->fdclient = fdclient;
        sourceclient->remainsize = 0;
        sourceclient->canwrite = 1;
        sourceclient->tail = NULL;
        struct PACKAGELIST *package;
        if (remainpackagelisthead) { // 全局数据包回收站不为空
            package = remainpackagelisthead;
            remainpackagelisthead = remainpackagelisthead->tail;
        } else {
            package = (struct PACKAGELIST*) malloc(sizeof(struct PACKAGELIST));
            if (package == NULL) {
                printf("malloc fail, in %s, at %d\n",  __FILE__, __LINE__);
                return -4;
            }
        }
        package->tail = NULL;
        sourceclient->packagelisthead = package;
        unsigned char *headend = strstr(readbuf, "\r\n\r\n");
        unsigned char httppath[256];
        unsigned char httpprot[16];
        if (sscanf(readbuf, "GET %s %s\r\n", httppath, httpprot) != 2 || strcmp(httpprot, "HTTP/1.1") || headend == NULL) {
            time_t now;
            time(&now);
            int len = strftime(package->data, MTU_SIZE+18, PAGE400, gmtime(&now));
            package->size = len;
            writenode(sourceclient);
            removeclient(fdclient);
            return -5;
        }
        *headend = '\0'; // 给http头部结尾添加字符串结束符，不解析body。
        unsigned char *key = strstr(readbuf, "Authorization: ");
        if (key != NULL) {
            key = key + 15;
            unsigned char *keyend = strchr(key, '\r');
            *keyend = '\0';
        }
        if (key == NULL || !strcmp(httppath, c.httppath) || !checkkeys(key)) {
            time_t now;
            time(&now);
            int len = strftime(package->data, MTU_SIZE+18, PAGE404, gmtime(&now));
            package->size = len;
            writenode(sourceclient);
            removeclient(fdclient);
            return -6;
        }
        memcpy(package->data, PAGE101, sizeof(PAGE101)-1);
        package->size = sizeof(PAGE101)-1;
        writenode(sourceclient);
        if (clientlisthead) {
            clientlisthead->head = sourceclient;
        }
        sourceclient->head = NULL;
        sourceclient->tail = clientlisthead;
        clientlisthead = sourceclient;
        fdclient->client = sourceclient;
        printf("add client success, fd:%d, in %s, at %d\n", sourceclient->fdclient->fd,  __FILE__, __LINE__);
        return 0;
    }
    unsigned int offset = 0;
    unsigned int totalsize;
    unsigned char *buff;
    if (sourceclient->remainsize > 0) {
        totalsize = sourceclient->remainsize + len;
        if (totalsize > maxtotalsize) {
            if (readbuff) {
                free(readbuff);
            }
            readbuff = (unsigned char*) malloc(totalsize * sizeof(unsigned char));
            if (readbuff == NULL) {
                printf("malloc fail, in %s, at %d\n",  __FILE__, __LINE__);
                return -9;
            }
            maxtotalsize = totalsize;
        }
        memcpy(readbuff, sourceclient->remainpackage, sourceclient->remainsize);
        memcpy(readbuff + sourceclient->remainsize, readbuf, len);
        sourceclient->remainsize = 0;
        buff = readbuff;
    } else {
        totalsize = len;
        buff = readbuf;
    }
    struct CLIENTLIST *writeclient = NULL;
    while (offset < totalsize) {
        if (offset + 64 > totalsize) { // mac帧单个最小必须是64个，小于这个的数据包一定不完整
            int remainsize = totalsize - offset;
            memcpy(sourceclient->remainpackage, buff + offset, remainsize);
            sourceclient->remainsize = remainsize;
            break;
        }
        unsigned int packagesize = 256 * buff[offset] + buff[offset+1] + 2; // 当前数据帧大小
        if (offset + packagesize > totalsize) {
            int remainsize = totalsize - offset;
            memcpy(sourceclient->remainpackage, buff + offset, remainsize);
            sourceclient->remainsize = remainsize;
            break;
        }
// 自学习算法开始
        unsigned int srchash = 256 * buff[offset+12] + buff[offset+13];
        if (sourceclient != machashlist[srchash]) {
            if (sourceclient->mac[0] != 0x00 || sourceclient->mac[1] != 0x00 || sourceclient->mac[2] != 0x00 || sourceclient->mac[3] != 0x00 || sourceclient->mac[4] != 0x00 || sourceclient->mac[5] != 0x00) {
                unsigned int oldhash = 256 * sourceclient->mac[5] + sourceclient->mac[6];
                if (sourceclient->hashhead) {
                    sourceclient->hashhead->hashtail = sourceclient->hashtail;
                } else {
                    machashlist[oldhash] = sourceclient->hashtail;
                }
                if (sourceclient->hashtail) {
                    sourceclient->hashtail->hashhead = sourceclient->hashhead;
                }
                sourceclient->hashhead = NULL;
            }
            if (machashlist[srchash]) {
                machashlist[srchash]->hashhead = sourceclient;
            }
            sourceclient->hashtail = machashlist[srchash];
            machashlist[srchash] = sourceclient;
        }
        memcpy(sourceclient->mac, buff + offset + 8, 6);
// 自学习算法结束
        unsigned char targetmac[6];
        memcpy(targetmac, buff + offset + 2, 6);
        if (targetmac[0] == 0xff && targetmac[1] == 0xff && targetmac[2] == 0xff && targetmac[3] == 0xff && targetmac[4] == 0xff && targetmac[5] == 0xff) { // 广播帧
            writeclient = braodcastdata(sourceclient, buff + offset, packagesize);
            offset += packagesize;
            continue;
        }
        unsigned int dsthash = 256 * buff[offset+6] + buff[offset+7];
        struct CLIENTLIST *targetclient;
        for (targetclient = machashlist[dsthash] ; targetclient != NULL ; targetclient = targetclient->tail) {
            if (!memcmp(targetclient->mac, targetmac, 4)) {
                break;
            }
        }
        if (targetclient == NULL) { // mac地址表中不存在，使用广播策略
            writeclient = braodcastdata(sourceclient, buff + offset, packagesize);
            offset += packagesize;
            continue;
        }
        struct PACKAGELIST *package;
        if (remainpackagelisthead) { // 全局数据包回收站不为空
            package = remainpackagelisthead;
            remainpackagelisthead = remainpackagelisthead->tail;
        } else {
            package = (struct PACKAGELIST*) malloc(sizeof(struct PACKAGELIST));
            if (package == NULL) {
                printf("malloc fail, in %s, at %d\n",  __FILE__, __LINE__);
                offset += packagesize;
                continue;
            }
        }
        if (targetclient == tapclient) {
            memcpy(package->data, buff + offset + 2, packagesize - 2);
            package->size = packagesize - 2;
        } else {
            memcpy(package->data, buff + offset, packagesize);
            package->size = packagesize;
        }
        package->tail = NULL;
        if (targetclient->packagelisthead == NULL) {
            targetclient->packagelisthead = package;
            targetclient->packagelisttail = targetclient->packagelisthead;
        } else {
            targetclient->packagelisttail->tail = package;
            targetclient->packagelisttail = targetclient->packagelisttail->tail;
        }
        if (!targetclient->canwrite) {
            offset += packagesize;
            continue;
        }
        struct CLIENTLIST *tmpclient;
        for (tmpclient = writeclient ; tmpclient != NULL ; tmpclient = tmpclient->writetail) {
            if (tmpclient == targetclient) {
                break;
            }
        }
        if (tmpclient == NULL) {
            targetclient->writetail = writeclient;
            writeclient = targetclient;
        }
        offset += packagesize;
    }
    writenode(writeclient);
    return 0;
}

int parseconfigfile () {
    int fd = open("config.json", O_RDONLY);
    if (fd < 0) {
        printf("open config.json fail, in %s, at %d\n", __FILE__, __LINE__);
        return -1;
    }
    ssize_t len = read(fd, readbuf, MAXDATASIZE);
    close(fd);
    if (len < 0) {
        printf("read config.json fail, in %s, at %d\n", __FILE__, __LINE__);
        return -2;
    }
    readbuf[len] = '\0';
    yyjson_doc *doc = yyjson_read(readbuf, len, YYJSON_READ_ALLOW_COMMENTS);
    yyjson_val *root = yyjson_doc_get_root(doc);
    yyjson_val *bindport = yyjson_obj_get(root, "bindport");
    if (bindport == NULL || yyjson_get_type(bindport) != YYJSON_TYPE_NUM) {
        printf("bindport not found, in %s, at %d\n", __FILE__, __LINE__);
        return -1;
    }
    c.bindport = yyjson_get_int(bindport);
    yyjson_val *tcpkeepalive = yyjson_obj_get(root, "tcpkeepalive");
    if (tcpkeepalive == NULL || yyjson_get_type(tcpkeepalive) != YYJSON_TYPE_BOOL) {
        c.tcpkeepalive = false;
    } else {
        c.tcpkeepalive = yyjson_get_bool(tcpkeepalive);
    }
    if (c.tcpkeepalive) {
        yyjson_val *tcpkeepidle = yyjson_obj_get(root, "tcpkeepidle");
        if (tcpkeepidle == NULL || yyjson_get_type(tcpkeepidle) != YYJSON_TYPE_NUM) {
            printf("tcpkeepidle not found, in %s, at %d\n", __FILE__, __LINE__);
            return -1;
        }
        c.tcpkeepidle = yyjson_get_int(tcpkeepidle);
        yyjson_val *tcpkeepintvl = yyjson_obj_get(root, "tcpkeepintvl");
        if (tcpkeepintvl == NULL || yyjson_get_type(tcpkeepintvl) != YYJSON_TYPE_NUM) {
            printf("tcpkeepintvl not found, in %s, at %d\n", __FILE__, __LINE__);
            return -1;
        }
        c.tcpkeepintvl = yyjson_get_int(tcpkeepintvl);
        yyjson_val *tcpkeepcnt = yyjson_obj_get(root, "tcpkeepcnt");
        if (tcpkeepcnt == NULL || yyjson_get_type(tcpkeepcnt) != YYJSON_TYPE_NUM) {
            printf("tcpkeepcnt not found, in %s, at %d\n", __FILE__, __LINE__);
            return -1;
        }
        c.tcpkeepcnt = yyjson_get_int(tcpkeepcnt);
    }
    yyjson_val *ssl = yyjson_obj_get(root, "ssl");
    if (ssl == NULL || yyjson_get_type(ssl) != YYJSON_TYPE_BOOL) {
        c.ssl = false;
    } else {
        c.ssl = yyjson_get_bool(ssl);
    }
    if (c.ssl) {
        yyjson_val *crtpath = yyjson_obj_get(root, "crtpath");
        if (crtpath == NULL || yyjson_get_type(crtpath) != YYJSON_TYPE_STR) {
            printf("crtpath not found, in %s, at %d\n", __FILE__, __LINE__);
            return -1;
        }
        strcpy(c.crtpath, yyjson_get_str(crtpath));
        yyjson_val *keypath = yyjson_obj_get(root, "keypath");
        if (keypath == NULL || yyjson_get_type(keypath) != YYJSON_TYPE_STR) {
            printf("keypath not found, in %s, at %d\n", __FILE__, __LINE__);
            return -1;
        }
        strcpy(c.keypath, yyjson_get_str(keypath));
    }
    yyjson_val *httppath = yyjson_obj_get(root, "httppath");
    if (httppath == NULL || yyjson_get_type(httppath) != YYJSON_TYPE_STR) {
        printf("httppath not found, in %s, at %d\n", __FILE__, __LINE__);
        return -1;
    }
    strcpy(c.httppath, yyjson_get_str(httppath));
    yyjson_val *ip = yyjson_obj_get(root, "ip");
    if (ip == NULL || yyjson_get_type(ip) != YYJSON_TYPE_STR) {
        printf("ip not found, in %s, at %d\n", __FILE__, __LINE__);
        return -1;
    }
    if (inet_pton(AF_INET, yyjson_get_str(ip), c.ip) < 0) {
        printf("ip format error, in %s, at %d\n", __FILE__, __LINE__);
        return -23;
    }
    yyjson_val *mask = yyjson_obj_get(root, "mask");
    if (mask == NULL || yyjson_get_type(mask) != YYJSON_TYPE_STR) {
        printf("mask not found, in %s, at %d\n", __FILE__, __LINE__);
        return -1;
    }
    if (inet_pton(AF_INET, yyjson_get_str(mask), c.mask) < 0) {
        printf("mask format error, in %s, at %d\n", __FILE__, __LINE__);
        return -23;
    }
    yyjson_val *tapname = yyjson_obj_get(root, "tapname");
    if (tapname == NULL || yyjson_get_type(tapname) != YYJSON_TYPE_STR) {
        strcpy(c.tapname, "wfvpn_tap");
    } else {
        strcpy(c.tapname, yyjson_get_str(tapname));
    }
    yyjson_val *keys = yyjson_obj_get(root, "keys");
    if (keys == NULL || yyjson_get_type(keys) != YYJSON_TYPE_ARR) {
        printf("keys not found, in %s, at %d\n", __FILE__, __LINE__);
        return -1;
    }
    size_t idx, max;
    yyjson_val *v;
    yyjson_arr_foreach(keys, idx, max, v) {
        if (yyjson_get_type(v) != YYJSON_TYPE_STR) {
            printf("key format error, in %s, at %d\n", __FILE__, __LINE__);
            return -1;
        }
        struct KEYS *keys = (struct KEYS*)malloc(sizeof(struct KEYS));
        if (keys == NULL) {
            printf("malloc fail, in %s, at %d\n", __FILE__, __LINE__);
            return -1;
        }
        strcpy(keys->key, yyjson_get_str(v));
        keys->tail = c.keys;
        c.keys = keys;
    }
    yyjson_val *routers = yyjson_obj_get(root, "routers");
    if (yyjson_get_type(routers) == YYJSON_TYPE_ARR) {
        yyjson_arr_foreach(routers, idx, max, v) {
            if (v == NULL || yyjson_get_type(v) != YYJSON_TYPE_OBJ) {
                printf("routers format error, in %s, at %d\n", __FILE__, __LINE__);
                return -1;
            }
            struct ROUTERS *routers = (struct ROUTERS*)malloc(sizeof(struct ROUTERS));
            if (routers == NULL) {
                printf("malloc fail, in %s, at %d\n", __FILE__, __LINE__);
                return -1;
            }
            yyjson_val *dstip = yyjson_obj_get(v, "dstip");
            if (dstip == NULL || yyjson_get_type(dstip) != YYJSON_TYPE_STR) {
                printf("dstip not found, in %s, at %d\n", __FILE__, __LINE__);
                return -1;
            }
            if (inet_pton(AF_INET, yyjson_get_str(dstip), routers->dstip) < 0) {
                printf("dstip format error, in %s, at %d\n", __FILE__, __LINE__);
                return -23;
            }
            yyjson_val *dstmask = yyjson_obj_get(v, "dstmask");
            if (dstmask == NULL || yyjson_get_type(dstmask) != YYJSON_TYPE_STR) {
                printf("dstmask not found, in %s, at %d\n", __FILE__, __LINE__);
                return -1;
            }
            if (inet_pton(AF_INET, yyjson_get_str(dstmask), routers->dstmask) < 0) {
                printf("dstmask format error, in %s, at %d\n", __FILE__, __LINE__);
                return -23;
            }
            yyjson_val *gateway = yyjson_obj_get(v, "gateway");
            if (gateway == NULL || yyjson_get_type(gateway) != YYJSON_TYPE_STR) {
                printf("gateway not found, in %s, at %d\n", __FILE__, __LINE__);
                return -1;
            }
            if (inet_pton(AF_INET, yyjson_get_str(gateway), routers->gateway) < 0) {
                printf("gateway format error, in %s, at %d\n", __FILE__, __LINE__);
                return -23;
            }
            routers->tail = c.routers;
            c.routers = routers;
        }
    }
    yyjson_doc_free(doc);
    return 0;
}

int main () {
    if (parseconfigfile()) {
        printf("parse config file fail, in %s, at %d\n", __FILE__, __LINE__);
        return -1;
    }
    if (c.ssl) {
        SSL_library_init();
        OpenSSL_add_all_algorithms();
        SSL_load_error_strings();
        ctx = SSL_CTX_new(TLS_client_method());
        if (!SSL_CTX_use_certificate_file(ctx, c.crtpath, SSL_FILETYPE_PEM)) {
            printf("load certificate file fail, in %s, at %d\n", __FILE__, __LINE__);
            return -2;
        }
        if (!SSL_CTX_use_PrivateKey_file(ctx, c.keypath, SSL_FILETYPE_PEM) ) {
            printf("load private key file fail, in %s, at %d\n", __FILE__, __LINE__);
            return -3;
        }
        if (!SSL_CTX_check_private_key(ctx)) {
            printf("check private key fail, in %s, at %d\n", __FILE__, __LINE__);
            return -4;
        }
    }
    for (int i = 0 ; i < 4096 ; i++) {
        machashlist[i] = NULL;
    }
    epollfd = epoll_create(MAX_EVENT);
    printf("epollfd:%d, in %s, at %d\n", epollfd, __FILE__, __LINE__);
    if (epollfd < 0) {
        printf("create epoll fd fail, in %s, at %d\n",  __FILE__, __LINE__);
        return -5;
    }
    if (tap_alloc()) {
        printf("alloc tap fail, in %s, at %d\n",  __FILE__, __LINE__);
        return -6;
    }
    if (create_socketfd()) {
        printf("create socket fd fail, in %s, at %d\n",  __FILE__, __LINE__);
        return -7;
    }
    printf("init finish, server port is %d, in %s, at %d\n", c.bindport, __FILE__, __LINE__);
    while (1) {
        static struct epoll_event evs[MAX_EVENT];
        static int wait_count;
        wait_count = epoll_wait(epollfd, evs, MAX_EVENT, -1);
        for (int i = 0 ; i < wait_count ; i++) {
            struct FDCLIENT *fdclient = evs[i].data.ptr;
            uint32_t events = evs[i].events;
            if (fdclient->watch == 0) { // 监听为空,什么事都不做
                continue;
            } else if (events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) { // 检测到数据异常
                printf("connect lose, fd:%d, EPOLLERR:%d, EPOLLHUP:%d, EPOLLRDHUP:%d, in %s, at %d\n", fdclient->fd, events&EPOLLERR ? 1 : 0, events&EPOLLHUP ? 1 : 0, events&EPOLLRDHUP ? 1 : 0, __FILE__, __LINE__);
                removeclient(fdclient);
            } else if (fdclient == fdserver) {
                addclient(fdclient->fd);
            } else if (events & EPOLLIN) { // 数据可读
                if (fdclient->tls) {
                    if (fdclient->tlsconnected == 0) {
                        int r_code = SSL_accept(fdclient->tls);
                        if (r_code < 0) {
                            int errcode = SSL_get_error(fdclient->tls, r_code);
                            if (errcode != SSL_ERROR_WANT_READ) {
                                perror("tls connect error");
                                printf("errno:%d, errcode:%d, in %s, at %d\n", errno, errcode, __FILE__, __LINE__);
                                removeclient(fdclient);
                            }
                        } else {
                            fdclient->tlsconnected = 1;
                        }
                    } else {
                        readdata(fdclient);
                    }
                } else {
                    readdata(fdclient);
                }
            } else if (events & EPOLLOUT) { // 数据可写
                fdclient->client->writetail = NULL;
                writenode(fdclient->client);
            } else {
                printf("receive new event 0x%08x, in %s, at %d\n", events,  __FILE__, __LINE__);
            }
        }
    }
    if (c.ssl) {
        SSL_CTX_free(ctx);
    }
    return 0;
}
