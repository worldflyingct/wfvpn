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
#include <netdb.h>
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
#define MTU_SIZE          1500

const char httprequest[] = "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nPragma: no-cache\r\nCache-Control: no-cache\r\nUpgrade: websocket\r\nAuthorization: %s\r\n\r\n";
const char httpresponse[] = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";

struct PACKAGELIST {
    unsigned char data[MTU_SIZE + 18];
    unsigned int size;
    struct PACKAGELIST *tail;
};
struct PACKAGELIST *remainpackagelisthead = NULL;
struct CLIENTLIST {
    int fd;
    SSL *tls;
    struct PACKAGELIST *packagelisthead; // 发给自己这个端口的数据包列表头部
    struct PACKAGELIST *packagelisttail; // 发给自己这个端口的数据包列表尾部
    unsigned char remainpackage[MTU_SIZE + 18]; // 自己接收到的数据出现数据不全，将不全的数据存在这里，等待新的数据将其补全
    unsigned int remainsize; // 不全的数据大小
    unsigned char canwrite;
} tclient, sclient;
struct CLIENTLIST *tapclient = &tclient;
struct CLIENTLIST *socketclient = &sclient;
int epollfd;
SSL_CTX *ctx;
unsigned char readbuf[MAXDATASIZE];

struct ROUTERS {
    unsigned char dstip[4];
    unsigned char dstmask[4];
    unsigned char gateway[4];
    struct ROUTERS *tail;
};
struct CONFIG {
    unsigned char serverip[4];
    unsigned short serverport;
    bool tcpkeepalive;
    unsigned char tcpkeepidle;
    unsigned char tcpkeepintvl;
    unsigned char tcpkeepcnt;
    bool ssl;
    unsigned char ip[4];
    unsigned char mask[4];
    unsigned char httphost[256];
    unsigned char httppath[256];
    unsigned char tapname[16];
    unsigned char key[16];
    unsigned char retryinterval;
    struct ROUTERS *routers;
};
struct CONFIG c;

int setnonblocking (int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        printf("get flags fail, fd:%d, in %s, at %d\n", fd, __FILE__, __LINE__);
        return -1;
    }
    if(fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        printf("set flags fail, fd:%d, in %s, at %d\n", fd, __FILE__, __LINE__);
        return -1;
    }
    return 0;
}

int addtoepoll (struct CLIENTLIST *fdclient) {
    struct epoll_event ev;
    ev.data.ptr = fdclient;
    ev.events = EPOLLIN | EPOLLERR | EPOLLHUP | EPOLLRDHUP; // 水平触发，保证所有数据都能读到
    return epoll_ctl(epollfd, EPOLL_CTL_ADD, fdclient->fd, &ev);
}

int modepoll (struct CLIENTLIST *client, int flags) {
    struct epoll_event ev;
    ev.data.ptr = client;
    ev.events = EPOLLIN | EPOLLERR | EPOLLHUP | EPOLLRDHUP | flags; // 水平触发，保证所有数据都能读到
    return epoll_ctl(epollfd, EPOLL_CTL_MOD, client->fd, &ev);
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
    tapclient->fd = fd;
    tapclient->tls = NULL;
    tapclient->packagelisthead = NULL;
    tapclient->remainsize = 0;
    tapclient->canwrite = 1;
    if (addtoepoll(tapclient)) {
        printf("clientfd addtoepoll fail, in %s, at %d\n",  __FILE__, __LINE__);
        close(fd);
        return -8;
    }
    return 0;
}

int connect_socketfd () {
    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(struct sockaddr_in));
    sin.sin_family = AF_INET; // ipv4
    memcpy(&sin.sin_addr, c.serverip, 4);
    sin.sin_port = htons(c.serverport);
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        printf("run socket function is fail, fd:%d, in %s, at %d\n", fd, __FILE__, __LINE__);
        return -1;
    }
    if(connect(fd, (struct sockaddr*)&sin, sizeof(sin)) < 0) {
        printf("connect server fail, fd:%d, in %s, at %d\n", fd, __FILE__, __LINE__);
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
    socksval = MAXDATASIZE - MTU_SIZE;
    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (unsigned char*)&socksval, sizeof(socksval))) {
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
    printf("old receive buffer is %d, len:%d, fd:%d, in %s, at %d\n", socksval, socksval_len, fd,  __FILE__, __LINE__);
    socksval = MAXDATASIZE - MTU_SIZE;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (unsigned char*)&socksval, sizeof(socksval))) {
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
    SSL *tls;
    if (c.ssl) {
        tls = SSL_new(ctx);
        if (tls) {
            printf("SSL new fail, fd:%d, in %s, at %d\n", fd,  __FILE__, __LINE__);
            close(fd);
            return -16;
        }
        if (!SSL_set_fd(tls, fd)) {
            printf("SSL set fd fail, fd:%d, in %s, at %d\n", fd,  __FILE__, __LINE__);
            SSL_shutdown(tls);
            SSL_free(tls);
            close(fd);
            return -17;
        }
        if(SSL_connect(tls) == -1) {
            printf("ssl connect error");
            SSL_shutdown(tls);
            SSL_free(tls);
            close(fd);
            return -18;
        }
    }
    unsigned int size = sprintf(readbuf, httprequest, c.httppath, c.httphost, c.key);
    ssize_t len;
    if (tls) {
        len = SSL_write(tls, readbuf, size);
    } else {
        len = write(fd, readbuf, size);
    }
    if (len < 0) {
        printf("write fail, fd:%d, in %s, at %d\n", fd, __FILE__, __LINE__);
        if (tls) {
            SSL_shutdown(tls);
            SSL_free(tls);
        }
        close(fd);
        return -19;
    }
    if (tls) {
        len = SSL_read(tls, readbuf, MAXDATASIZE);
    } else {
        len = read(fd, readbuf, MAXDATASIZE);
    }
    if (len < 0) {
        printf("read fail, fd:%d, in %s, at %d\n", fd, __FILE__, __LINE__);
        if (tls) {
            SSL_shutdown(tls);
            SSL_free(tls);
        }
        close(fd);
        return -20;
    }
    readbuf[len] = '\0';
    if (strcmp(readbuf, httpresponse)) {
        printf("password check fail, fd:%d, in %s, at %d\n", fd, __FILE__, __LINE__);
        if (tls) {
            SSL_shutdown(tls);
            SSL_free(tls);
        }
        close(fd);
        return -21;
    }
    if (setnonblocking(fd) < 0) { // 设置为非阻塞IO
        printf("set nonblocking fail, fd:%d, in %s, at %d\n", fd, __FILE__, __LINE__);
        if (tls) {
            SSL_shutdown(tls);
            SSL_free(tls);
        }
        close(fd);
        return -22;
    }
    socketclient->fd = fd;
    if (tls) {
        socketclient->tls = tls;
    } else {
        socketclient->tls = NULL;
    }
    socketclient->packagelisthead = NULL;
    socketclient->remainsize = 0;
    socketclient->canwrite = 1;
    if (addtoepoll(socketclient)) {
        printf("tapfd addtoepoll fail, fd:%d, in %s, at %d\n", fd,  __FILE__, __LINE__);
        if (tls) {
            SSL_shutdown(tls);
            SSL_free(tls);
        }
        close(fd);
        return -23;
    }
    return 0;
}

int removeclient () {
    struct epoll_event ev;
    epoll_ctl(epollfd, EPOLL_CTL_DEL, tapclient->fd, &ev);
    close(tapclient->fd);
    struct PACKAGELIST *package = tapclient->packagelisthead;
    while (package) {
        struct PACKAGELIST *tmppackage = package;
        package = package->tail;
        tmppackage->tail = remainpackagelisthead;
        remainpackagelisthead = tmppackage;
    }
    epoll_ctl(epollfd, EPOLL_CTL_DEL, socketclient->fd, &ev);
    if (socketclient->tls) {
        SSL_shutdown(socketclient->tls);
        SSL_free(socketclient->tls);
    }
    close(socketclient->fd);
    package = socketclient->packagelisthead;
    while (package) {
        struct PACKAGELIST *tmppackage = package;
        package = package->tail;
        tmppackage->tail = remainpackagelisthead;
        remainpackagelisthead = tmppackage;
    }
    return 0;
}

int writenode (struct CLIENTLIST *client) {
    struct PACKAGELIST *package = client->packagelisthead;
    client->packagelisthead = NULL;
    while (package) {
        ssize_t len;
        if (client->tls) {
            len = SSL_write(client->tls, package->data, package->size);
        } else {
            len = write(client->fd, package->data, package->size);
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
                return -1;
            }
            if (client->canwrite) { // 之前缓冲区是可以写入的，现在不行了
                if (modepoll(client, EPOLLOUT)) { // 监听可写事件
                    printf("modepoll fail, in %s, at %d\n",  __FILE__, __LINE__);
                    return -2;
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
                if (modepoll(client, EPOLLOUT)) { // 监听可写事件
                    printf("modepoll fail, in %s, at %d\n",  __FILE__, __LINE__);
                    return -3;
                }
                client->canwrite = 0;
            }
            break;
        }
        if (client->canwrite == 0) { // 缓冲区尚有空间，并且之前已经提示不足
            if (modepoll(client, 0)) { // 取消监听可写事件
                printf("modepoll fail, in %s, at %d\n",  __FILE__, __LINE__);
                client->packagelisthead = package;
                return -4;
            }
            client->canwrite = 1;
        }
        struct PACKAGELIST *tmppackage = package;
        package = package->tail;
        tmppackage->tail = remainpackagelisthead;
        remainpackagelisthead = tmppackage;
    }
    return 0;
}

int readdata (struct CLIENTLIST *sourceclient) {
    unsigned char *readbuff = NULL; // 这里是用于存储全部的需要写入的数据buf，
    int32_t maxtotalsize = 0;
    struct CLIENTLIST *targetclient;
    ssize_t len;
    if (sourceclient == tapclient) { // tap驱动，原始数据，需要自己额外添加数据包长度。
        len = read(sourceclient->fd, readbuf + 2, MAXDATASIZE); // 这里最大只可能是1518
        if (len < 0) {
            if (errno != EAGAIN) {
                printf("errno:%d, in %s, at %d\n", errno,  __FILE__, __LINE__);
                perror("tap read error");
                return -1;
            }
            return 0;
        }
        readbuf[0] = len >> 8;
        readbuf[1] = len & 0xff;
        len += 2;
        targetclient = socketclient;
    } else { // 网络套接字。
        if (sourceclient->tls) {
            len = SSL_read(sourceclient->tls, readbuf, MAXDATASIZE);
        } else {
            len = read(sourceclient->fd, readbuf, MAXDATASIZE);
        }
        if (len < 0) {
            if (errno != EAGAIN) {
                printf("errno:%d, in %s, at %d\n", errno,  __FILE__, __LINE__);
                perror("socket read error");
                return -2;
            }
            return 0;
        }
        targetclient = tapclient;
    }
    unsigned int offset = 0;
    unsigned int totalsize;
    unsigned char *buff;
    if (sourceclient->remainsize > 0) {
        totalsize = sourceclient->remainsize + len;
        if (totalsize > maxtotalsize) {
            if (readbuff) {
                free (readbuff);
            }
            readbuff = (unsigned char*) malloc(totalsize * sizeof(unsigned char));
            if (readbuff == NULL) {
                printf("malloc fail, in %s, at %d\n",  __FILE__, __LINE__);
                return -3;
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
        unsigned int packagesize = 256*buff[offset] + buff[offset+1] + 2; // 当前数据帧大小
        if (offset + packagesize > totalsize) {
            int remainsize = totalsize - offset;
            memcpy(sourceclient->remainpackage, buff + offset, remainsize);
            sourceclient->remainsize = remainsize;
            break;
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
            memcpy(package->data, buff + offset + 2, packagesize);
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
        offset += packagesize;
    }
    if (targetclient->canwrite) {
        return writenode(targetclient);
    }
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
    yyjson_val *serverhost = yyjson_obj_get(root, "serverhost");
    if (serverhost == NULL || yyjson_get_type(serverhost) != YYJSON_TYPE_STR) {
        printf("serverhost not found, in %s, at %d\n", __FILE__, __LINE__);
        return -3;
    }
    const char *serverdomain = yyjson_get_str(serverhost);
    struct hostent *sip = gethostbyname(serverdomain); // 域名dns解析
    if(sip == NULL) {
        printf("get ip by domain error, domain:%s, in %s, at %d\n", serverdomain,  __FILE__, __LINE__);
        return -4;
    }
    memcpy(c.serverip, sip->h_addr_list[0], 4);
    yyjson_val *serverport = yyjson_obj_get(root, "serverport");
    if (serverport == NULL || yyjson_get_type(serverport) != YYJSON_TYPE_NUM) {
        printf("serverport not found, in %s, at %d\n", __FILE__, __LINE__);
        return -5;
    }
    c.serverport = yyjson_get_int(serverport);
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
            return -6;
        }
        c.tcpkeepidle = yyjson_get_int(tcpkeepidle);
        yyjson_val *tcpkeepintvl = yyjson_obj_get(root, "tcpkeepintvl");
        if (tcpkeepintvl == NULL || yyjson_get_type(tcpkeepintvl) != YYJSON_TYPE_NUM) {
            printf("tcpkeepintvl not found, in %s, at %d\n", __FILE__, __LINE__);
            return -7;
        }
        c.tcpkeepintvl = yyjson_get_int(tcpkeepintvl);
        yyjson_val *tcpkeepcnt = yyjson_obj_get(root, "tcpkeepcnt");
        if (tcpkeepcnt == NULL || yyjson_get_type(tcpkeepcnt) != YYJSON_TYPE_NUM) {
            printf("tcpkeepcnt not found, in %s, at %d\n", __FILE__, __LINE__);
            return -8;
        }
        c.tcpkeepcnt = yyjson_get_int(tcpkeepcnt);
    }
    yyjson_val *ssl = yyjson_obj_get(root, "ssl");
    if (ssl == NULL || yyjson_get_type(ssl) != YYJSON_TYPE_BOOL) {
        c.ssl = false;
    } else {
        c.ssl = yyjson_get_bool(ssl);
    }
    yyjson_val *httphost = yyjson_obj_get(root, "httphost");
    if (httphost == NULL || yyjson_get_type(httphost) != YYJSON_TYPE_STR) {
        strcpy(c.httphost, yyjson_get_str(httphost));
    } else {
        strcpy(c.httphost, "localhost");
    }
    yyjson_val *httppath = yyjson_obj_get(root, "httppath");
    if (httppath == NULL || yyjson_get_type(httppath) != YYJSON_TYPE_STR) {
        printf("httppath not found, in %s, at %d\n", __FILE__, __LINE__);
        return -9;
    }
    strcpy(c.httppath, yyjson_get_str(httppath));
    yyjson_val *ip = yyjson_obj_get(root, "ip");
    if (ip == NULL || yyjson_get_type(ip) != YYJSON_TYPE_STR) {
        printf("ip not found, in %s, at %d\n", __FILE__, __LINE__);
        return -10;
    }
    if (inet_pton(AF_INET, yyjson_get_str(ip), c.ip) < 0) {
        printf("ip format error, in %s, at %d\n", __FILE__, __LINE__);
        return -11;
    }
    yyjson_val *mask = yyjson_obj_get(root, "mask");
    if (mask == NULL || yyjson_get_type(mask) != YYJSON_TYPE_STR) {
        printf("mask not found, in %s, at %d\n", __FILE__, __LINE__);
        return -12;
    }
    if (inet_pton(AF_INET, yyjson_get_str(mask), c.mask) < 0) {
        printf("mask format error, in %s, at %d\n", __FILE__, __LINE__);
        return -13;
    }
    yyjson_val *tapname = yyjson_obj_get(root, "tapname");
    if (tapname == NULL || yyjson_get_type(tapname) != YYJSON_TYPE_STR) {
        strcpy(c.tapname, "wfvpn_tap");
    } else {
        strcpy(c.tapname, yyjson_get_str(tapname));
    }
    yyjson_val *key = yyjson_obj_get(root, "key");
    if (key == NULL || yyjson_get_type(key) != YYJSON_TYPE_STR) {
        printf("key not found, in %s, at %d\n", __FILE__, __LINE__);
        return -14;
    }
    strcpy(c.key, yyjson_get_str(key));
    yyjson_val *retryinterval = yyjson_obj_get(root, "retryinterval");
    if (retryinterval == NULL || yyjson_get_type(retryinterval) != YYJSON_TYPE_NUM) {
        c.retryinterval = 1;
    } else {
        c.retryinterval = yyjson_get_int(retryinterval);
    }
    size_t idx, max;
    yyjson_val *v;
    yyjson_val *routers = yyjson_obj_get(root, "routers");
    if (yyjson_get_type(routers) == YYJSON_TYPE_ARR) {
        yyjson_arr_foreach(routers, idx, max, v) {
            if (v == NULL || yyjson_get_type(v) != YYJSON_TYPE_OBJ) {
                printf("routers format error, in %s, at %d\n", __FILE__, __LINE__);
                return -15;
            }
            struct ROUTERS *routers = (struct ROUTERS*)malloc(sizeof(struct ROUTERS));
            if (routers == NULL) {
                printf("malloc fail, in %s, at %d\n", __FILE__, __LINE__);
                return -16;
            }
            yyjson_val *dstip = yyjson_obj_get(v, "dstip");
            if (dstip == NULL || yyjson_get_type(dstip) != YYJSON_TYPE_STR) {
                printf("dstip not found, in %s, at %d\n", __FILE__, __LINE__);
                return -17;
            }
            if (inet_pton(AF_INET, yyjson_get_str(dstip), routers->dstip) < 0) {
                printf("dstip format error, in %s, at %d\n", __FILE__, __LINE__);
                return -18;
            }
            yyjson_val *dstmask = yyjson_obj_get(v, "dstmask");
            if (dstmask == NULL || yyjson_get_type(dstmask) != YYJSON_TYPE_STR) {
                printf("dstmask not found, in %s, at %d\n", __FILE__, __LINE__);
                return -19;
            }
            if (inet_pton(AF_INET, yyjson_get_str(dstmask), routers->dstmask) < 0) {
                printf("dstmask format error, in %s, at %d\n", __FILE__, __LINE__);
                return -20;
            }
            yyjson_val *gateway = yyjson_obj_get(v, "gateway");
            if (gateway == NULL || yyjson_get_type(gateway) != YYJSON_TYPE_STR) {
                printf("gateway not found, in %s, at %d\n", __FILE__, __LINE__);
                return -21;
            }
            if (inet_pton(AF_INET, yyjson_get_str(gateway), routers->gateway) < 0) {
                printf("dstmask format error, in %s, at %d\n", __FILE__, __LINE__);
                return -22;
            }
            routers->tail = c.routers;
            c.routers = routers;
        }
    }
    yyjson_doc_free(doc);
    return 0;
}

int main (int argc, char *argv[]) {
    if (parseconfigfile()) {
        printf("parse config file fail, in %s, at %d\n", __FILE__, __LINE__);
        return -1;
    }
    if (c.ssl) {
        SSL_library_init();
        OpenSSL_add_all_algorithms();
        SSL_load_error_strings();
        ctx = SSL_CTX_new(TLS_client_method());
    }
    epollfd = epoll_create(MAX_EVENT);
    if (epollfd < 0) {
        printf("create epoll fd fail, in %s, at %d\n",  __FILE__, __LINE__);
        return -2;
    }
    while (1) {
        if (connect_socketfd()) {
            printf("create socket fd fail, in %s, at %d\n",  __FILE__, __LINE__);
            return -3;
        }
        if (tap_alloc()) {
            printf("alloc tap fail, in %s, at %d\n",  __FILE__, __LINE__);
            return -4;
        }
        unsigned char loop = 1;
        while (loop) {
            static struct epoll_event evs[MAX_EVENT];
            static int wait_count;
            wait_count = epoll_wait(epollfd, evs, MAX_EVENT, -1);
            for (int i = 0 ; i < wait_count ; i++) {
                struct CLIENTLIST *client = evs[i].data.ptr;
                uint32_t events = evs[i].events;
                if (events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) { // 检测到数据异常
                    printf ("receive error event, fd:%d, EPOLLERR:%d, EPOLLHUP:%d, EPOLLRDHUP:%d, in %s, at %d\n", client->fd, events&EPOLLERR ? 1 : 0, events&EPOLLHUP ? 1 : 0, events&EPOLLRDHUP ? 1 : 0,  __FILE__, __LINE__);
                    removeclient();
                    loop = 0;
                    break;
                } else if (events & EPOLLIN) {
                    if (readdata(client) < 0) {
                        removeclient();
                        loop = 0;
                        break;
                    }
                } else if (events & EPOLLOUT) {
                    if (writenode(client) < 0) {
                        removeclient();
                        loop = 0;
                        break;
                    }
                } else {
                    printf("receive new event 0x%08x, in %s, at %d\n", evs[i].events,  __FILE__, __LINE__);
                    removeclient();
                    loop = 0;
                    break;
                }
            }
        }
        sleep(c.retryinterval);
    }
    if (c.ssl) {
        SSL_CTX_free(ctx);
    }
    return 0;
}
