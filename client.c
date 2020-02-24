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
#include <netinet/tcp.h>
#include <sys/epoll.h>
// 用于生成随机种子
#include <time.h>

#define MAXDATASIZE       2*1024*1024
#define MAX_EVENT         1024
#define MTU_SIZE          1500
#define KEEPALIVE            // 如果定义了，就是启动心跳包，不定义就不启动，下面3个参数就没有意义。
#define KEEPIDLE          60 // tcp完全没有数据传输的最长间隔为60s，操过60s就要发送询问数据包
#define KEEPINTVL         5  // 如果询问失败，间隔多久再次发出询问数据包
#define KEEPCNT           3  // 如果询问失败，间隔多久再次发出询问数据包
#define RETRYINTERVAL     5  // 如果重要链接断掉了，重连间隔时间，单位秒

struct PACKAGELIST {
    unsigned char data[MTU_SIZE + 18];
    int size;
    struct PACKAGELIST *tail;
};
struct PACKAGELIST *remainpackagelisthead = NULL;
struct CLIENTLIST {
    int fd; // 与fdclient中的fd意义一样，只是为了方便使用而已
    struct PACKAGELIST *packagelisthead; // 发给自己这个端口的数据包列表头部
    struct PACKAGELIST *packagelisttail; // 发给自己这个端口的数据包列表尾部
    unsigned char remainpackage[MTU_SIZE + 18]; // 自己接收到的数据出现数据不全，将不全的数据存在这里，等待新的数据将其补全
    int remainsize; // 不全的数据大小
    int canwrite;
    unsigned char sendcrypt;
    unsigned char sendk;
    unsigned char sendb;
    unsigned char receivecrypt;
    unsigned char receivek;
    unsigned char receiveb;
} tclient, sclient;
struct CLIENTLIST *tapclient = &tclient;
struct CLIENTLIST *socketclient = &sclient;
int epollfd;

unsigned char serverip[16]; // 服务器的地址，不支持域名
unsigned int serverport; // 服务器的连接端口
unsigned char password[33]; // 密码固定为32位

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

void encrypt (struct CLIENTLIST *targetclient, unsigned char *data, unsigned int len) {
    unsigned char sendcrypt = targetclient->sendcrypt;
    unsigned char sendk = targetclient->sendk;
    unsigned char sendb = targetclient->sendb;
    switch (sendcrypt) {
        case 0:
            for (unsigned int i = 0 ; i < len ; i++) {
                data[i] = data[i] ^ sendk;
                data[i] = data[i] + sendb;
            }
            break;
        case 1:
            for (unsigned int i = 0 ; i < len ; i++) {
                data[i] = data[i] ^ sendk;
                data[i] = data[i] - sendb;
            }
            break;
        case 2:
            for (unsigned int i = 0 ; i < len ; i++) {
                data[i] = data[i] + sendb;
                data[i] = data[i] ^ sendk;
            }
            break;
        case 3:
            for (unsigned int i = 0 ; i < len ; i++) {
                data[i] = data[i] - sendb;
                data[i] = data[i] ^ sendk;
            }
            break;
    }
}

void decrypt (struct CLIENTLIST *sourceclient, unsigned char *data, uint32_t len) {
    unsigned char receivecrypt = sourceclient->receivecrypt;
    unsigned char receivek = sourceclient->receivek;
    unsigned char receiveb = sourceclient->receiveb;
    switch (receivecrypt) {
        case 0:
            for (uint32_t i = 0 ; i < len ; i++) {
                data[i] = data[i] - receiveb;
                data[i] = data[i] ^ receivek;
            }
            break;
        case 1:
            for (uint32_t i = 0 ; i < len ; i++) {
                data[i] = data[i] + receiveb;
                data[i] = data[i] ^ receivek;
            }
            break;
        case 2:
            for (uint32_t i = 0 ; i < len ; i++) {
                data[i] = data[i] ^ receivek;
                data[i] = data[i] - receiveb;
            }
            break;
        case 3:
            for (uint32_t i = 0 ; i < len ; i++) {
                data[i] = data[i] ^ receivek;
                data[i] = data[i] + receiveb;
            }
            break;
    }
}

int writenode (struct CLIENTLIST *client) {
    struct PACKAGELIST *package = client->packagelisthead;
    client->packagelisthead = NULL;
    while (package != NULL) {
        ssize_t len = write(client->fd, package->data, package->size);
        if (len < package->size) { // 缓冲区不足，已无法继续写入数据。
            if (len < 0) {
                if (client == tapclient) {
                    perror("tap write error");
                } else {
                    perror("socket write error");
                }
                client->packagelisthead = package;
                break;
            }
            int size = package->size - len;
            unsigned char tmpdata[MTU_SIZE + 18];
            memcpy(tmpdata, package->data + len, size);
            memcpy(package->data, tmpdata, size);
            package->size = size;
            client->packagelisthead = package;
            if (client->canwrite) { // 之前缓冲区是可以写入的，现在不行了
                if (modepoll(client, EPOLLOUT)) { // 监听可写事件
                    printf("modepoll fail, in %s, at %d\n",  __FILE__, __LINE__);
                    break;
                }
                client->canwrite = 0;
            }
            break;
        } else if (client->canwrite == 0) { // 缓冲区尚有空间，并且之前已经提示不足
            if (modepoll(client, 0)) { // 取消监听可写事件
                printf("modepoll fail, in %s, at %d\n",  __FILE__, __LINE__);
                break;
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
    unsigned char readbuf[MAXDATASIZE]; // 这里使用static关键词是为了将数据存储与数据段，减小对栈空间的压力。
    static unsigned char *readbuff = NULL; // 这里是用于存储全部的需要写入的数据buf，
    static int32_t maxtotalsize = 0;
    int fd = sourceclient->fd;
    struct CLIENTLIST *targetclient;
    ssize_t len;
    if (sourceclient == tapclient) { // tap驱动，原始数据，需要自己额外添加数据包长度。
        len = read(fd, readbuf + 2, MAXDATASIZE); // 这里最大只可能是1518
        if (len < 0) {
            perror("tap read error");
            return -1;
        }
        readbuf[0] = len >> 8;
        readbuf[1] = len & 0xff;
        len += 2;
        targetclient = socketclient;
    } else { // 网络套接字。
        len = read(fd, readbuf, MAXDATASIZE);
        if (len < 0) {
            perror("socket read error");
            return -2;
        }
        targetclient = tapclient;
        decrypt(sourceclient, readbuf, len);
    }
    int32_t offset = 0;
    int32_t totalsize;
    unsigned char *buff;
    if (sourceclient->remainsize > 0) {
        totalsize = sourceclient->remainsize + len;
        if (totalsize > maxtotalsize) {
            maxtotalsize = totalsize;
            if (readbuff != NULL) {
                free (readbuff);
            }
            readbuff = (unsigned char*) malloc(totalsize * sizeof(unsigned char));
            if (readbuff == NULL) {
                printf("malloc fail, in %s, at %d\n",  __FILE__, __LINE__);
                return -3;
            }
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
        int packagesize = 256*buff[offset] + buff[offset+1] + 2; // 当前数据帧大小
        if (offset + packagesize > totalsize) {
            int remainsize = totalsize - offset;
            memcpy(sourceclient->remainpackage, buff + offset, remainsize);
            sourceclient->remainsize = remainsize;
            break;
        }
        struct PACKAGELIST *package;
        if (remainpackagelisthead != NULL) { // 全局数据包回收站不为空
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
            encrypt(targetclient, package->data, packagesize);
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
        writenode(targetclient);
    }
    return 0;
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
    if (ioctl(fd, TUNSETIFF, (void*) &ifr) < 0) {
        printf("ioctl tun node fail, in %s, at %d\n", __FILE__, __LINE__);
        close(fd);
        return -2;
    }
    if (setnonblocking(fd) < 0) {
        printf("set nonblocking fail, fd:%d, in %s, at %d\n", fd, __FILE__, __LINE__);
        close(fd);
        return -3;
    }
    printf("tap device name is %s, in %s, at %d\n", ifr.ifr_name, __FILE__, __LINE__);
    tapclient->fd = fd;
    tapclient->packagelisthead = NULL;
    tapclient->remainsize = 0;
    tapclient->canwrite = 1;
    if (addtoepoll(tapclient)) {
        printf("clientfd addtoepoll fail, in %s, at %d\n",  __FILE__, __LINE__);
        close(fd);
        return -4;
    }
    return 0;
}

int connect_socketfd (unsigned char *ip, unsigned int port) {
    struct sockaddr_in sin;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        printf("run socket function is fail, in %s, at %d\n", __FILE__, __LINE__);
        return -1;
    }
    memset(&sin, 0, sizeof(struct sockaddr_in));
    sin.sin_family = AF_INET; // ipv4
    in_addr_t _ip = inet_addr(ip); // 服务器ip地址，这里不能输入域名
    if (_ip == INADDR_NONE) {
        printf("server ip error, ip:%s, in %s, at %d\n", ip, __FILE__, __LINE__);
        close(fd);
        return -2;
    }
    sin.sin_addr.s_addr = _ip;
    sin.sin_port = htons(port);
    if(connect(fd, (struct sockaddr*)&sin, sizeof(sin)) < 0) {
        printf("connect server fail, in %s, at %d\n", __FILE__, __LINE__);
        close(fd);
        return -3;
    }
    unsigned char data[9+sizeof(password)-1];
    memset(data, 0, 3);
    socketclient->receivecrypt = data[3] = 0x03 & rand();
    socketclient->receivek = data[4] = rand();
    socketclient->receiveb = data[5] = rand();
    socketclient->sendcrypt = data[6] = 0x03 & rand();
    socketclient->sendk = data[7] = rand();
    socketclient->sendb = data[8] = rand();
    memcpy(data + 9, password, sizeof(password)-1);
    ssize_t len = write(fd, data, sizeof(data));
    if (len < sizeof(data)) {
        printf("write fail, fd:%d, in %s, at %d\n", fd, __FILE__, __LINE__);
        close(fd);
        return -4;
    }
    len = read(fd, data, sizeof(data));
    if (len < 1) {
        printf("read fail, fd:%d, in %s, at %d\n", fd, __FILE__, __LINE__);
        close(fd);
        return -5;
    }
    if (data[0] != 0x01) {
        printf("password check fail, fd:%d, in %s, at %d\n", fd, __FILE__, __LINE__);
        close(fd);
        return -6;
    }
    if (setnonblocking(fd) < 0) { // 设置为非阻塞IO
        printf("set nonblocking fail, fd:%d, in %s, at %d\n", fd, __FILE__, __LINE__);
        close(fd);
        return -7;
    }
    unsigned int socksval = 1;
    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (unsigned char*)&socksval, sizeof(socksval))) { // 关闭Nagle协议
        printf("close Nagle protocol fail, fd:%d, in %s, at %d\n", fd, __FILE__, __LINE__);
        close(fd);
        return -8;
    }
#ifdef KEEPALIVE
    socksval = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (unsigned char*)&socksval, sizeof(socksval))) { // 启动tcp心跳包
        printf("set socket keepalive fail, fd:%d, in %s, at %d\n", fd, __FILE__, __LINE__);
        close(fd);
        return -9;
    }
    socksval = KEEPIDLE;
    if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, (unsigned char*)&socksval, sizeof(socksval))) { // 设置tcp心跳包参数
        printf("set socket keepidle fail, fd:%d, in %s, at %d\n", fd, __FILE__, __LINE__);
        close(fd);
        return -10;
    }
    socksval = KEEPINTVL;
    if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, (unsigned char*)&socksval, sizeof(socksval))) { // 设置tcp心跳包参数
        printf("set socket keepintvl fail, fd:%d, in %s, at %d\n", fd, __FILE__, __LINE__);
        close(fd);
        return -11;
    }
    socksval = KEEPCNT;
    if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, (unsigned char*)&socksval, sizeof(socksval))) { // 设置tcp心跳包参数
        printf("set socket keepcnt fail, fd:%d, in %s, at %d\n", fd, __FILE__, __LINE__);
        close(fd);
        return -12;
    }
#endif
    // 修改发送缓冲区大小
    socklen_t socksval_len = sizeof(socksval);
    if (getsockopt(fd, SOL_SOCKET, SO_SNDBUF, (unsigned char*)&socksval, &socksval_len)) {
        printf("get send buffer fail, fd:%d, in %s, at %d\n", fd,  __FILE__, __LINE__);
        close(fd);
        return -13;
    }
    printf("old send buffer is %d, socksval_len:%d, fd:%d, in %s, at %d\n", socksval, socksval_len, fd,  __FILE__, __LINE__);
    socksval = MAXDATASIZE - MTU_SIZE;
    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (unsigned char*)&socksval, sizeof(socksval))) {
        printf("set send buffer fail, fd:%d, in %s, at %d\n", fd,  __FILE__, __LINE__);
        close(fd);
        return -14;
    }
    socksval_len = sizeof(socksval);
    if (getsockopt(fd, SOL_SOCKET, SO_SNDBUF, (unsigned char*)&socksval, &socksval_len)) {
        printf("get send buffer fail, fd:%d, in %s, at %d\n", fd,  __FILE__, __LINE__);
        close(fd);
        return -15;
    }
    printf("new send buffer is %d, socksval_len:%d, fd:%d, in %s, at %d\n", socksval, socksval_len, fd,  __FILE__, __LINE__);
    // 修改接收缓冲区大小
    socksval_len = sizeof(socksval);
    if (getsockopt(fd, SOL_SOCKET, SO_RCVBUF, (unsigned char*)&socksval, &socksval_len)) {
        printf("get receive buffer fail, fd:%d, in %s, at %d\n", fd,  __FILE__, __LINE__);
        close(fd);
        return -16;
    }
    printf("old receive buffer is %d, len:%d, fd:%d, in %s, at %d\n", socksval, socksval_len, fd,  __FILE__, __LINE__);
    socksval = MAXDATASIZE - MTU_SIZE;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (unsigned char*)&socksval, sizeof(socksval))) {
        printf("set receive buffer fail, fd:%d, in %s, at %d\n", fd,  __FILE__, __LINE__);
        close(fd);
        return -17;
    }
    socksval_len = sizeof(socksval);
    if (getsockopt(fd, SOL_SOCKET, SO_RCVBUF, (unsigned char*)&socksval, &socksval_len)) {
        printf("get receive buffer fail, fd:%d, in %s, at %d\n", fd,  __FILE__, __LINE__);
        close(fd);
        return -18;
    }
    printf("new receive buffer is %d, socksval_len:%d, fd:%d, in %s, at %d\n", socksval, socksval_len, fd,  __FILE__, __LINE__);
    socketclient->fd = fd;
    socketclient->packagelisthead = NULL;
    socketclient->remainsize = 0;
    socketclient->canwrite = 1;
    if (addtoepoll(socketclient)) {
        printf("tapfd addtoepoll fail, fd:%d, in %s, at %d\n", fd,  __FILE__, __LINE__);
        close(fd);
        return -19;
    }
    return 0;
}

int removeclient (struct CLIENTLIST *client) {
    struct epoll_event ev;
    epoll_ctl(epollfd, EPOLL_CTL_DEL, client->fd, &ev);
    close(client->fd);
    for (struct PACKAGELIST *package = client->packagelisthead ; package != NULL ; package = package->tail) {
        package->tail = remainpackagelisthead;
        remainpackagelisthead = package;
    }
    if (client == socketclient) { // 常规情况
        do {
            sleep(RETRYINTERVAL);
            printf("try connect tcp socket again, in %s, at %d\n", __FILE__, __LINE__);
        }
        while (connect_socketfd(serverip, serverport));
    } else { // 基本不可能情况
        do {
            sleep(RETRYINTERVAL);
            printf("try connect tap driver again, in %s, at %d\n", __FILE__, __LINE__);
        }
        while (tap_alloc());
    }
    return 0;
}

int parseargs (int argc, char *argv[]) {
    strcpy(serverip, "192.168.56.101");
    serverport = 3480;
    strcpy(password, "vCIhnEMbk9wgK4uUxCptm4bFxAAkGdTs");
    for (int i = 1 ; i < argc ; i++) {
        if (!strcmp(argv[i], "-h")) {
            i++;
            if (strlen(argv[i]) >= 16) {
                printf("server ip too long, in %s, at %d\n",  __FILE__, __LINE__);
                return -1;
            }
            strcpy(serverip, argv[i]);
        } else if (!strcmp(argv[i], "-p")) {
            i++;
            serverport = atoi(argv[i]);
        } else if (!strcmp(argv[i], "-k")) {
            i++;
            if (strlen(argv[i]) != 32) {
                printf("access key must 32 bytes, in %s, at %d\n",  __FILE__, __LINE__);
                return -2;
            }
            strcpy(password, argv[i]);
        } else {
            printf("build time: %s %s\n", __DATE__, __TIME__);
            printf("-h server ip, not support domain, default is 192.168.56.101\n");
            printf("-p server port, default is 3480\n");
            printf("-k access key, default is vCIhnEMbk9wgK4uUxCptm4bFxAAkGdTs\n");
            return -3;
        }
    }
    return 0;
}

int main (int argc, char *argv[]) {
    if (parseargs (argc, argv)) {
        return -1;
    }
    srand(time(NULL));
    epollfd = epoll_create(MAX_EVENT);
    if (epollfd < 0) {
        printf("create epoll fd fail, in %s, at %d\n",  __FILE__, __LINE__);
        return -1;
    }
    if (tap_alloc()) {
        printf("alloc tap fail, in %s, at %d\n",  __FILE__, __LINE__);
        return -2;
    }
    if (connect_socketfd(serverip, serverport)) {
        printf("create socket fd fail, in %s, at %d\n",  __FILE__, __LINE__);
        return -3;
    }
    while (1) {
        static struct epoll_event evs[MAX_EVENT];
        static int wait_count;
        wait_count = epoll_wait(epollfd, evs, MAX_EVENT, -1);
        for (int i = 0 ; i < wait_count ; i++) {
            struct CLIENTLIST *client = evs[i].data.ptr;
            uint32_t events = evs[i].events;
            if (events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) { // 检测到数据异常
                printf ("receive error event, fd:%d, EPOLLERR:%d, EPOLLHUP:%d, EPOLLRDHUP:%d, in %s, at %d\n", client->fd, events&EPOLLERR ? 1 : 0, events&EPOLLHUP ? 1 : 0, events&EPOLLRDHUP ? 1 : 0,  __FILE__, __LINE__);
                removeclient(client);
            } else if (events & EPOLLIN) {
                if (readdata(client)) {
                    removeclient(client);
                }
            } else if (events & EPOLLOUT) {
                writenode(client);
            } else {
                printf("receive new event 0x%08x, in %s, at %d\n", evs[i].events,  __FILE__, __LINE__);
            }
        }
    }
    return 0;
}
