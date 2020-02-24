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

#define MAXDATASIZE       2*1024*1024
#define MAX_EVENT         1024
#define MAX_CONNECT       51200
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
    struct FDCLIENT *fdclient; // 与自己相关联的fdclient对象
    unsigned char mac[6]; // 该端口的源mac地址
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
    struct CLIENTLIST *hashhead; // 从哈希表中寻找上一个clientlist
    struct CLIENTLIST *hashtail; // 从哈希表中寻找下一个clientlist
    struct CLIENTLIST *head; // 从remainclientlist中寻找下一个可用的clientlist
    struct CLIENTLIST *tail; // 从remainclientlist中寻找下一个可用的clientlist
    struct CLIENTLIST *writetail; // 用于存储在readdata中发现有写入过程的node
};
struct CLIENTLIST *clientlisthead = NULL;
struct CLIENTLIST *remainclientlisthead = NULL;
struct CLIENTLIST *machashlist[65536]; // mac地址的hash表，用于快速找到对应的mac
struct CLIENTLIST *tapclient;
struct FDCLIENT {
    int fd;
    struct CLIENTLIST *client;
    struct FDCLIENT *tail; // 从remainclientlist中寻找下一个可用的clientlist
};
struct FDCLIENT *remainfdclienthead = NULL;
struct FDCLIENT *fdserver;
int epollfd;

unsigned int serverport; // 服务器的连接端口
unsigned char password[33]; // 密码固定为32位

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
    printf("tap device name is %s, tapfd %d, in %s, at %d\n", ifr.ifr_name, fd, __FILE__, __LINE__);
    if (remainclientlisthead) {
        tapclient = remainclientlisthead;
        remainclientlisthead = remainclientlisthead->tail;
    } else {
        tapclient = (struct CLIENTLIST*) malloc(sizeof(struct CLIENTLIST));
        if (tapclient == NULL) {
            printf("malloc fail, in %s, at %d\n",  __FILE__, __LINE__);
            close(fd);
            return -4;
        }
    }
    tapclient->fd = fd;
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
            return -5;
        }
    }
    tapclient->fdclient = fdclient;
    fdclient->fd = fd;
    fdclient->client = tapclient;
    if (addtoepoll(fdclient)) {
        printf("tapfd add to epoll fail, in %s, at %d\n",  __FILE__, __LINE__);
        fdclient->tail = remainfdclienthead;
        remainfdclienthead = fdclient;
        clientlisthead = clientlisthead->tail;
        tapclient->tail = remainclientlisthead;
        remainclientlisthead = tapclient;
        close(fd);
        return -6;
    }
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
    sin.sin_port = htons(serverport);
    if (bind(fd, (struct sockaddr*)&sin, sizeof(sin)) < 0) {
        printf("bind port %d fail, fd:%d, in %s, at %d\n", fd, serverport, __FILE__, __LINE__);
        close(fd);
        return -2;
    }
    if (listen(fd, MAX_CONNECT) < 0) {
        printf("listen port %d fail, fd:%d, in %s, at %d\n", fd, serverport, __FILE__, __LINE__);
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
    fdserver->client = NULL;
    if (addtoepoll(fdserver)) {
        printf("serverfd add to epoll fail, fd:%d, in %s, at %d\n", fd,  __FILE__, __LINE__);
        fdserver->tail = remainfdclienthead;
        remainfdclienthead = fdserver;
        return -6;
    }
    return 0;
}

int addclient (int serverfd) {
    struct sockaddr_in sin;
    socklen_t in_addr_len = sizeof(struct sockaddr_in);
    int fd = accept(serverfd, (struct sockaddr*)&sin, &in_addr_len);
    printf("new socket:%d, in %s, at %d\n", fd,  __FILE__, __LINE__);
    if (fd < 0) {
        printf("accept a new fd fail, fd:%d, in %s, at %d\n", fd,  __FILE__, __LINE__);
        return -1;
    }
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
#ifdef KEEPALIVE
    socksval = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (unsigned char*)&socksval, sizeof(socksval))) { // 启动tcp心跳包
        printf("set socket keepalive fail, fd:%d, in %s, at %d\n", fd, __FILE__, __LINE__);
        close(fd);
        return -4;
    }
    socksval = KEEPIDLE;
    if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, (unsigned char*)&socksval, sizeof(socksval))) { // 设置tcp心跳包参数
        printf("set socket keepidle fail, fd:%d, in %s, at %d\n", fd, __FILE__, __LINE__);
        close(fd);
        return -5;
    }
    socksval = KEEPINTVL;
    if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, (unsigned char*)&socksval, sizeof(socksval))) { // 设置tcp心跳包参数
        printf("set socket keepintvl fail, fd:%d, in %s, at %d\n", fd, __FILE__, __LINE__);
        close(fd);
        return -6;
    }
    socksval = KEEPCNT;
    if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, (unsigned char*)&socksval, sizeof(socksval))) { // 设置tcp心跳包参数
        printf("set socket keepcnt fail, fd:%d, in %s, at %d\n", fd, __FILE__, __LINE__);
        close(fd);
        return -7;
    }
#endif
    // 修改发送缓冲区大小
    socklen_t socksval_len = sizeof(socksval);
    if (getsockopt(fd, SOL_SOCKET, SO_SNDBUF, (unsigned char*)&socksval, &socksval_len)) {
        printf("get send buffer fail, fd:%d, in %s, at %d\n", fd,  __FILE__, __LINE__);
        close(fd);
        return -8;
    }
    printf("old send buffer is %d, socksval_len:%d, fd:%d, in %s, at %d\n", socksval, socksval_len, fd,  __FILE__, __LINE__);
    socksval = MAXDATASIZE;
    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (unsigned char*)&socksval, sizeof (socksval))) {
        printf("set send buffer fail, fd:%d, in %s, at %d\n", fd,  __FILE__, __LINE__);
        close(fd);
        return -9;
    }
    socksval_len = sizeof(socksval);
    if (getsockopt(fd, SOL_SOCKET, SO_SNDBUF, (unsigned char*)&socksval, &socksval_len)) {
        printf("get send buffer fail, fd:%d, in %s, at %d\n", fd,  __FILE__, __LINE__);
        close(fd);
        return -10;
    }
    printf("new send buffer is %d, socksval_len:%d, fd:%d, in %s, at %d\n", socksval, socksval_len, fd,  __FILE__, __LINE__);
    // 修改接收缓冲区大小
    socksval_len = sizeof(socksval);
    if (getsockopt(fd, SOL_SOCKET, SO_RCVBUF, (unsigned char*)&socksval, &socksval_len)) {
        printf("get receive buffer fail, fd:%d, in %s, at %d\n", fd,  __FILE__, __LINE__);
        close(fd);
        return -11;
    }
    printf("old receive buffer is %d, socksval_len:%d, fd:%d, in %s, at %d\n", socksval, socksval_len, fd,  __FILE__, __LINE__);
    socksval = MAXDATASIZE;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (char*)&socksval, sizeof(socksval))) {
        printf("set receive buffer fail, fd:%d, in %s, at %d\n", fd,  __FILE__, __LINE__);
        close(fd);
        return -12;
    }
    socksval_len = sizeof(socksval);
    if (getsockopt(fd, SOL_SOCKET, SO_RCVBUF, (unsigned char*)&socksval, &socksval_len)) {
        printf("get receive buffer fail, fd:%d, in %s, at %d\n", fd,  __FILE__, __LINE__);
        close(fd);
        return -13;
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
            return -14;
        }
    }
    fdclient->fd = fd;
    fdclient->client = NULL;
    if (addtoepoll(fdclient)) {
        printf("add to epoll fail, fd:%d, in %s, at %d\n", fd,  __FILE__, __LINE__);
        fdclient->tail = remainfdclienthead;
        remainfdclienthead = fdclient;
        close(fd);
        return -15;
    }
    return 0;
}

int removeclient (struct FDCLIENT *fdclient) {
    struct epoll_event ev;
    epoll_ctl(epollfd, EPOLL_CTL_DEL, fdclient->fd, &ev);
    close(fdclient->fd);
    struct CLIENTLIST *client = fdclient->client;
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
        do {
            sleep(RETRYINTERVAL);
            printf("try connect tap driver again, in %s, at %d\n", __FILE__, __LINE__);
        }
        while(tap_alloc());
    }
    return 0;
}

int writenode (struct CLIENTLIST *writeclient) {
    for (struct CLIENTLIST *client = writeclient ; client != NULL ; client = client->writetail) {
        struct PACKAGELIST *package = client->packagelisthead;
        client->packagelisthead = NULL;
        while (package) {
            ssize_t len = write(client->fd, package->data, package->size);
            if (len < package->size) { // 缓冲区不足，已无法继续写入数据。
                if (len < 0) {
                    printf("errno:%d, in %s, at %d\n", errno,  __FILE__, __LINE__);
                    if (client == tapclient) {
                        perror("tap write error");
                    } else {
                        perror("socket write error");
                    }
                    client->packagelisthead = package;
                    if (errno == 104) {
                        removeclient(client->fdclient);
                        return -1;
                    }
                    break;
                }
                int size = package->size - len;
                unsigned char tmpdata[MTU_SIZE + 18];
                memcpy(tmpdata, package->data + len, size);
                memcpy(package->data, tmpdata, size);
                package->size = size;
                client->packagelisthead = package;
                if (client->canwrite) { // 之前缓冲区是可以写入的，现在不行了
                    if (modepoll(client->fdclient, EPOLLOUT)) { // 监听可写事件
                        printf("modepoll fail, in %s, at %d\n",  __FILE__, __LINE__);
                        break;
                    }
                    client->canwrite = 0;
                }
                break;
            } else if (client->canwrite == 0) { // 缓冲区尚有空间，并且之前已经提示不足
                if (modepoll(client->fdclient, 0)) { // 取消监听可写事件
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
        if (targetclient->canwrite) {
            targetclient->writetail = writeclient;
            writeclient = targetclient;
        }
    }
    return writeclient;
}

int readdata (struct FDCLIENT *fdclient) {
    unsigned char readbuf[MAXDATASIZE]; // 这里使用static关键词是为了将数据存储与数据段，减小对栈空间的压力。
    static unsigned char *readbuff = NULL; // 这里是用于存储全部的需要写入的数据buf，
    static unsigned int maxtotalsize = 0;
    int fd = fdclient->fd;
    struct CLIENTLIST *sourceclient = fdclient->client;
    ssize_t len;
    if (sourceclient == tapclient) { // tap驱动，原始数据，需要自己额外添加数据包长度。
        len = read(fd, readbuf + 2, MAXDATASIZE); // 这里最大只可能是1518
        if (len < 0) {
            printf("errno:%d, in %s, at %d\n", errno,  __FILE__, __LINE__);
            perror("tap read error");
            removeclient(fdclient);
            return -1;
        }
        readbuf[0] = len >> 8;
        readbuf[1] = len & 0xff;
        len += 2;
    } else { // 网络套接字。
        len = read(fd, readbuf, MAXDATASIZE);
        if (len < 0) {
            printf("errno:%d, in %s, at %d\n", errno,  __FILE__, __LINE__);
            perror("socket read error");
            removeclient(fdclient);
            return -2;
        }
        if (sourceclient) {
            decrypt(sourceclient, readbuf, len);
        }
    }
    int32_t offset = 0;
    if (sourceclient == NULL) { // 用户没有找到
        if (len < 9 + sizeof(password) - 1) {
            printf("len abnormal, in %s, at %d\n",  __FILE__, __LINE__);
            removeclient(fdclient);
            return -3;
        }
        if (readbuf[0] != 0x00 || readbuf[1] != 0x00 || readbuf[2] != 0x00) { // 前两个字节为0代表特殊命令，单独处理。第三个字节为0代表注册。
            printf("just can run login, in %s, at %d\n",  __FILE__, __LINE__);
            removeclient(fdclient);
            return -4;
        }
        if (memcmp(readbuf + 9, password, sizeof(password)-1)) { // 绑定密码错误
            printf("password check fail, in %s, at %d\n",  __FILE__, __LINE__);
            removeclient(fdclient);
            return -5;
        }
        if (remainclientlisthead) {
            sourceclient = remainclientlisthead;
            remainclientlisthead = remainclientlisthead->tail;
        } else {
            sourceclient = (struct CLIENTLIST*) malloc(sizeof(struct CLIENTLIST));
            if (sourceclient == NULL) {
                printf("malloc fail, in %s, at %d\n",  __FILE__, __LINE__);
                removeclient(fdclient);
                return -6;
            }
        }
        if (readbuf[3] >= 4 || readbuf[6] >= 4) {
            printf("send crypt type or receive crypt type error in %s, at %d\n",  __FILE__, __LINE__);
            removeclient(fdclient);
            return -7;
        }
        sourceclient->sendcrypt = readbuf[3];
        sourceclient->sendk = readbuf[4];
        sourceclient->sendb = readbuf[5];
        sourceclient->receivecrypt = readbuf[6];
        sourceclient->receivek = readbuf[7];
        sourceclient->receiveb = readbuf[8];
        unsigned char data[1];
        data[0] = 0x01;
        ssize_t wlen = write(fd, data, sizeof(data));
        if (wlen != sizeof(data)) {
            printf("write encrypt data fail, in %s, at %d\n",  __FILE__, __LINE__);
            removeclient(fdclient);
            return -8;
        }
        sourceclient->fd = fd;
        memset(sourceclient->mac, 0, 6);
        sourceclient->fdclient = fdclient;
        sourceclient->packagelisthead = NULL;
        sourceclient->remainsize = 0;
        sourceclient->canwrite = 1;
        sourceclient->head = NULL;
        if (clientlisthead) {
            clientlisthead->head = sourceclient;
        }
        sourceclient->tail = clientlisthead;
        clientlisthead = sourceclient;
        fdclient->client = sourceclient;
        offset += 9 + sizeof(password) - 1; // 绑定包长度
        printf("add client success, fd:%d, in %s, at %d\n", fd,  __FILE__, __LINE__);
        decrypt(sourceclient, readbuf + offset, len - offset);
    }
    int32_t totalsize;
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
        int packagesize = 256 * buff[offset] + buff[offset+1] + 2; // 当前数据帧大小
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

int parseargs (int argc, char *argv[]) {
    serverport = 3480;
    strcpy(password, "vCIhnEMbk9wgK4uUxCptm4bFxAAkGdTs");
    for (int i = 1 ; i < argc ; i++) {
        if (!strcmp(argv[i], "-p")) {
            i++;
            serverport = atoi(argv[i]);
        } else if (!strcmp(argv[i], "-k")) {
            i++;
            if (strlen(argv[i]) != 32) {
                printf("access key must 32 bytes, in %s, at %d\n",  __FILE__, __LINE__);
                return -1;
            }
            strcpy(password, argv[i]);
        } else {
            printf("build time: %s %s\n", __DATE__, __TIME__);
            printf("-p server port, default is 3480\n");
            printf("-k access key, default is vCIhnEMbk9wgK4uUxCptm4bFxAAkGdTs\n");
            return -2;
        }
    }
    return 0;
}

int main (int argc, char *argv[]) {
    if (parseargs (argc, argv)) {
        return -1;
    }
    for (int i = 0 ; i < 4096 ; i++) {
        machashlist[i] = NULL;
    }
    epollfd = epoll_create(MAX_EVENT);
    printf("epollfd:%d, in %s, at %d\n", epollfd, __FILE__, __LINE__);
    if (epollfd < 0) {
        printf("create epoll fd fail, in %s, at %d\n",  __FILE__, __LINE__);
        return -1;
    }
    if (tap_alloc()) {
        printf("alloc tap fail, in %s, at %d\n",  __FILE__, __LINE__);
        return -2;
    }
    if (create_socketfd(serverport)) {
        printf("create socket fd fail, in %s, at %d\n",  __FILE__, __LINE__);
        return -3;
    }
    printf("init finish, server port is %d password is %s, in %s, at %d\n", serverport, password,  __FILE__, __LINE__);
    while (1) {
        static struct epoll_event evs[MAX_EVENT];
        static int wait_count;
        wait_count = epoll_wait(epollfd, evs, MAX_EVENT, -1);
        for (int i = 0 ; i < wait_count ; i++) {
            struct FDCLIENT *fdclient = evs[i].data.ptr;
            uint32_t events = evs[i].events;
            if (events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) { // 检测到数据异常
                printf("connect lose, fd:%d, EPOLLERR:%d, EPOLLHUP:%d, EPOLLRDHUP:%d, in %s, at %d\n", fdclient->fd, events&EPOLLERR ? 1 : 0, events&EPOLLHUP ? 1 : 0, events&EPOLLRDHUP ? 1 : 0, __FILE__, __LINE__);
                removeclient(fdclient);
                continue;
            } else if (fdclient == fdserver) {
                addclient(fdclient->fd);
            } else if (events & EPOLLIN) { // 数据可读
                readdata(fdclient);
            } else if (events & EPOLLOUT) { // 数据可写
                fdclient->client->writetail = NULL;
                writenode(fdclient->client);
            } else {
                printf("receive new event 0x%08x, in %s, at %d\n", events,  __FILE__, __LINE__);
            }
        }
    }
    return 0;
}
