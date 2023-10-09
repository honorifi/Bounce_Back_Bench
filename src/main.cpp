#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <time.h>

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 8090

char SERVER_CERT[] = "./myCA/server-cert.pem";
char SERVER_KEY[] = "./myCA/server-key.pem";
char CLIENT_CERT[] = "./myCA/client-cert.pem";
char CLIENT_KEY[] = "./myCA/client-key.pem";

using namespace std;

void server(int repeat, int msg_size) {
    
    int sockfd;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(-1==sockfd){
        return;
        puts("Failed to create socket");
    }


    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;       // Use IPV4
    addr.sin_port = htons(SERVER_PORT);    //
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    // Time out
    // struct timeval tv;
    // tv.tv_sec  = 0;
    // tv.tv_usec = 200000;  // 200 ms
    // setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(struct timeval));

    if (bind(sockfd, (struct sockaddr*)&addr, addr_len) == -1){
        printf("Failed to bind socket on port %d\n", SERVER_PORT);
        close(sockfd);
        return ;
    }
    listen(sockfd, 1024);

    struct sockaddr_in clientAddr;
    socklen_t clientAddr_len = sizeof(clientAddr);
    memset(&clientAddr, 0, sizeof(clientAddr));

    char buffer[msg_size]; 
    memset(buffer, 0x3f, msg_size);
    int counter = 0;
    int conn_fd = accept(sockfd, (struct sockaddr *)&clientAddr, &clientAddr_len);
    printf("Communicate test begin...\n");
    while(counter < repeat){
        // block to recv msg
        recv(conn_fd, buffer, msg_size, 0);
        // buffer[1023] = 0;
        // printf("\rGet Message %d: %s", counter++, buffer);
        send(conn_fd, buffer, msg_size, 0);
        counter++;
    }
    close(conn_fd);

    close(sockfd);
}

void ssl_server(int repeat, int msg_size) {
    SSL_CTX *ctx;
    SSL *ssl;
  
    SSL_library_init();
    ctx = SSL_CTX_new(TLS_server_method());
    
    if (SSL_CTX_use_certificate_file(ctx, SERVER_CERT, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, SERVER_KEY, SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    if (!SSL_CTX_check_private_key(ctx)) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    
    int sockfd;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(-1==sockfd){
        return;
        puts("Failed to create socket");
    }


    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;       // Use IPV4
    addr.sin_port = htons(SERVER_PORT);    //
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    // Time out
    // struct timeval tv;
    // tv.tv_sec  = 0;
    // tv.tv_usec = 200000;  // 200 ms
    // setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(struct timeval));

    if (bind(sockfd, (struct sockaddr*)&addr, addr_len) == -1){
        printf("Failed to bind socket on port %d\n", SERVER_PORT);
        close(sockfd);
        return ;
    }
    listen(sockfd, 1024);

    struct sockaddr_in clientAddr;
    socklen_t clientAddr_len = sizeof(clientAddr);
    memset(&clientAddr, 0, sizeof(clientAddr));

    char buffer[msg_size]; 
    memset(buffer, 0x3f, msg_size);
    int counter = 0;
    int conn_fd = accept(sockfd, (struct sockaddr *)&clientAddr, &clientAddr_len);
    printf("Communicate test begin...\n");

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, conn_fd);
    if (SSL_accept(ssl) == -1) {
        ERR_print_errors_fp(stderr);
    } else {
        printf("TLS connection build......\n");
    }
    while(counter < repeat){
        // block to recv msg
        SSL_read(ssl, buffer, msg_size);
        // buffer[1023] = 0;
        // printf("\rGet Message %d: %s", counter++, buffer);
        SSL_write(ssl, buffer, msg_size);
        counter++;
    }
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);

    close(conn_fd);

    close(sockfd);
}

void client(int repeat, int msg_size) {
    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, SERVER_IP, &serverAddr.sin_addr);

    struct sockaddr_in clientAddr;
    socklen_t serverAddr_len = sizeof(serverAddr);

    char buffer[msg_size]; 
    memset(buffer, 0x3f, msg_size);
    int counter = 0;
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(-1==sockfd){
        return;
        puts("Failed to create socket");
    }
    connect(sockfd, (struct sockaddr *)&serverAddr, sizeof(serverAddr));
    printf("Communicate test begin...\n");

    while(counter < repeat){
        // buffer[1023] = 0;
        send(sockfd, buffer, msg_size, 0);
        recv(sockfd, buffer, msg_size, 0);
        counter++;
    }
    close(sockfd);
}

void ssl_client(int repeat, int msg_size) {
    SSL_CTX *ctx;
    SSL *ssl;
  
    SSL_library_init();
    ctx = SSL_CTX_new(TLS_client_method());
    
    if (SSL_CTX_use_certificate_file(ctx, CLIENT_CERT , SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, CLIENT_KEY, SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    if (!SSL_CTX_check_private_key(ctx)) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, SERVER_IP, &serverAddr.sin_addr);

    struct sockaddr_in clientAddr;
    socklen_t serverAddr_len = sizeof(serverAddr);

    char buffer[msg_size]; 
    memset(buffer, 0x3f, msg_size);
    int counter = 0;
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(-1==sockfd){
        return;
        puts("Failed to create socket");
    }
    connect(sockfd, (struct sockaddr *)&serverAddr, sizeof(serverAddr));
    printf("Communicate test begin...\n");

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);
    if (SSL_connect(ssl) == -1) {
        ERR_print_errors_fp(stderr);
    } else {
        printf("TLS connection build......\n");
    }
    while(counter < repeat){
        // buffer[1023] = 0;
        SSL_write(ssl, buffer, msg_size);
        SSL_read(ssl, buffer, msg_size);
        counter++;
    }
    close(sockfd);
}

int main(int argc, char* argv[]) {
    int rank = 0;
    if (argc > 1) {
        rank = atoi(argv[1]);
    }
    int repeat = 1;
    if (argc > 2) {
        repeat = atoi(argv[2]);
    }
    int msg_size;
    if (argc > 3) {
        msg_size = atoi(argv[3]);
    }
    printf("rank: %d, repeat: %dk msg_size: %dB\n", rank, repeat, msg_size);
    repeat *= 1024;

    clock_t start, end;
    start = clock();
    if (rank == 0) {
        server(repeat, msg_size);
    }else if (rank == 1){
        client(repeat, msg_size);
    }else if (rank == 2) {
        ssl_server(repeat, msg_size);
    }else {
        ssl_client(repeat, msg_size);
    }
    end = clock();
    double time_cost = double(end-start)/CLOCKS_PER_SEC;
    printf("\ntime cost: %f\n", time_cost);
    double Mbps = repeat / 1024.0 * 2 * 8 * msg_size / time_cost / 1024.0;
    printf("\nThroughput: %f Mbps\n", Mbps);
}