#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <time.h>
#include <openssl/md5.h>
#include <sys/un.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#define MAX_MSG_LEN 1024
#define FILE_SIZE 104857600
#define CHUNK_SIZE 15000
#define UDS_D_PATH "/tmp/uds_dgram_socket2"
#define UDS_S_PATH "/tmp/uds_stream_socket3"

void gen_file()
{
    FILE *file;
    char *buffer;
    size_t i;

    // Allocate memory for the buffer
    buffer = (char *)malloc(FILE_SIZE * sizeof(char));
    if (buffer == NULL)
    {
        printf("Memory allocation failed.\n");
        return;
    }

    // Open the file in binary write mode
    file = fopen("100MB.bin", "wb");
    if (file == NULL)
    {
        printf("Failed to open the file.\n");
        return;
    }

    // Generate random data and write it to the file
    srand(time(NULL));
    for (i = 0; i < FILE_SIZE; i++)
    {
        buffer[i] = rand() % 256; // Generate random byte (0-255)
    }

    fwrite(buffer, sizeof(char), FILE_SIZE, file);

    // Close the file and free the buffer memory
    fclose(file);
    free(buffer);
}

void checksum(const char *filename)
{
    FILE *f = fopen(filename, "rb");
    if (f == NULL)
    {
        perror("Error opening file");
        exit(1);
    }

    unsigned char hash[16];
    int i;
    unsigned char buffer[CHUNK_SIZE];
    memset(hash, 0, sizeof(hash));
    while ((i = fread(buffer, 1, sizeof(buffer), f)) > 0)
    {
        // Calculate checksum using some hashing algorithm
        // Here, we're just summing up the bytes in the buffer
        for (int j = 0; j < i; j++)
        {
            hash[j % 16] += buffer[j];
        }
    }

    printf("Checksum for file '%s': ", filename);
    for (i = 0; i < 16; i++)
    {
        printf("%02x", hash[i]);
    }
    printf("\n");
    fclose(f);
}

void tcp_ipv4_server(int port)
{
    printf("in tcp_ipv4_server\n");
    int sock_tcp_ipv4 = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_tcp_ipv4 < 0)
    {
        perror("socket");
        exit(1);
    }

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(port);

    if (bind(sock_tcp_ipv4, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        perror("bind");
        exit(1);
    }

    if (listen(sock_tcp_ipv4, 1) < 0)
    {
        perror("listen");
        exit(1);
    }

    printf("Listening in tcp_ipv4 on port %d\n", port);

    int conn_tcp_ipv4 = accept(sock_tcp_ipv4, NULL, NULL);
    if (conn_tcp_ipv4 < 0)
    {
        perror("accept");
        exit(1);
    }

    printf("Client connected\n");

    char buf[CHUNK_SIZE];

    int buffer_size = FILE_SIZE;
    FILE *f = fopen("tcp_ipv4", "wb");
    fclose(f);
    f = fopen("tcp_ipv4", "ab");
    printf("open a file\n");
    int receive;
    clock_t start_time = clock();

    while (buffer_size)
    {
        while ((receive = (recv(conn_tcp_ipv4, buf, CHUNK_SIZE, MSG_DONTWAIT))) <= 0)
        {
            if (buffer_size == FILE_SIZE)
                start_time = clock();
            else
                break;
        }
        fwrite(buf, 1, receive, f);
        buffer_size -= receive;
        memset(buf, 0, CHUNK_SIZE);
        printf("");
    }
    clock_t end_time = clock();
    fflush(stdout);
    double elapsed_time = (double)(end_time - start_time) / CLOCKS_PER_SEC;
    printf("IPv4 tcp, %f\n", elapsed_time * 1000);

    char *filename = "tcp_ipv4";
    checksum(filename);
    fclose(f);
    close(conn_tcp_ipv4);
    fflush(stdout);
}

void tcp_ipv4_client(const char *ip, int port)
{
    printf("tcp_ipv4_client - 1\n");
    fflush(stdout);
    int sock_tcp_ipv4 = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_tcp_ipv4 < 0)
    {
        perror("socket");
        exit(1);
    }
    printf("tcp_ipv4_client with port %d\n", port);
    struct sockaddr_in serv_addr_4;
    memset(&serv_addr_4, 0, sizeof(serv_addr_4));
    serv_addr_4.sin_family = AF_INET;
    serv_addr_4.sin_addr.s_addr = inet_addr(ip);
    serv_addr_4.sin_port = htons(port);

    if (connect(sock_tcp_ipv4, (struct sockaddr *)&serv_addr_4, sizeof(serv_addr_4)) < 0)
    {
        perror("connect");
        exit(1);
    }

    printf("Connected to server in tcp_ipv4 at %s: %d\n", ip, port);

    int read;
    char buffer[CHUNK_SIZE];
    FILE *f = fopen("100MB.bin", "rb");
    char *filename = "100MB.bin";
    checksum(filename);
    printf("open a file\n");

    while ((read = fread(buffer, 1, CHUNK_SIZE, f)) > 0)
    {
        if (send(sock_tcp_ipv4, buffer, read, 0) < 0)
        {
            printf("Error sending data\n");
            exit(1);
        }
        // printf("sent %d\n", read);
    }
    printf("sent a file\n");
    fclose(f);
    close(sock_tcp_ipv4);
}

void udp_ipv4_server(int port)
{
    printf("in udp_ipv4_server\n");
    struct sockaddr_in serv_addr, cli_addr;
    socklen_t cli_addr_len = sizeof(cli_addr);
    int sock_udp_ipv4 = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_udp_ipv4 < 0)
    {
        perror("socket");
        exit(1);
    }

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(port);

    if (bind(sock_udp_ipv4, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        perror("bind");
        exit(1);
    }

    printf("Client connected\n");

    char buf[CHUNK_SIZE];
    int i = 6966;
    FILE *f = fopen("udp_ipv4", "wb");
    fclose(f);
    f = fopen("udp_ipv4", "ab");
    printf("open a file\n");
    int receive;
    clock_t start_time = clock();

    while (i)
    {
        while (receive = (recvfrom(sock_udp_ipv4, buf, (CHUNK_SIZE + 500), MSG_DONTWAIT, (struct sockaddr *)&cli_addr, &cli_addr_len)) <= 0)
        {
            if (i == 6966)
                start_time = clock();
            else
                break;
        }
        fwrite(buf, 1, receive, f);
        i--;
    }
    clock_t end_time = clock();

    double elapsed_time = (double)(end_time - start_time) / CLOCKS_PER_SEC;
    printf("IPv4 udp, %f\n", elapsed_time * 1000);

    char *filename = "udp_ipv4";
    checksum(filename);
    fclose(f);
    close(sock_udp_ipv4);
}

void udp_ipv4_client(const char *ip, int port)
{
    struct sockaddr_in servaddr;
    int sock_udp_ipv4 = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_udp_ipv4 < 0)
    {
        perror("socket");
        exit(1);
    }
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(ip);
    serv_addr.sin_port = htons(port);

    printf("Connected to server in udp_ipv4 at %s:%d\n", ip, port);

    int read;
    char buffer[CHUNK_SIZE];
    FILE *f = fopen("100MB.bin", "rb");
    char *filename = "100MB.bin";
    checksum(filename);
    printf("Opened file '%s'\n", filename);

    sleep(2);
    while ((read = fread(buffer, 1, CHUNK_SIZE, f)) > 0)
    {
        // sleep(0.1);
        if (sendto(sock_udp_ipv4, buffer, read, 0, (const struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
        {
            perror("sendto");
            exit(1);
        }
    }
    printf("Sent file '%s'\n", filename);
    fclose(f);
    close(sock_udp_ipv4);
}

void tcp_ipv6_server(int port)
{
    printf("in tcp_ipv6_server\n");
    int sock_tcp_ipv6 = socket(AF_INET6, SOCK_STREAM, 0);
    if (sock_tcp_ipv6 < 0)
    {
        perror("socket");
        exit(1);
    }

    struct sockaddr_in6 serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin6_family = AF_INET6;
    serv_addr.sin6_addr = in6addr_any;
    serv_addr.sin6_port = htons(port);

    if (bind(sock_tcp_ipv6, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        perror("bind");
        exit(1);
    }

    if (listen(sock_tcp_ipv6, 1) < 0)
    {
        perror("listen");
        exit(1);
    }

    printf("Listening in tcp_ipv6 on port %d\n", port);

    int conn_tcp_ipv6 = accept(sock_tcp_ipv6, NULL, NULL);
    if (conn_tcp_ipv6 < 0)
    {
        perror("accept");
        exit(1);
    }

    printf("Client connected\n");

    char buf[CHUNK_SIZE];

    int buffer_size = FILE_SIZE;
    FILE *f = fopen("tcp_ipv6", "wb");
    fclose(f);
    f = fopen("tcp_ipv6", "ab");
    printf("open a file\n");
    int receive;
    clock_t start_time = clock();

    while (buffer_size)
    {
        while ((receive = (recv(conn_tcp_ipv6, buf, CHUNK_SIZE, MSG_DONTWAIT))) <= 0)
        {
            if (buffer_size == FILE_SIZE)
                start_time = clock();
            else
                break;
        }

        fwrite(buf, 1, receive, f);
        buffer_size -= receive;
    }
    clock_t end_time = clock();

    double elapsed_time = (double)(end_time - start_time) / CLOCKS_PER_SEC;
    printf("IPv6 tcp, %f\n", elapsed_time * 1000);

    char *filename = "tcp_ipv6";
    checksum(filename);
    fclose(f);
    close(conn_tcp_ipv6);
}

void tcp_ipv6_client(const char *ip, int port)
{
    printf("tcp_ipv6_client - 1\n");
    fflush(stdout);
    int sock_tcp_ipv6 = socket(AF_INET6, SOCK_STREAM, 0);
    if (sock_tcp_ipv6 < 0)
    {
        perror("socket");
        exit(1);
    }
    printf("tcp_ipv6_client with port %d\n", port);
    struct sockaddr_in6 serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin6_family = AF_INET6;
    inet_pton(AF_INET6, ip, &(serv_addr.sin6_addr));
    serv_addr.sin6_port = htons(port);

    if (connect(sock_tcp_ipv6, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        perror("connect");
        exit(1);
    }

    printf("Connected to server in tcp_ipv6 at %s: %d\n", ip, port);

    int read;
    char buffer[CHUNK_SIZE];
    FILE *f = fopen("100MB.bin", "rb");
    char *filename = "100MB.bin";
    checksum(filename);
    printf("open a file\n");

    while ((read = fread(buffer, 1, CHUNK_SIZE, f)) > 0)
    {
        if (send(sock_tcp_ipv6, buffer, read, 0) < 0)
        {
            printf("Error sending data\n");
            exit(1);
        }
        // printf("sent %d\n", read);
    }
    printf("sent a file\n");
    fclose(f);
    close(sock_tcp_ipv6);
}

void udp_ipv6_server(int port)
{
    printf("in udp_ipv6_server\n");
    struct sockaddr_in6 serv_addr, cli_addr;
    socklen_t cli_addr_len = sizeof(cli_addr);
    int sock_udp_ipv6 = socket(AF_INET6, SOCK_DGRAM, 0);
    if (sock_udp_ipv6 < 0)
    {
        perror("socket");
        exit(1);
    }

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin6_family = AF_INET6;
    serv_addr.sin6_addr = in6addr_any;
    serv_addr.sin6_port = htons(port);

    if (bind(sock_udp_ipv6, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        perror("bind");
        exit(1);
    }

    printf("Client connected\n");

    char buf[CHUNK_SIZE];
    int i = 6966;
    FILE *f = fopen("udp_ipv6", "wb");
    fclose(f);
    f = fopen("udp_ipv6", "ab");
    printf("open a file\n");
    int receive;
    clock_t start_time = clock();

    while (i)
    {
        while (receive = (recvfrom(sock_udp_ipv6, buf, (CHUNK_SIZE + 500), MSG_DONTWAIT, (struct sockaddr *)&cli_addr, &cli_addr_len)) <= 0)
        {
            if (i == 6966)
                start_time = clock();
            else
                break;
        }
        fwrite(buf, 1, receive, f);
        i--;
    }
    clock_t end_time = clock();

    double elapsed_time = (double)(end_time - start_time) / CLOCKS_PER_SEC;
    printf("IPv6 udp, %f\n", elapsed_time * 1000);

    char *filename = "udp_ipv6";
    checksum(filename);
    fclose(f);
    close(sock_udp_ipv6);
}

void udp_ipv6_client(const char *ip, int port)
{
    struct sockaddr_in6 servaddr;
    int sock_udp_ipv6 = socket(AF_INET6, SOCK_DGRAM, 0);
    if (sock_udp_ipv6 < 0)
    {
        perror("socket");
        exit(1);
    }
    struct sockaddr_in6 serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin6_family = AF_INET6;
    inet_pton(AF_INET6, ip, &serv_addr.sin6_addr);
    serv_addr.sin6_port = htons(port);

    printf("Connected to server in udp_ipv6 at %s:%d\n", ip, port);

    int read;
    char buffer[CHUNK_SIZE];
    FILE *f = fopen("100MB.bin", "rb");
    char *filename = "100MB.bin";
    checksum(filename);
    printf("Opened file '%s'\n", filename);

    sleep(2);
    while ((read = fread(buffer, 1, CHUNK_SIZE, f)) > 0)
    {
        // sleep(0.1);
        if (sendto(sock_udp_ipv6, buffer, read, 0, (const struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
        {
            perror("sendto");
            exit(1);
        }
    }
    printf("Sent file '%s'\n", filename);
    fclose(f);
    close(sock_udp_ipv6);
}

void uds_dgram_server()
{
    printf("in uds_dgram_server\n");
    struct sockaddr_un serv_addr_uds, cli_addr;
    socklen_t cli_addr_len = sizeof(cli_addr);
    int sock_uds_dgram = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (sock_uds_dgram < 0)
    {
        perror("socket");
        exit(1);
    }

    memset(&serv_addr_uds, 0, sizeof(serv_addr_uds));
    serv_addr_uds.sun_family = AF_UNIX;
    strncpy(serv_addr_uds.sun_path, UDS_D_PATH, sizeof(serv_addr_uds.sun_path) - 1);

    if (bind(sock_uds_dgram, (struct sockaddr *)&serv_addr_uds, sizeof(serv_addr_uds)) < 0)
    {
        perror("bind");
        close(sock_uds_dgram);
        exit(1);
    }

    printf("Client connected\n");

    char buf[CHUNK_SIZE];
    int i = 500000;
    FILE *f = fopen("uds_dgram", "wb");
    fclose(f);
    f = fopen("uds_dgram", "ab");
    printf("open a file\n");
    int receive;
    int buffer_size = FILE_SIZE;
    sleep(1);
    clock_t start_time = clock();

    while (i)
    {
        while (receive = (recvfrom(sock_uds_dgram, buf, (CHUNK_SIZE), MSG_DONTWAIT, (struct sockaddr *)&cli_addr, &cli_addr_len)) <= 0)
        {
            if (i == 500000)
                start_time = clock();
            else
                break;
        }
        fwrite(buf, 1, receive, f);
        i--;
    }
    clock_t end_time = clock();

    double elapsed_time = (double)(end_time - start_time) / CLOCKS_PER_SEC;
    printf("UDS datagram, %f\n", elapsed_time * 1000);

    char *filename = "uds_dgram";
    checksum(filename);
    // sleep(10);
    fclose(f);
    close(sock_uds_dgram);
}

void uds_dgram_client()
{
    struct sockaddr_un servaddr;
    int sock_uds_dgram = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (sock_uds_dgram < 0)
    {
        perror("socket");
        exit(1);
    }
    struct sockaddr_un serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sun_family = AF_UNIX;
    strncpy(serv_addr.sun_path, UDS_D_PATH, sizeof(serv_addr.sun_path) - 1);

    printf("Connected to server in uds_dgram\n");

    int read;
    char buffer[CHUNK_SIZE];
    FILE *f = fopen("100MB.bin", "rb");
    char *filename = "100MB.bin";
    checksum(filename);
    printf("Opened file '%s'\n", filename);
    int i = 1;

    sleep(2);
    while ((read = fread(buffer, 1, CHUNK_SIZE, f)) > 0)
    {
        if (sendto(sock_uds_dgram, buffer, read, 0, (const struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
        {
            perror("sendto");
            exit(1);
        }
        i++;
    }
    printf("Sent file '%s'\n", filename);
    fclose(f);
    close(sock_uds_dgram);
}

void uds_stream_server()
{
    printf("in uds_stream_server\n");
    struct sockaddr_un serv_addr_uds, cli_addr;
    socklen_t cli_addr_len = sizeof(cli_addr);
    int sock_uds_stream = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock_uds_stream < 0)
    {
        perror("socket");
        exit(1);
    }

    memset(&serv_addr_uds, 0, sizeof(serv_addr_uds));
    serv_addr_uds.sun_family = AF_UNIX;
    strncpy(serv_addr_uds.sun_path, UDS_S_PATH, sizeof(serv_addr_uds.sun_path) - 1);

    if (bind(sock_uds_stream, (struct sockaddr *)&serv_addr_uds, sizeof(serv_addr_uds)) < 0)
    {
        perror("bind");
        close(sock_uds_stream);
        exit(1);
    }

    printf("Client connected\n");

    char buf[CHUNK_SIZE];
    int i = 500000;
    FILE *f = fopen("uds_stream", "wb");
    fclose(f);
    f = fopen("uds_stream", "ab");
    printf("open a file\n");
    int receive;
    int buffer_size = FILE_SIZE;
    sleep(1);
    clock_t start_time = clock();

    if (listen(sock_uds_stream, 1) < 0)
    {
        perror("listen");
        close(sock_uds_stream);
        exit(1);
    }

    int conn_sock = accept(sock_uds_stream, NULL, NULL);
    if (conn_sock < 0)
    {
        perror("accept");
        close(sock_uds_stream);
        exit(1);
    }

    while (i)
    {
        while (receive = (recv(conn_sock, buf, (CHUNK_SIZE), MSG_DONTWAIT)) <= 0)
        {
            if (i == 500000)
                start_time = clock();
            else
                break;
        }
        fwrite(buf, 1, receive, f);
        i--;
    }
    clock_t end_time = clock();

    double elapsed_time = (double)(end_time - start_time) / CLOCKS_PER_SEC;
    printf("UDS stream, %f\n", elapsed_time * 1000);

    char *filename = "uds_stream";
    checksum(filename);
    // sleep(10);
    fclose(f);
    close(conn_sock);
    close(sock_uds_stream);
}

void uds_stream_client()
{
    struct sockaddr_un serv_addr;
    int sock_uds_stream = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock_uds_stream < 0)
    {
        perror("socket");
        exit(1);
    }
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sun_family = AF_UNIX;
    strncpy(serv_addr.sun_path, UDS_S_PATH, sizeof(serv_addr.sun_path) - 1);

    sleep(1);
    if (connect(sock_uds_stream, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        perror("connect");
        exit(1);
    }

    printf("Connected to server in uds_stream\n");

    int read_bytes;
    char buffer[CHUNK_SIZE];
    FILE *f = fopen("100MB.bin", "rb");
    char *filename = "100MB.bin";
    checksum(filename);
    printf("Opened file '%s'\n", filename);

    sleep(2);
    while ((read_bytes = fread(buffer, 1, CHUNK_SIZE, f)) > 0)
    {
        int sent_bytes = send(sock_uds_stream, buffer, read_bytes, 0);
        if (sent_bytes < 0)
        {
            perror("send");
            exit(1);
        }
        else if (sent_bytes != read_bytes)
        {
            printf("Incomplete write to socket\n");
            exit(1);
        }
    }
    printf("Sent file '%s'\n", filename);
    fclose(f);
    close(sock_uds_stream);
}

void mmap_server(char *filename)
{
    int fd = open(filename, O_RDWR | O_CREAT, 0666); // create file with read/write permissions
    if (fd == -1)
    {
        perror("open");
        exit(1);
    }

    // Set the file size
    if (ftruncate(fd, FILE_SIZE) == -1)
    {
        perror("ftruncate");
        exit(1);
    }

    // Map the file into memory
    void *addr = mmap(NULL, FILE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (addr == MAP_FAILED)
    {
        perror("mmap");
        exit(1);
    }

    // Wait for the client to write data to the mapped memory
    while (strcmp((char *)addr, "ACK") != 0)
    {
        sleep(1);
    }

    // Write the data from the mapped memory to a new file
    int new_fd = open("mmp.bin", O_WRONLY | O_CREAT, 0666); // create output file with write permissions

    clock_t start_time = clock();
    if (new_fd == -1)
    {
        perror("open");
        exit(1);
    }
    if (write(new_fd, addr, FILE_SIZE) == -1)
    {
        perror("write");
        exit(1);
    }
    clock_t end_time = clock();

    double elapsed_time = (double)(end_time - start_time) / CLOCKS_PER_SEC;
    printf("MMAP, %f\n", elapsed_time * 1000);
    checksum ("mmp.bin");

    // Unmap the memory and close the files
    if (munmap(addr, FILE_SIZE) == -1)
    {
        perror("munmap");
        exit(1);
    }
    close(fd);
    close(new_fd);
}

void mmap_client(const char *filename)
{
    printf("filename = %s\n", filename);
    fflush(stdout);

    int fd = open("mmap", O_RDWR, S_IRUSR | S_IWUSR); // open file with read permissions
    if (fd == -1)
    {
        perror("open");
        exit(1);
    }

    // Map the file into memory
    char *addr = mmap(NULL, FILE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (addr == MAP_FAILED)
    {
        perror("mmap");
        exit(1);
    }

    // Read the data from the file into the mapped memory
    char buffer[CHUNK_SIZE];
    FILE *f = fopen(filename, "rb");
    if (f == NULL)
    {
        perror("open");
        exit(1);
    }

    while (fread(buffer, 1, CHUNK_SIZE, f) > 0)
    {
        memcpy(addr, buffer, CHUNK_SIZE);
    }

    // Signal the server that the data has been written to the mapped memory
    strcpy((char *)addr, "ACK");

    // Unmap the memory and close the file
    if (munmap(addr, FILE_SIZE) == -1)
    {
        perror("munmap");
        exit(1);
    }
    close(fd);
}

void run_client(char *ip, int port, int flag, const char *type, const char *param)
{
    char *ip_6 = ip;
    if (flag && (strcmp(type, "ipv6") == 0))
    {
        struct sockaddr_in6 serv_addr_6;
        memset(&serv_addr_6, 0, sizeof(serv_addr_6));
        serv_addr_6.sin6_family = AF_INET6;
        int result_6 = inet_pton(AF_INET6, ip, &serv_addr_6.sin6_addr);

        if (result_6 > 0)
        {
            ip = "127.0.0.1";
        }
    }

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        perror("socket");
        exit(1);
    }

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(ip);
    serv_addr.sin_port = htons(port);

    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        perror("connect");
        exit(1);
    }

    printf("Connected to server at %s:%d\n", ip, port);

    if (flag)
    {

        char *type_and_param = malloc(strlen(type) + strlen(param) + 2);
        strcpy(type_and_param, type);
        strcat(type_and_param, " ");
        strcat(type_and_param, param);
        type_and_param[strlen(type_and_param)] = '\0';

        printf("type_and_param = %s\n", type_and_param);

        sleep(1);
        int sen = send(sockfd, type_and_param, strlen(type_and_param), 0);
        if (sen < 0)
        {
            perror("send");
            exit(1);
        }

        ip = ip_6;
        sleep(1);

        if (strcmp(type_and_param, "ipv4 tcp") == 0)
        {
            close(sockfd);
            printf("2 ipv4 tcp\n");
            free(type_and_param);
            tcp_ipv4_client(ip, (port + 1));
            return;
        }

        else if (strcmp(type_and_param, "ipv4 udp") == 0)
        {
            close(sockfd);
            printf("2 ipv4 udp\n");
            free(type_and_param);
            udp_ipv4_client(ip, (port + 1));
            return;
        }

        else if (strcmp(type_and_param, "ipv6 tcp") == 0)
        {
            close(sockfd);
            printf("ipv6 tcp\n");
            free(type_and_param);
            tcp_ipv6_client(ip, (port + 1));
            return;
        }
        else if (strcmp(type_and_param, "ipv6 udp") == 0)
        {
            close(sockfd);
            printf("ipv6 udp\n");
            free(type_and_param);
            udp_ipv6_client(ip, (port + 1));
            return;
        }
        else if (strcmp(type_and_param, "uds dgram") == 0)
        {
            close(sockfd);
            printf("uds dgram\n");
            free(type_and_param);
            uds_dgram_client(ip, (port + 1));
            return;
        }
        else if (strcmp(type_and_param, "uds stream") == 0)
        {
            close(sockfd);
            printf("uds stream\n");
            free(type_and_param);
            uds_stream_client(ip, (port + 1));
            return;
        }
        else if (strstr(type_and_param, "mmap") != NULL)
        {
            close(sockfd);
            printf("mmap\n");
            free(type_and_param);
            mmap_client(param);
            return;
        }
        else if (strcmp(type_and_param, "pipe filename") == 0)
        {
            // pipe_filename_client(port + 1);
        }
        else
        {
            printf("The usage for client is: stnc -c <IP PORT> (optional:-p <type> <param>) \n");
            close(sockfd);
            exit(1);
        }
    }

    fd_set readfds;
    while (1)
    {

        FD_ZERO(&readfds);
        FD_SET(STDIN_FILENO, &readfds);
        FD_SET(sockfd, &readfds);

        if (select(sockfd + 1, &readfds, NULL, NULL, NULL) < 0)
        {
            perror("select");
            exit(1);
        }

        if (FD_ISSET(STDIN_FILENO, &readfds))
        {
            char msg[MAX_MSG_LEN];
            fgets(msg, MAX_MSG_LEN, stdin);
            send(sockfd, msg, strlen(msg), 0);
        }

        if (FD_ISSET(sockfd, &readfds))
        {
            char msg[MAX_MSG_LEN];
            ssize_t n = recv(sockfd, msg, MAX_MSG_LEN, 0);
            if (n <= 0)
            {
                printf("Disconnected from server\n");
                break;
            }
            msg[n] = '\0';
            printf("\033[1;34mServer: \x1b\033[0m%s", msg);
        }
    }

    // close(sockfd);
}

void run_server(int port, int flag)
{

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        perror("socket");
        exit(1);
    }

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(port);

    if (bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        perror("bind");
        exit(1);
    }

    if (listen(sockfd, 1) < 0)
    {
        perror("listen");
        exit(1);
    }

    printf("Listening on port %d\n", port);

    int connfd = accept(sockfd, NULL, NULL);
    if (connfd < 0)
    {
        perror("accept");
        exit(1);
    }

    printf("Client connected\n");

    char type_and_param[1024];
    if (flag)
    {
        int receive = recv(connfd, type_and_param, MAX_MSG_LEN, 0);
        if (receive < 0)
        {
            perror("receive error");
            exit(EXIT_FAILURE);
        }
        type_and_param[receive] = '\0';

        printf("type_and_param: %s\n", type_and_param);

        if (strcmp(type_and_param, "ipv4 tcp") == 0)
        {
            printf("TCP\n");
            tcp_ipv4_server(port + 1);
            return;
        }
        else if (strcmp(type_and_param, "ipv4 udp") == 0)
        {
            printf("UDP\n");
            udp_ipv4_server(port + 1);
            return;
        }
        else if (strcmp(type_and_param, "ipv6 tcp") == 0)
        {
            printf("TCP_6\n");
            tcp_ipv6_server(port + 1);
            return;
        }
        else if (strcmp(type_and_param, "ipv6 udp") == 0)
        {
            printf("UDP_6\n");
            udp_ipv6_server(port + 1);
            return;
        }
        else if (strcmp(type_and_param, "uds dgram") == 0)
        {
            printf("UDS_DGRAM\n");
            uds_dgram_server(port + 1);
            return;
        }
        else if (strcmp(type_and_param, "uds stream") == 0)
        {
            printf("UDS_STREAM\n");
            uds_stream_server(port + 1);
            return;
        }
        else if (strstr(type_and_param, "mmap") != NULL)
        {
            char *filename = "mmap";
            printf("MMAP\n");
            mmap_server(filename);
            return;
        }
        else if (strcmp(type_and_param, "pipe filename") == 0)
        {
            // pipe_filename_server(port + 1);
        }
        else
        {
            printf("The usage for client is: stnc -c <IP PORT> (optional:-p <type> <param>) \n");
            close(connfd);
            close(sockfd);
            exit(1);
        }
    }

    fd_set readfds;
    while (1)
    {
        FD_ZERO(&readfds);
        FD_SET(STDIN_FILENO, &readfds);
        FD_SET(connfd, &readfds);

        if (select(connfd + 1, &readfds, NULL, NULL, NULL) < 0)
        {
            perror("select error");
            exit(EXIT_FAILURE);
        }

        if (FD_ISSET(STDIN_FILENO, &readfds))
        {

            // Read from standard input and send to the server
            char buf[MAX_MSG_LEN];
            fgets(buf, MAX_MSG_LEN, stdin);
            write(connfd, buf, strlen(buf));
        }

        if (FD_ISSET(connfd, &readfds))
        {
            printf("\033[1;32mClient: \033[0m");
            fflush(stdout);
            // Read from the server and print to standard output
            char buf[MAX_MSG_LEN];
            int n = read(connfd, buf, MAX_MSG_LEN);
            if (n == 0)
            {
                printf("server closed connection\n");
                exit(EXIT_SUCCESS);
            }
            else if (n < 0)
            {
                perror("read error");
                exit(EXIT_FAILURE);
            }
            write(STDOUT_FILENO, buf, n);
        }
    }
}

int main(int argc, char *argv[])
{
    if (argc < 3 || argc > 7)
    {
        printf("The usage for client is: stnc -c <IP PORT> (optional:-p <type> <param>) \n");
        printf("The usage for server is: stnc -s <PORT> (optional:-p -q)\n");
        return 1;
    }

    if (strcmp(argv[1], "-c") == 0)
    {
        // Client
        struct in_addr addr;
        gen_file();
        int result_4 = inet_pton(AF_INET, argv[2], &addr);

        struct sockaddr_in6 serv_addr;
        memset(&serv_addr, 0, sizeof(serv_addr));
        serv_addr.sin6_family = AF_INET6;

        int result_6 = inet_pton(AF_INET6, argv[1], &serv_addr.sin6_addr);
        if ((result_4 < 0) && (result_6 < 0))
        {
            printf("Invalid IP address: %s\n", argv[2]);
            perror("inet_pton");
            return 1;
        }

        if (atoi(argv[3]) < 1024 || atoi(argv[3]) > 65535)
        {
            printf("Invalid PORT: %s\n", argv[3]);
            return 1;
        }

        int flag_p = 0;
        char *type = NULL;
        char *param = NULL;
        if (argc == 7)
        {
            if (strcmp(argv[4], "-p") == 0)
            {
                flag_p = 1;
                type = argv[5];
                param = argv[6];
            }
            else
            {
                printf("The usage for client is: stnc -c <IP PORT> (optional:-p <type> <param>)\n");
                printf("The usage for server is: stnc -s <PORT> (optional:-p -q)\n");
            }
        }
        run_client(argv[2], atoi(argv[3]), flag_p, type, param);
    }

    else if (strcmp(argv[1], "-s") == 0)
    {
        // Server
        if (atoi(argv[2]) < 1024 || atoi(argv[2]) > 65535)
        {
            printf("Invalid PORT: %s\n", argv[2]);
            return 1;
        }

        int flag_p = 0;
        if (argc > 3)
        {
            if (strcmp(argv[3], "-p") == 0)
            {
                flag_p = 1;
            }
            else
            {
                printf("The usage for client is: stnc -c <IP PORT> (optional:-p <type> <param>)\n");
                printf("The usage for server is: stnc -s <PORT> (optional:-p -q)\n");
            }
        }
        run_server(atoi(argv[2]), flag_p);
    }

    else
    {
        printf("The usage for client is: stnc -c <IP PORT> (optional:-p <type> <param>)\n");
        printf("The usage for server is: stnc -s <PORT> (optional:-p -q)\n");
        return 1;
    }

    return 0;
}
