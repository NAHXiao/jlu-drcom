/*
 *  simple JLU drcom client
 *  dirty hack version
 *
 */

/*
 * -- doc --
 * 数据包类型表示
 * 0x01 challenge request
 * 0x02 challenge response
 * 0x03 login request
 * 0x04 login response
 * 0x07 keep_alive request
 *		keep_alive response
 *		logout request
 *		logout response
 *		change_pass request
 *		change_pass response
 *
 */
#pragma comment(lib,"ws2_32.lib")
#define _CRT_SECURE_NO_WARNINGS
#ifdef _WIN32
#define sleep(sec) Sleep(1000*sec)
#endif
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>

// #include <arpa/inet.h>
// #include <netinet/in.h>
// #include <sys/socket.h>
// #include <sys/types.h>
// #include <unistd.h>

#include <fcntl.h>
#include <io.h>
#include <signal.h>
#include <sys/stat.h>
#include <time.h>

#include "./curl.h"
#include "md5.h"


time_t t;
// FILE* stdout2=NULL,*stdin2=NULL;
#define print(fmt, ...)                                             \
    {                                                               \
        time(&t);                                                   \
        fprintf(stdout, "[%.24s]: " fmt, ctime(&t), ##__VA_ARGS__); \
    }
#define eprint(fmt, ...)                                            \
    {                                                               \
        time(&t);                                                   \
        fprintf(stderr, "[%.24s]: " fmt, ctime(&t), ##__VA_ARGS__); \
    }

// 必须修改，帐号密码和 mac 地址是绑定的
char user[128] = "";
char pass[128] = "";
// echo 0x`ifconfig eth | egrep -io "([0-9a-f]{2}:){5}[0-9a-f]{2}" | tr -d ":"`
uint64_t mac = 0; 
// 不一定要修改
char host[] = "drcom";
char os[] = "drcom";
int user_len = sizeof(user) - 1;
int pass_len = sizeof(pass) - 1;
int host_len = sizeof(host) - 1;
int os_len = sizeof(os) - 1;

// TODO 增加从文件读取参数

// SERVER_DOMAIN login.jlu.edu.cn
#define SERVER_ADDR "10.100.61.3"
#define SERVER_PORT 61440

#define RECV_DATA_SIZE 1000
#define SEND_DATA_SIZE 1000
#define CHALLENGE_TRY 10
#define LOGIN_TRY 5
#define ALIVE_TRY 5

/* infomation */
struct user_info_pkt {
    char* username;
    char* password;
    char* hostname;
    char* os_name;
    uint64_t mac_addr;
    int username_len;
    int password_len;
    int hostname_len;
    int os_name_len;
};

/* signal process flag */
int logout_flag = 0;

void get_user_info(struct user_info_pkt* user_info_w)
{
    user_info_w->username = user;
    user_info_w->username_len = user_len;
    user_info_w->password = pass;
    user_info_w->password_len = pass_len;
    user_info_w->hostname = host;
    user_info_w->hostname_len = host_len;
    user_info_w->os_name = os;
    user_info_w->os_name_len = os_len;
    user_info_w->mac_addr = mac;
}

void set_challenge_data(unsigned char* clg_data_w, int clg_data_len, int clg_try_count)
{
    /* set challenge */
    int random = rand() % 0xF0 + 0xF;
    int data_index = 0;
    memset(clg_data_w, 0x00, clg_data_len);
    /* 0x01 challenge request */
    clg_data_w[data_index++] = 0x01;
    /* clg_try_count first 0x02, then increment */
    clg_data_w[data_index++] = 0x02 + (unsigned char)clg_try_count;
    /* two byte of challenge_data */
    clg_data_w[data_index++] = (unsigned char)(random % 0xFFFF);
    clg_data_w[data_index++] = (unsigned char)((random % 0xFFFF) >> 8);
    /* end with 0x09 */
    clg_data_w[data_index++] = 0x09;
}

#ifdef WIN32
int challenge(SOCKET sock, struct sockaddr_in serv_addr, unsigned char* clg_data, int clg_data_len, char* recv_data, int recv_len)
#else
int challenge(int sock, struct sockaddr_in serv_addr, unsigned char* clg_data, int clg_data_len, char* recv_data, int recv_len)
#endif
{
    int ret;
    int challenge_try = 0;
    do {
        if (challenge_try > CHALLENGE_TRY) {
            #ifdef WIN32
            closesocket(sock);
            #else
            close(sock);
            #endif
            print("[drcom-challenge]: try challenge, but failed, please check your network connection.\n");
            return EXIT_FAILURE;
        }
        set_challenge_data(clg_data, clg_data_len, challenge_try);
        challenge_try++;
        ret = sendto(sock, clg_data, clg_data_len, 0, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
        if (ret != clg_data_len) {
            print("[drcom-challenge]: send challenge data failed.\n");
            continue;
        }
        ret = recvfrom(sock, recv_data, recv_len, 0, NULL, NULL);
        if (ret < 0) {
            print("[drcom-challenge]: recieve data from server failed.\n");
            continue;
        }
        if (*recv_data != 0x02) {
            if (*recv_data == 0x07) {
            #ifdef WIN32
            closesocket(sock);
            #else
            close(sock);
            #endif
                print("[drcom-challenge]: wrong challenge data.\n");
                return EXIT_FAILURE;
            }
            print("[drcom-challenge]: challenge failed!, try again.\n");
        }
    } while ((*recv_data != 0x02));
    print("[drcom-challenge]: challenge success!\n");
    return EXIT_SUCCESS;
}

void set_login_data(struct user_info_pkt* user_info, unsigned char* login_data, int login_data_len, unsigned char* salt, int salt_len)
{
    /* login data */
    int i, j;
    unsigned char md5_str[16];
    unsigned char md5_str_tmp[200];
    int md5_str_len;

    int data_index = 0;

    memset(login_data, 0x00, login_data_len);

    /* magic 3 byte, username_len 1 byte */
    login_data[data_index++] = 0x03;
    login_data[data_index++] = 0x01;
    login_data[data_index++] = 0x00;
    login_data[data_index++] = (unsigned char)(user_info->username_len + 20);

    /* md5 0x03 0x01 salt password */
    md5_str_len = 2 + salt_len + user_info->password_len;
    memset(md5_str_tmp, 0x00, md5_str_len);
    md5_str_tmp[0] = 0x03;
    md5_str_tmp[1] = 0x01;
    memcpy(md5_str_tmp + 2, salt, salt_len);
    memcpy(md5_str_tmp + 2 + salt_len, user_info->password, user_info->password_len);
    MD5(md5_str_tmp, md5_str_len, md5_str);
    memcpy(login_data + data_index, md5_str, 16);
    data_index += 16;

    /* user name 36 */
    memcpy(login_data + data_index, user_info->username, user_info->username_len);
    data_index += user_info->username_len > 36 ? user_info->username_len : 36;

    /* 0x00 0x00 */
    data_index += 2;

    /* (data[4:10].encode('hex'),16)^mac */
    uint64_t sum = 0;
    for (i = 0; i < 6; i++) {
        sum = (int)md5_str[i] + sum * 256;
    }
    sum ^= user_info->mac_addr;
    for (i = 6; i > 0; i--) {
        login_data[data_index + i - 1] = (unsigned char)(sum % 256);
        sum /= 256;
    }
    data_index += 6;

    /* md5 0x01 pwd salt 0x00 0x00 0x00 0x00 */
    md5_str_len = 1 + user_info->password_len + salt_len + 4;
    memset(md5_str_tmp, 0x00, md5_str_len);
    md5_str_tmp[0] = 0x01;
    memcpy(md5_str_tmp + 1, user_info->password, user_info->password_len);
    memcpy(md5_str_tmp + 1 + user_info->password_len, salt, salt_len);
    MD5(md5_str_tmp, md5_str_len, md5_str);
    memcpy(login_data + data_index, md5_str, 16);
    data_index += 16;

    /* 0x01 0x31 0x8c 0x21 0x28 0x00*12 */
    login_data[data_index++] = 0x01;
    login_data[data_index++] = 0x31;
    login_data[data_index++] = 0x8c;
    login_data[data_index++] = 0x21;
    login_data[data_index++] = 0x28;
    data_index += 12;

    /* md5 login_data[0-data_index] 0x14 0x00 0x07 0x0b 8 bytes */
    md5_str_len = data_index + 4;
    memset(md5_str_tmp, 0x00, md5_str_len);
    memcpy(md5_str_tmp, login_data, data_index);
    md5_str_tmp[data_index + 0] = 0x14;
    md5_str_tmp[data_index + 1] = 0x00;
    md5_str_tmp[data_index + 2] = 0x07;
    md5_str_tmp[data_index + 3] = 0x0b;
    MD5(md5_str_tmp, md5_str_len, md5_str);
    memcpy(login_data + data_index, md5_str, 8);
    data_index += 8;

    /* 0x01 0x00*4 */
    login_data[data_index++] = 0x01;
    data_index += 4;

    /* hostname */
    i = user_info->hostname_len > 71 ? 71 : user_info->hostname_len;
    memcpy(login_data + data_index, user_info->hostname, i);
    data_index += 71;

    /* 0x01 */
    login_data[data_index++] = 0x01;

    /* osname */
    i = user_info->os_name_len > 128 ? 128 : user_info->os_name_len;
    memcpy(login_data + data_index, user_info->os_name, i);
    data_index += 128;

    /* 0x6d 0x00 0x00 len(pass) */
    login_data[data_index++] = 0x6d;
    login_data[data_index++] = 0x00;
    login_data[data_index++] = 0x00;
    login_data[data_index++] = (unsigned char)(user_info->password_len);

    /* ror (md5 0x03 0x01 salt pass) pass */
    md5_str_len = 2 + salt_len + user_info->password_len;
    memset(md5_str_tmp, 0x00, md5_str_len);
    md5_str_tmp[0] = 0x03;
    md5_str_tmp[1] = 0x01;
    memcpy(md5_str_tmp + 2, salt, salt_len);
    memcpy(md5_str_tmp + 2 + salt_len, user_info->password, user_info->password_len);
    MD5(md5_str_tmp, md5_str_len, md5_str);
    int ror_check = 0;
    for (i = 0; i < user_info->password_len; i++) {
        ror_check = (int)md5_str[i] ^ (int)(user_info->password[i]);
        login_data[data_index++] = (unsigned char)(((ror_check << 3) & 0xFF) + (ror_check >> 5));
    }

    /* 0x02 0x0c */
    login_data[data_index++] = 0x02;
    login_data[data_index++] = 0x0c;

    /* checksum point */
    int check_point = data_index;
    login_data[data_index++] = 0x01;
    login_data[data_index++] = 0x26;
    login_data[data_index++] = 0x07;
    login_data[data_index++] = 0x11;

    /* 0x00 0x00 mac */
    login_data[data_index++] = 0x00;
    login_data[data_index++] = 0x00;
    uint64_t mac = user_info->mac_addr;
    for (i = 0; i < 6; i++) {
        login_data[data_index + i - 1] = (unsigned char)(mac % 256);
        mac /= 256;
    }
    data_index += 6;

    /* 0x00 0x00 0x00 0x00 the last two byte I dont't know*/
    login_data[data_index++] = 0x00;
    login_data[data_index++] = 0x00;
    login_data[data_index++] = 0x00;
    login_data[data_index++] = 0x00;

    /* checksum */
    sum = 1234;
    uint64_t check = 0;
    for (i = 0; i < data_index; i += 4) {
        check = 0;
        for (j = 0; j < 4; j++) {
            check = check * 256 + (int)login_data[i + j];
        }
        sum ^= check;
    }
    sum = (1968 * sum) & 0xFFFFFFFF;
    for (j = 0; j < 4; j++) {
        login_data[check_point + j] = (unsigned char)(sum >> (j * 8) & 0x000000FF);
    }
}

#ifdef WIN32
int login(SOCKET sock, struct sockaddr_in serv_addr, unsigned char* login_data, int login_data_len, char* recv_data, int recv_len)
#else
int login(int sock, struct sockaddr_in serv_addr, unsigned char* login_data, int login_data_len, char* recv_data, int recv_len)
#endif
//TODO:返回类型细化
{
    /* login */
    int ret = 0;
    int login_try = 0;
    do {
        if (login_try > LOGIN_TRY) {
            #ifdef WIN32
            closesocket(sock);
            #else
            close(sock);
            #endif
            print("[drcom-login]: try login, but failed, something wrong.\n");
            return EXIT_FAILURE;
        }
        login_try++;
        ret = sendto(sock, login_data, login_data_len, 0, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
        if (ret != login_data_len) {
            print("[drcom-login]: send login data failed.\n");
            continue;
        }
        ret = recvfrom(sock, recv_data, recv_len, 0, NULL, NULL);
        if (ret < 0) {
            print("[drcom-login]: recieve data from server failed.\n");
            continue;
        }
        if (*recv_data != 0x04) {
            if (*recv_data == 0x05) {
            #ifdef WIN32
            closesocket(sock);
            #else
            close(sock);
            #endif
                print("[drcom-login]: wrong password or username!\n");
                return EXIT_FAILURE;
            }
            print("[drcom-login]: login failed!, try again\n");
        }
    } while ((*recv_data != 0x04));
    print("[drcom-login]: login success!\n");
    return EXIT_SUCCESS;
}

void set_alive_data(unsigned char* alive_data, int alive_data_len, unsigned char* tail, int tail_len, int alive_count, int random)
{
    // 0: 84 | 1: 82 | 2: 82
    int i = 0;
    memset(alive_data, 0x00, alive_data_len);
    alive_data[i++] = 0x07;
    alive_data[i++] = (unsigned char)alive_count;
    alive_data[i++] = 0x28;
    alive_data[i++] = 0x00;
    alive_data[i++] = 0x0b;
    alive_data[i++] = (unsigned char)(alive_count * 2 + 1);
    //	if (alive_count) {
    alive_data[i++] = 0xdc;
    alive_data[i++] = 0x02;
    //	} else {
    //		alive_data[i++] = 0x0f;
    //		alive_data[i++] = 0x27;
    //	}
    random += rand() % 10;
    for (i = 9; i > 7; i--) {
        alive_data[i] = random % 256;
        random /= 256;
    }
    memcpy(alive_data + 16, tail, tail_len);
    i = 25;
    //	if (alive_count && alive_count % 3 == 0) {
    //		/* crc */
    //		memset(alive_data, 0xFF, 16);
    //	}
}

void set_logout_data(unsigned char* logout_data, int logout_data_len)
{
    memset(logout_data, 0x00, logout_data_len);
    // TODO
}

#ifdef WIN32
int logout(SOCKET sock, struct sockaddr_in serv_addr, unsigned char* logout_data, int logout_data_len, char* recv_data, int recv_len)
#else
int logout(int sock, struct sockaddr_in serv_addr, unsigned char* logout_data, int logout_data_len, char* recv_data, int recv_len)
#endif
{
    set_logout_data(logout_data, logout_data_len);
    // TODO

            #ifdef WIN32
            closesocket(sock);
            #else
            close(sock);
            #endif
    exit(EXIT_SUCCESS);
    // return EXIT_SUCCESS;
}

void logout_signal(int signum)
{
    print("[drcom-signal]: received signal , will logout and exit\n");
    logout_flag = 1;
}
#ifdef WIN32
int set_socket_timeouts(SOCKET sock, int recv_timeout, int send_timeout) {
    int recv_timeout_val = recv_timeout * 1000; 
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&recv_timeout_val, sizeof(recv_timeout_val)) == SOCKET_ERROR) {
        return SOCKET_ERROR;
    }
    int send_timeout_val = send_timeout * 1000; 
    if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&send_timeout_val, sizeof(send_timeout_val)) == SOCKET_ERROR) {
        return SOCKET_ERROR;
    }
    return 0; 
}
#else
#include <sys/socket.h>
int set_socket_timeouts(int sock, int recv_timeout, int send_timeout) {
    struct timeval recv_timeout_val;
    recv_timeout_val.tv_sec = recv_timeout; // 秒
    recv_timeout_val.tv_usec = 0; // 微秒
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &recv_timeout_val, sizeof(recv_timeout_val)) < 0) {
        return -1; // 失败
    }
    struct timeval send_timeout_val;
    send_timeout_val.tv_sec = send_timeout; // 秒
    send_timeout_val.tv_usec = 0; // 微秒
    if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &send_timeout_val, sizeof(send_timeout_val)) < 0) {
        return -1; // 失败
    }
    return 0; // 成功
}

#endif


typedef enum {
    LOGOUT_SUCCESS = 0,
    LOGIN_ERROR,
    LOGOUT_ERROR,
    KEEP_ALIVE_ERROR,
    CREATE_SOCK_ERROR,
    CHALLENGE_ERROR,
    ALIVE_ERROR,
    TEST_NET_CONNECTION_ERROR,
} Result;
const char* msg[] = {
    [LOGOUT_SUCCESS] = "LOGOUT_SUCCESS",
    [LOGIN_ERROR] = "LOGIN_ERROR",
    [LOGOUT_ERROR] = "LOGOUT_ERROR",
    [KEEP_ALIVE_ERROR] = "KEEP_ALIVE_ERROR",
    [CREATE_SOCK_ERROR] = "CREATE_SOCK_ERROR",
    [CHALLENGE_ERROR] = "CHALLENGE_ERROR",
    [ALIVE_ERROR] = "ALIVE_ERROR",
    [TEST_NET_CONNECTION_ERROR] = "TEST_NET_CONNECTION_ERROR"
};
Result login_and_keep()
{

#ifdef WIN32
    SOCKET sock;
    int ret;
#else
    int sock, ret;
#endif
    unsigned char send_data[SEND_DATA_SIZE];
    char recv_data[RECV_DATA_SIZE];
    struct sockaddr_in serv_addr;

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        print("[drcom]: create sock failed.\n");
        return CREATE_SOCK_ERROR;
    }
    // 设置超时
    if (set_socket_timeouts(sock,3,3)){
        print("[drcom]:set timeout failed.\n");
    }
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(SERVER_ADDR);
    serv_addr.sin_port = htons(SERVER_PORT);


    // challenge data length 20
    if (challenge(sock, serv_addr, send_data, 20, recv_data, RECV_DATA_SIZE)) {
        return CHALLENGE_ERROR;
    }

    struct user_info_pkt user_info;
    // get user information
    get_user_info(&user_info);

    // login data length 338, salt length 4
    set_login_data(&user_info, send_data, 338, (unsigned char*)(recv_data + 4), 4);
    memset(recv_data, 0x00, RECV_DATA_SIZE);
    if (login(sock, serv_addr, send_data, 338, recv_data, RECV_DATA_SIZE)) {
        return LOGIN_ERROR;
    }
    // umask(0);

    // keep alive alive data length 42 or 40
    unsigned char tail[4];
    int tail_len = 4;
    memset(tail, 0x00, tail_len);
    int random = rand() % 0xFFFF;

    int alive_data_len = 0;
    int alive_count = 0;
    int alive_fail_count = 0;
    do {
        // print("[0]\n");
        {
            if (alive_fail_count > ALIVE_TRY) {
            #ifdef WIN32
            closesocket(sock);
            #else
            close(sock);
            #endif
                print("[drcom-keep-alive]: couldn't connect to network, check please.\n");
                return ALIVE_ERROR;
            }
        }

        {
            alive_data_len = alive_count > 0 ? 40 : 42;
            set_alive_data(send_data, alive_data_len, tail, tail_len, alive_count, random);
        }

        {
            ret = sendto(sock, send_data, alive_data_len, 0, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
            if (ret != alive_data_len) {
                alive_fail_count++;
                print("[drcom-keep-alive]: send keep-alive data failed.\n");
                continue;
            } else {
                alive_fail_count = 0;
            }
            memset(recv_data, 0x00, RECV_DATA_SIZE);
        }

        { 
            ret = recvfrom(sock, recv_data, RECV_DATA_SIZE, 0, NULL, NULL);
            if (ret < 0 || *recv_data != 0x07) {
                alive_fail_count++;
                print("[drcom-keep-alive]: recieve keep-alive response data from server failed.\n");
                continue;
            } else {
                alive_fail_count = 0;
            }
            if (alive_count > 1)
                memcpy(tail, recv_data + 16, tail_len);
            print("[drcom-keep-alive]: keep alive.\n");
            alive_count = (alive_count + 1) % 3;
        }

        {
            for(int i=0;i<15;i++){
                if(logout_flag) 
                    break;
                sleep(1);
            }
        }
        {
            if(!logout_flag){
                int ret = test_net_connection();
                print("[drcom-curl]:curl -sL baidu.com return:%d\n",ret);
                if (0!=ret) {//接收到logout就不测试了
                    return TEST_NET_CONNECTION_ERROR;
                }
            }
        }

    } while (logout_flag != 1);

    // logout, data_length 80 or ?
    memset(recv_data, 0x00, RECV_DATA_SIZE);
    if (logout(sock, serv_addr, send_data, 80, recv_data, RECV_DATA_SIZE)) {
        return LOGOUT_ERROR;
    }

    return LOGOUT_SUCCESS;
}
void set_stdoutstderr(const char*path){
            // int fd = open(argv[1], O_WRONLY | O_CREAT | O_APPEND, 0644);//append模式
            int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644); // 每次清空
            if (fd == -1) {
                perror("Error opening file");
            } else {
                #ifdef WIN32
                _dup2(3, 1);
                _dup2(3, 2);
                #else
                close(1);
                close(2);
                dup2(3, 1);
                dup2(3, 2);
                #endif
                setbuf(stdout, NULL);
                setbuf(stderr, NULL);
            }
}
typedef struct {
    char* username;
    char* password;
    char* mac;
    char* logfile;
} Arguments;

void print_usage(const char* program_name) {
    fprintf(stderr, "Usage: %s -u username -p password -m mac_address [logfile]\n", program_name);
    fprintf(stderr, "MAC address format: 0xXXXXXXXXXXXX (e.g., 0xBBAACC1100DE)\n");
}

int is_valid_mac(const char* mac) {
    if (strlen(mac) != 14 || mac[0] != '0' || mac[1] != 'x') {
        return 0;
    }
    
    for (int i = 2; i < 14; i++) {
        if (!isxdigit(mac[i])) {
            return 0;
        }
    }
    
    return 1;
}

Arguments parse_arguments(int argc, char* argv[]) {
    Arguments args = {NULL, NULL, NULL, NULL};
    
    if (argc < 7) {
        print_usage(argv[0]);
        exit(1);
    }
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-u") == 0) {
            if (i + 1 < argc) {
                args.username = argv[++i];
            } else {
                fprintf(stderr, "Error: -u requires a username\n");
                print_usage(argv[0]);
                exit(1);
            }
        } else if (strcmp(argv[i], "-p") == 0) {
            if (i + 1 < argc) {
                args.password = argv[++i];
            } else {
                fprintf(stderr, "Error: -p requires a password\n");
                print_usage(argv[0]);
                exit(1);
            }
        } else if (strcmp(argv[i], "-m") == 0) {
            if (i + 1 < argc) {
                char* mac = argv[++i];
                if (!is_valid_mac(mac)) {
                    fprintf(stderr, "Error: Invalid MAC address format. Expected format: 0xXXXXXXXXXXXX\n");
                    print_usage(argv[0]);
                    exit(1);
                }
                args.mac = mac;
            } else {
                fprintf(stderr, "Error: -m requires a MAC address\n");
                print_usage(argv[0]);
                exit(1);
            }
        } else if (args.logfile == NULL && i == argc - 1) {
            args.logfile = argv[i];
        }
    }
    
    // Verify required arguments
    if (!args.username || !args.password || !args.mac) {
        fprintf(stderr, "Error: Username (-u), password (-p), and MAC address (-m) are all required\n");
        print_usage(argv[0]);
        exit(1);
    }
    
    return args;
}

int main(int argc, char* argv[])
{
    Arguments args = parse_arguments(argc, argv);
    strcpy(user,args.username);
    strcpy(pass,args.password);
    sscanf(args.mac,"0x%llx",&mac);
    user_len=(int)strlen(user);
    pass_len=(int)strlen(pass);
    print("[drcom-argparse]:u:%s,pl:%d,mac:0x%llx,logfile:%s\n",user,pass_len,mac,args.logfile?args.logfile:"stdout");
    if (args.logfile)set_stdoutstderr(args.logfile);

    WSADATA wsaData;
    int err = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (err != 0)
        return 1;
    Result ret = -1;
    signal(SIGINT, logout_signal);
    do {
        if (ret != -1) {
            print("[Retry]:...\n");
            sleep(1);
        }
        ret = login_and_keep();
        print("[PANIC]: %s\n", msg[ret]);
    } while (ret != LOGIN_ERROR && ret != LOGOUT_SUCCESS);
    WSACleanup();
    return ret;
}
