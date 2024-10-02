#ifndef DRCOM_CURL
#include <curl/curl.h>
size_t write_callback(void* contents, size_t size, size_t nmemb, void* userp);
// return 0 => success
int test_net_connection();
#endif // !DRCOM_CURL
#define DRCOM_CURL
