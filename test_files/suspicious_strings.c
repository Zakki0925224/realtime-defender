#include <stdio.h>

int main(void)
{
    char *u1 = "https://www.google.co.jp/";
    char *u2 = "https://twitter.com/home";
    char *u3 = "https://www.yahoo.co.jp/";
    char *u4 = "http://localhost:8080/"; // not match

    char *i1 = "172.217.161.35"; // google.co.jp
    char *i2 = "104.244.42.65";  // twitter.com
    return 0;
}
