#include <stdio.h>

int main(void)
{
    char s1[10];
    scanf("%9s", &s1);

    char i;
    scanf("%d", &i);

    char s2[10];
    scanf("%s", &s2); // vulnerable code
}
