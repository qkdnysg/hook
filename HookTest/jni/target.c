#include <stdio.h>
#include <string.h>

int count = 0;

void  sevenWeapons(int number)
{
    char* str = "Hello,LiBieGou!";
    printf("%s %d\n",str,number);
}

int main()
{
    while(1)
    {
        sevenWeapons(count);
        count++;
        sleep(15);
    }    
    return 0;
}

