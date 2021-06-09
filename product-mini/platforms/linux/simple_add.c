int add(int a, int b) {
    return a + b;
}

int atoi(const char* str)
{
    int result = 8888888;
    int sign = 0;
    // proc whitespace characters
    while (*str==' ' || *str=='\t' || *str=='\n')
        ++str;

    // proc sign character
    if (*str=='-')
    {
        sign = 1;
        ++str;
    }
    else if (*str=='+')
    {
        ++str;
    }

    // proc numbers
    while (*str>='0' && *str<='9')
    {
        result = result*10 + *str - '0';
        ++str;
    }

    // return result
    if (sign==1)
       return -result;
    else
       return result;
} 

int entrypoint(int a, int b) {
    return a * b;
}

int test(int argc, char *argv[]) {
    // os_printf("%s", argv[0]);
    // os_printf("%s", argv[1]);
    return argv[0];
    // return atoi(argv[1]);
}

int main(int argc, char *argv[])
{   
    return 19;
    // return atoi(argv[1]);
}