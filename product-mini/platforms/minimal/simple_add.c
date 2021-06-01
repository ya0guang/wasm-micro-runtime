int add(int a, int b) {
    return a + b;
}

int entrypoint(int a, int b) {
    return a * b;
}

int main(int argc, char *argv[])
{   
    int res = add(3, 4);
    argv[0] = res;
    entrypoint(3, 4);
    return res;
}