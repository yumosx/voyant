// file: lang/cache.c
#include "cache.h"

long fact(long n){
    if (n < 1)
        return 1;
    return n * fact(n - 1);
}

int hello(int id) {
    return id;
}


Person_t* Person_new() {
    Person_t* p = (Person_t*) malloc(sizeof(*p));
    return p;
}