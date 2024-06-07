#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    char* buffer = (char*)malloc(256);
    if (buffer == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return 1;
    }

    sprintf(buffer, "/sys/kernel/debug/tracing/events/syscalls/%s/id", "sys_enter_execve");
    printf("%s\n", buffer);

    FILE* fp = fopen(buffer, "r");
    
    if (fp == NULL) {
        perror("Error opening file");
        return 1;
    }

    int number;

    if (fscanf(fp, "%d", &number) != 1) {
        fprintf(stderr, "Error reading number from file\n");
        fclose(fp);
        return 1;
    }
    
    printf("[%d]\n", number);
    
    free(buffer);

    return 0;
}
