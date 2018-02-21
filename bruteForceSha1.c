#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

void createHash(unsigned char hash[], char *plaintext, const EVP_MD *md, EVP_MD_CTX *mdctx, int md_len);
char generateRandomLowerLetter();
void generateRandomText(char *plaintext2);
int sameHash(unsigned char firstThreeBytes1[], unsigned char firstThreeBytes2[]);
void printCollision(char *plaintext1, char *plaintext2, unsigned char firstThreeBytes1[], unsigned char firstThreeBytes2[], numberOfTrials);
int findCollision(char *plaintext1, char *plaintext2, unsigned char firstThreeBytes1[], unsigned char firstThreeBytes2[], int numberOfTrials, unsigned char hash[], int md_len, const EVP_MD *md, EVP_MD_CTX *mdctx);
void readInHash(char *argv[], unsigned char hash[]);
int findPlaintextFromHash(unsigned char hash[], char *plaintext2, unsigned char firstThreeBytes1[], unsigned char firstThreeBytes2[], int numberOfTrials, int md_len, const EVP_MD *md, EVP_MD_CTX *mdctx);
void printOneWay(char *plaintext2, unsigned char firstThreeBytes1[], int numberOfTrials);

const int NUMBER_OF_BYTES = 3;
const int RAND_LENGTH = 4;

int main(int argc, char *argv[]) 
{
    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    char *plaintext1 = "1234567";
    char *plaintext2 = malloc(sizeof(char) * RAND_LENGTH);;
    int md_len;
    int numberOfTrials = 1;
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned char firstThreeBytes1[NUMBER_OF_BYTES];
    unsigned char firstThreeBytes2[NUMBER_OF_BYTES];

    // Comment this to test one way  
    createHash(hash, plaintext1, md, mdctx, md_len);
    memcpy(firstThreeBytes1, hash, NUMBER_OF_BYTES);
    generateRandomText(plaintext2);
    createHash(hash, plaintext2, md, mdctx, md_len);
    memcpy(firstThreeBytes2, hash, NUMBER_OF_BYTES);

    numberOfTrials = findCollision(plaintext1, plaintext2, firstThreeBytes1, firstThreeBytes2, numberOfTrials, hash, md_len, md, mdctx);
    printCollision(plaintext1, plaintext2, firstThreeBytes1, firstThreeBytes2, numberOfTrials);

    // Comment this to test collision
    readInHash(argv, firstThreeBytes1);
    numberOfTrials = findPlaintextFromHash(hash, plaintext2, firstThreeBytes1, firstThreeBytes2, numberOfTrials, md_len, md, mdctx);
    
    printOneWay(plaintext2, firstThreeBytes1, numberOfTrials);
    exit(0);
}

void printOneWay(char *plaintext2, unsigned char firstThreeBytes1[], int numberOfTrials) 
{
    printf("=====Testing one way property=====\n");
    printf("Looking for hash: ");
    
    for(int i = 0; i < NUMBER_OF_BYTES; i++)
        printf("%02x", firstThreeBytes1[i]);
    
    printf("\n");
    printf("Successfully found plain text of the input hash: ");

    for(int i = 0; i < NUMBER_OF_BYTES; i++)
        printf("%02x", firstThreeBytes1[i]);

    printf(" in %d trials\n", numberOfTrials);
    printf("plaintext: ");

    for(int i = 0; i < RAND_LENGTH; i++)
        printf("%c", plaintext2[i]);

    printf("\n");
}

void readInHash(char *argv[], unsigned char firstThreeBytes1[]) 
{
    for(int i = 0; i < NUMBER_OF_BYTES; i++) {
        sscanf(argv[1], "%2hhx", &firstThreeBytes1[i]);
        argv[1] += 2;
    }
}

int findPlaintextFromHash(unsigned char hash[], char *plaintext2, unsigned char firstThreeBytes1[], unsigned char firstThreeBytes2[], int numberOfTrials, int md_len, const EVP_MD *md, EVP_MD_CTX *mdctx) 
{
    numberOfTrials = 1;
    generateRandomText(plaintext2);
    createHash(hash, plaintext2, md, mdctx, md_len);
    memcpy(firstThreeBytes2, hash, NUMBER_OF_BYTES);
    
    while(!sameHash(firstThreeBytes1, firstThreeBytes2)) {
        numberOfTrials++;
        generateRandomText(plaintext2);
        createHash(hash, plaintext2, md, mdctx, md_len);
        memcpy(firstThreeBytes2, hash, NUMBER_OF_BYTES);
      
        /*//Uncomment for verboseness
        printf("==========\n");
        printf("given has is: ");
        for(int i = 0; i < NUMBER_OF_BYTES; i++)
            printf("%02x", firstThreeBytes1[i]);
        printf("\n");
        printf("string 1: ");
        for(int i = 0; i < RAND_LENGTH; i++)
            printf("%c", plaintext2[i]);
        printf("\n");
        printf("hash 1: ");
        for(int i = 0; i < NUMBER_OF_BYTES; i++)
            printf("%02x", firstThreeBytes2[i]);
        printf("\n");
        printf("%d\n", numberOfTrials);
        printf("==========\n");*/
    }
    return numberOfTrials;  
}

int findCollision(char *plaintext1, char *plaintext2, unsigned char firstThreeBytes1[], unsigned char firstThreeBytes2[], int numberOfTrials, unsigned char hash[], int md_len, const EVP_MD *md, EVP_MD_CTX *mdctx)
{   
    while(!sameHash(firstThreeBytes1, firstThreeBytes2)) {
        numberOfTrials++;
        generateRandomText(plaintext2);
        createHash(hash, plaintext2, md, mdctx, md_len);
        memcpy(firstThreeBytes2, hash, NUMBER_OF_BYTES);

     /* //Uncomment for verboseness
        printf("==========\n");
        printf("string 1: ");
        for(int i = 0; i < RAND_LENGTH; i++)
            printf("%c", plaintext1[i]);
        printf("\n");
        printf("hash 1: ");
        for(int i = 0; i < NUMBER_OF_BYTES; i++)
            printf("%02x", firstThreeBytes1[i]);
        printf("\n");
        printf("string 2: ");
        for(int i = 0; i < RAND_LENGTH; i++)
            printf("%c", plaintext2[i]);
        printf("\n");
        printf("hash 2: ");
        for(int i = 0; i < NUMBER_OF_BYTES; i++)
            printf("%02x", firstThreeBytes2[i]);
        printf("\n");
        printf("%d\n", numberOfTrials);
        printf("==========\n");*/

    }
    return numberOfTrials;
}

void printCollision(char *plaintext1, char *plaintext2, unsigned char firstThreeBytes1[], unsigned char firstThreeBytes2[], int numberOfTrials)
{
    printf("=====Testing collision free property=====\n");
    printf("Successfully found two strings generating the same hash in %d trials\n", numberOfTrials);
    printf("string 1: ");

    for(int i = 0; i < RAND_LENGTH; i++)
        printf("%c", plaintext1[i]);

    printf("\n");
    printf("hash 1: ");

    for(int i = 0; i < NUMBER_OF_BYTES; i++)
        printf("%02x", firstThreeBytes1[i]);

    printf("\n");
    printf("string 2: ");

    for(int i = 0; i < RAND_LENGTH; i++)
        printf("%c", plaintext2[i]);

    printf("\n");
    printf("hash 2: ");

    for(int i = 0; i < NUMBER_OF_BYTES; i++)
        printf("%02x", firstThreeBytes2[i]);

    printf("\n");
}

void createHash(unsigned char hash[], char *plaintext, const EVP_MD *md, EVP_MD_CTX *mdctx, int md_len) 
{
    OpenSSL_add_all_digests();
    md = EVP_get_digestbyname("sha1");
    mdctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, plaintext, strlen(plaintext));
    EVP_DigestFinal_ex(mdctx, hash, &md_len);
    EVP_MD_CTX_destroy(mdctx);
}

void generateRandomText(char *plaintext2)
{      
    for(int i = 0; i < RAND_LENGTH; i++) {
        plaintext2[i] = generateRandomLowerLetter();
    }
}

char generateRandomLowerLetter()
{
    unsigned char *byte;
    byte = malloc(sizeof(unsigned char));

    RAND_load_file("/dev/random", 1024);
    RAND_pseudo_bytes(byte, sizeof(byte));
    int temp = (int) byte[0];

    while(!(temp > 96 && temp < 123)) {
        RAND_pseudo_bytes(byte, sizeof(byte));
        temp = (int) byte[0];
    }
    temp = (char)temp;
    return temp;
}

int sameHash(unsigned char firstThreeBytes1[], unsigned char firstThreeBytes2[])
{
    for(int i = 0; i < NUMBER_OF_BYTES; i++) {
        if(firstThreeBytes1[i] != firstThreeBytes2[i]) {
            return 0;
        }
    }

    return 1;
}

