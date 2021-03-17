#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <errno.h>
#include <math.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <ctype.h>
#include <pthread.h>
#include "mta_crypt.h"
#include "mta_rand.h"

#define bool int
#define true 1
#define false 0

pthread_mutex_t waitDecryptorMutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t PasswordMutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t FinishedMutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t EncryptorReadyMutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t NewPasswordMutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t PassFoundMutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t OnlyOneDecryptor = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t WatingEncryptorMutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t DecryptDone = PTHREAD_COND_INITIALIZER;
pthread_cond_t EncryptorReady = PTHREAD_COND_INITIALIZER;
pthread_cond_t NewPasswordToDecrypt = PTHREAD_COND_INITIALIZER;

bool EncryptorReadyBool = false;

char* GLOBAL_ENCRYPTED_PASSWORD;
bool ID_DECRYPTOR_FINISHED;
bool IS_DECRYPTOR_FINISHED;
bool PASS_FOUND = false;
bool WATING_ECNRYPTOR_BRODCAST_START = false;
bool WATING_ECNRYPTOR_BRODCAST = false;
char* DECRYPTED_PASSWORD;
int NUM_OF_THREADS_WATING = 0;


typedef struct DataToDecryptor
{
    int passwordLength;
    int keyLength;
    int threadNum;
    int sizeOfEncryption;
    int timeout;
}DataToDecryptor;


typedef struct InputParams
{
    int numOfDecrypters;
    int passwordLength;
    int timeOutInSecs; 
}InputParams;