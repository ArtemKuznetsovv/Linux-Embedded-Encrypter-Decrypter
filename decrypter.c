#define _GNU_SOURCE
#include <sched.h>
#include "shared.h"


bool isPrintable(char* buffer, int size)
{
    for (int i = 0; i < size; i++)
    {
        if (!isprint((int)buffer[i]))
        {
            return false;
        }
    }

    return true;
}

void *decryptPassword(void* decryporParam)
{
    pthread_mutex_lock(&EncryptorReadyMutex);
    while (!EncryptorReadyBool)
    {
        WATING_ECNRYPTOR_BRODCAST_START = true;
        pthread_cond_wait(&EncryptorReady, &EncryptorReadyMutex);
    }
    pthread_mutex_unlock(&EncryptorReadyMutex);


    int res = -1, policy = -1;
	pthread_t pthread = -1;
	pthread_attr_t attr;
	cpu_set_t set;
	struct sched_param min_prio = {sched_get_priority_min(SCHED_RR)};
	pthread_setschedparam(pthread_self(), SCHED_RR, &min_prio);


    DataToDecryptor* data = (DataToDecryptor*)decryporParam;
    int keyLen = data->keyLength;
    char *encryptedPassword = GLOBAL_ENCRYPTED_PASSWORD;
    int encryptedPasswordLen = data->sizeOfEncryption;
    char* dycrptedPassword = (char*)malloc(255);
    char* randomKeyBuffer = (char*)malloc(keyLen + 1);
    MTA_CRYPT_RET_STATUS cryptRetStatus;
    int numOfIterations = 0;

    while (true)
    {

        pthread_mutex_lock(&PasswordMutex);
        if (strcmp(encryptedPassword, GLOBAL_ENCRYPTED_PASSWORD) != 0)
        {
            numOfIterations = 0;
            encryptedPassword = GLOBAL_ENCRYPTED_PASSWORD;
        }
        pthread_mutex_unlock(&PasswordMutex);
        

        MTA_get_rand_data(randomKeyBuffer, keyLen);
        randomKeyBuffer[keyLen] = '\0';

        cryptRetStatus = MTA_decrypt(randomKeyBuffer, keyLen, encryptedPassword ,encryptedPasswordLen, dycrptedPassword, &encryptedPasswordLen);

        if (cryptRetStatus == MTA_CRYPT_RET_OK)
        {
            pthread_mutex_lock(&OnlyOneDecryptor);
            pthread_mutex_lock(&PassFoundMutex);
            if (isPrintable(dycrptedPassword, encryptedPasswordLen))
            {
                PASS_FOUND = true; //stop all other decryptor threads

                pthread_mutex_lock(&WatingEncryptorMutex);
                WATING_ECNRYPTOR_BRODCAST = false; 
                pthread_mutex_unlock(&WatingEncryptorMutex);
                char *temp;
                temp = malloc(sizeof(char) * encryptedPasswordLen);
                dycrptedPassword[encryptedPasswordLen] = '\0';

                printf("Theard number #%d found the decrypted password: %s , key: %s, iterations: %d\n",
                        data->threadNum, dycrptedPassword, randomKeyBuffer, numOfIterations);

                numOfIterations = 0;

                ID_DECRYPTOR_FINISHED = data->threadNum;
                strcpy(temp, dycrptedPassword);
                DECRYPTED_PASSWORD = temp;
                IS_DECRYPTOR_FINISHED = true;
                pthread_cond_broadcast(&DecryptDone);
                
                while (!WATING_ECNRYPTOR_BRODCAST)
                {
                    pthread_cond_wait(&EncryptorReady, &PassFoundMutex);
                }
            }

            pthread_mutex_unlock(&PassFoundMutex);
            pthread_mutex_unlock(&OnlyOneDecryptor);

        }

        numOfIterations++;
    }
}