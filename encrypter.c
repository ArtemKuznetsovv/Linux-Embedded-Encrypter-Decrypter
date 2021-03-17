#include "decrypter.c"
#include <sys/time.h>
#include <ctype.h>
#include <sched.h>




void waitForDecryptor(int timeout, char* originalPassword)
{  
    int condReturn;
    struct timespec ts;
    bool isConditionSatisfied = false;
    pthread_mutex_lock(&waitDecryptorMutex);
    while(!isConditionSatisfied)
    {
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += timeout;
        if (timeout == 0)
        {
            WATING_ECNRYPTOR_BRODCAST = true; 
            pthread_cond_broadcast(&EncryptorReady); 
            condReturn = pthread_cond_wait(&DecryptDone, &waitDecryptorMutex); // giving up mutex
            fflush(stdin);
        }
        else 
        {
            condReturn = pthread_cond_timedwait(&DecryptDone, &waitDecryptorMutex, &ts); // giving up  mutex
            if(condReturn == ETIMEDOUT)
            {
                printf("No password recieved during the configured timeout period (%d seconds) regenerating password\n",timeout);
                break;
            } 
        }
        //pthread_mutex_lock(&FinishedMutex);
        if(condReturn == 0 && IS_DECRYPTOR_FINISHED)
        {
            IS_DECRYPTOR_FINISHED = false;

            if(strcmp(DECRYPTED_PASSWORD, originalPassword) == 0)
            {
                printf("Password decrypted successfully by client #%d, recieved %s, is %s \n",ID_DECRYPTOR_FINISHED, DECRYPTED_PASSWORD, originalPassword);
                isConditionSatisfied = true;
                fflush(stdin);
            }
            else
            {
                printf("Wrong password recieved from client #%d %s , should be %s \n",ID_DECRYPTOR_FINISHED, DECRYPTED_PASSWORD, originalPassword);  
                pthread_mutex_lock(&WatingEncryptorMutex);
                WATING_ECNRYPTOR_BRODCAST = true; 
                pthread_mutex_unlock(&WatingEncryptorMutex);
                pthread_cond_broadcast(&EncryptorReady);
            }
            
        }
        
    }
    pthread_mutex_unlock(&waitDecryptorMutex);
}


void getPrintablePassword(char* passwordBuffer, int bufferSize)
{
    char c;

    for (int i = 0; i < bufferSize; i++)
    {
        do
        {
            c = MTA_get_rand_char();

        } while (!isprint((int)c));

        passwordBuffer[i] = c;
    }
}


void* encryptPassword(void* input)
{
    int res = -1, policy = -1;
	pthread_t pthread = -1;
	pthread_attr_t attr;
	cpu_set_t set;
	struct sched_param max_prio = {sched_get_priority_max(SCHED_FIFO)}; 
	struct sched_param min_prio = {sched_get_priority_min(SCHED_RR)};
	pthread_setschedparam(pthread_self(), SCHED_RR, &max_prio);


    DataToDecryptor* data = (DataToDecryptor*)input;
    unsigned int passwordLength = data->passwordLength;
    unsigned int keyLength = passwordLength/8;
    int timeout = data->timeout;
    char* encryptedPassword = (char *)malloc(255 * sizeof(char));
    char* originalPassword = (char *)malloc(passwordLength * sizeof(char) + 1);
    char* encriptionKey = (char *)malloc(keyLength * sizeof(char) + 1);
    unsigned int encryptedPasswordLength;
    MTA_CRYPT_RET_STATUS decryptRetType;
    int num_password_decrypted = 0;

    while (true)
    {
        if (keyLength > 1)
        {
            getPrintablePassword(originalPassword, passwordLength);
        }
        else
        {
            do
            {
                MTA_get_rand_data(originalPassword, passwordLength);

            } while (!isPrintable(originalPassword, passwordLength));
        }
        
        originalPassword[passwordLength] = '\0';

        MTA_get_rand_data(encriptionKey, keyLength);
        encriptionKey[keyLength] = '\0';

        decryptRetType = MTA_encrypt(encriptionKey, keyLength, originalPassword, passwordLength, encryptedPassword, &encryptedPasswordLength);
        if (decryptRetType == MTA_CRYPT_RET_OK)
        {
            printf("New password generated: %s , key: %s, After encryption: %s\n",originalPassword, encriptionKey, encryptedPassword);
            pthread_mutex_lock(&PasswordMutex);
            GLOBAL_ENCRYPTED_PASSWORD = encryptedPassword; 
            pthread_mutex_unlock(&PasswordMutex);
            usleep(20000);
            pthread_mutex_lock(&WatingEncryptorMutex);
            WATING_ECNRYPTOR_BRODCAST = true;
            pthread_mutex_unlock(&WatingEncryptorMutex);
            pthread_cond_broadcast(&EncryptorReady);
            EncryptorReadyBool = true;
            num_password_decrypted++;
        }
        else
        {
            printf("Error while trying to encrypt password %s, status is %d\n",originalPassword, decryptRetType);
            continue;
        }

        waitForDecryptor(timeout, originalPassword);
    }
  
}


bool isNumber(char* input)
{
    int i = 0;

    while (input[i] != '\0')
    {
        if(input[i] < '0' || input[i] > '9')
        {
            return false;
        }
        
        i++;
    }
    
    return true;
}

InputParams* parseInputParams(int argc, char*argv[])
{

    if (argc < 5)
    {
        printf("Missing arguments: -n|--num-of-decrypters, -l|--password-length , -t|--timeout(optional)\n");
        exit(1);
    }

    InputParams *inputPrams = malloc(sizeof(InputParams));

    inputPrams->numOfDecrypters = -1;
    inputPrams->passwordLength = -1;
    inputPrams->timeOutInSecs = 0;

    for (int i = 0; i < argc - 1; i++)
    {
        if (strcmp(argv[i],"-n") == 0)
        {
            if(isNumber(argv[i+1]) == true)
            {
                inputPrams->numOfDecrypters = atoi(argv[i+1]);
            }
            else
            {
                printf("ERROR: Number of decryptors is not a number\n");
                exit(-1);
            }
        }
        else if (strcmp(argv[i],"-l") == 0)
        {
            if(isNumber(argv[i+1]) == true)
            {
                inputPrams->passwordLength = atoi(argv[i+1]);
                if (inputPrams->passwordLength % 8 != 0)
                {
                    printf("ERROR: Password length is not devisable by 8\n");
                    exit(-1);
                }
            }
            else
            {
                printf("ERROR: Password length is not a number\n");
                exit(-1);
            }
        }
        else if (strcmp(argv[i],"-t") == 0)
        {
            if(isNumber(argv[i+1]) == true)
            {
                inputPrams->timeOutInSecs = atoi(argv[i+1]);
            }
            else
            {
                printf("ERROR: Timeout parmater is not a number");
                exit(-1);
            }
        }
    }

    if (inputPrams->passwordLength == -1 || inputPrams->numOfDecrypters == -1)
    {
        printf("ERROR :Input parameters for password length or number of decryptors were not given\n");
        exit(-1);
    }

    return inputPrams;
}

int main(int argc, char*argv[])
{
    srand(time(NULL));
  
    pthread_t encryptor_thread;
   
    InputParams* userInput = parseInputParams(argc, argv);
    int num_of_decryptor_threads = userInput->numOfDecrypters;

    pthread_t decryptor_threads[num_of_decryptor_threads];
    DataToDecryptor* data = malloc(sizeof(DataToDecryptor)* num_of_decryptor_threads);

    for (int i = 0; i < userInput->numOfDecrypters; i++)
    {
        data[i].timeout = userInput->timeOutInSecs;
        data[i].keyLength = userInput->passwordLength / 8;
        data[i].threadNum = i + 1;
        data[i].passwordLength = userInput->passwordLength;
        data[i].sizeOfEncryption = userInput->passwordLength;
        pthread_create(&decryptor_threads[i], NULL, &decryptPassword, &data[i]);
    }
    pthread_create(&encryptor_thread, NULL, &encryptPassword, &data[0]);
    pthread_join(encryptor_thread, NULL);

    return 0;
}