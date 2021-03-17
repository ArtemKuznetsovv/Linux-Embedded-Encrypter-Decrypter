# Encrypter-Decrypter
This is a multithreaded application developed in C, as part of my Linux Embedded course.
The application illustrates a password hacking scenario using brute force techniques.


## How It Works

1. This application has 2 source files(decrypter.c and encrypter.c) and a Makefile.
2. In the encrypter source file we create a custom number of decrypters, each of them running in a seperate thread.
2. The encrypter generates a password with a custom length and sends it to the decrypters.
3. The decrypters compete on who can crack the password first, meanwhile the encrypter waits for them to crack the password(it is possible to configure a timeout too).
4. Whenever the password is cracked, the encryptor generates a new password and sends it to the decrypters.

## How To Use It

1. Clone this repository to your local machine.
2. Install openssl 
 ```sh
    $ sudo apt-get install libssl-dev
    ```
4. To use the encryption and decryption libraries, install the .deb package by running: sudo dpkg --install mta-utils-dev.deb
5. Execute the Make command
6. Run through the bash terminal: sudo ./encrypter.out -n <Number_Of_Decrypters> -l <Password_Length> -t <Seconds_To_Wait_For_Encrypter>

* For example: sudo ./encrypter.out -n 10 -l 16 
