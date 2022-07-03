#!/usr/bin/env python
from argon2 import PasswordHasher
import sys
from compression import AESCipher

def encryptAlg(aes, password):
    return aes.encrypt(password)

def hashPsw(aes, ph, password):
    encryptedStr = encryptAlg(aes, password)
    return ph.hash(encryptedStr)

def check_password(ph, password, hashed):
    try:
        ph.verify(hashed, password)
        print("[COMP_HASH] true")
    except:
        print("[COMP_HASH] false")


def comp_hash(aes, ph, psw1, psw2):
    hash1 = hashPsw(aes, ph, psw1)
    encryptedStr = encryptAlg(aes, psw2)
    print( "[COMP_HASH] psw1 = %s, psw2 = %s" % (psw1, psw2));
    check_password(ph, encryptedStr, hash1)

def printPsw(aes, ph, password):
    print( "[INPUT] %s" % password);
    print( "[OUTPUT] %s" % hashPsw(aes, ph, password));

def main():
    ph = PasswordHasher()
    aes = AESCipher()
    psw1 = 'pass123';
    psw2 = '123pass';
    printPsw(aes, ph, psw1)
    printPsw(aes, ph, psw2)
    comp_hash(aes, ph, psw1, psw1)
    comp_hash(aes, ph, psw1, psw2)

if __name__ == '__main__':
    main()
