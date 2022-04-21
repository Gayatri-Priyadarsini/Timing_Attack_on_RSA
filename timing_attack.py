#!/usr/bin/env python3

import random
import time


DEBUG = True
# DEBUG = False   


def rand():
    return random.randint(0, 2147483647)

calc = [0 for _ in range(100)]


### binary_exponentiation is used to calculate the powers in log2(power) complexity
def binary_exponentiation(a, b):
    if b == 1:
        return a
    if b == 0:
        return 1
    tmp = binary_exponentiation(a, b//2)
    if b % 2 != 0:
        return tmp*tmp*a
    else:
        return tmp*tmp
 
def premier(q):
    while True:
        m = rand() % 200
        if (m < 5) or (m == q):
            continue
        s = 0
        m2 = m - 1
        while m2 % 2 == 0:
            m2 /= 2
            s += 1
        t = (m-1) // binary_exponentiation(2, s)
        cpt = 0
        while cpt < 20:
            a = rand() % (m-1) + 1
            u = (binary_exponentiation(a,t)) % m
            if u == 1:
                b = True
            else:
                i = 0
                b = False
                while (i < s) and (b == 0):
                    if (u == m-1) or (u == -1):
                    # if u== m-1:
                        b = True
                    else:
                        b = False
                    u = (u*u) % m
                    i += 1
            if  b == False:
                cpt = 21
            else:
                cpt += 1
        if cpt <= 20:
            break
    return m

## phi = (p-1)*(q-1)
## Here is the function that checks the following constraint.
## e and phi must be co-prime. 
def check(phi, e):              
    if e % 2 == 0:
        return False
    for  i in range(3,e+1,2):
        if e % i == 0 and phi % i == 0:
            return False
    return True

# c = m**e (mod n)
# This function is used to calculate the cipher text from the message using public key(e,n).
def encrypt(M, e, n):
    C = 1
    for _ in range(e):
        C = C * M % n
    C = C % n
    if M < 32:
        M = 32
    print("\tCharacter %c cipher text : %d" % (chr(M), C))
    return C

# m = c**d (mod n)
# This function is used to calculate the message from the cipher text using private key(d,n).
def decrypt(C, len_d, n, binary_rep_d):
    s = []
    R = []
    data_list = []
    s.append(1)
    for i in range(len_d):
        start = time.perf_counter()
        repeat_count = 1000
        hazard = rand()
        for j in range(repeat_count):
            if hazard < 2147483647/2:
                    Ri = s[i]
            else:
                for _ in range(11):
                    pass
            if binary_rep_d[len_d-1-i] == 1: 
                Ri = s[i] * C % n
            else:
                Ri = s[i]

        end = time.perf_counter()

        R.append(Ri)


        tm = (end - start) * 1000000000 // repeat_count  
        print("time for iteration %d: %d nsec" % (i, tm))

        s.append((Ri * Ri) % n)
        data_list.append( (tm, i) )

    data_list.sort(key = lambda x: x[0])

    ecart = 0
    ecart_bis = 0
    j = 0
    for d in data_list:
        if (j >= (len_d/3)-1 and j <= len_d-(len_d/3) and j+1 < len(data_list) and (data_list[j+1][0] - d[0]) > ecart):
            ecart = data_list[j+1][0] - d[0]
            ind_ecart = j
        elif j+1 < len(data_list) and (data_list[j+1][0] - d[0]) > ecart:
            ecart_bis = data_list[j+1][0] - d[0]
            ind_ecart_bis = j
        j += 1
    if ecart == 0:
        ecart = ecart_bis
        ind_ecart = ind_ecart_bis
    key = [0 for i in range(100)]  
    for j in range(ind_ecart+1):
        d = data_list[j]
        key[d[1]] = 0
        if d[1] == 0:
            key[d[1]] = 1
            calc[d[1]] += 1
    for i in range(ind_ecart+1, len(data_list)):
        d = data_list[i]
        key[d[1]] = 1
        calc[d[1]] += 1
    print("Key estimate:\t ", end="")
    for j in range(1, len_d):
        print(key[j], end=" ")
    M = R[len_d - 1]
    print("\tCharacter decrypt : %c" % M)


def convert_to_binary(d):
    binary_digits = []
    q = 1
    i = 0
    while q != 0:
        q = d // 2
        r = d % 2
        d = q
        binary_digits.append(r)
        i += 1
        j = i
    print("\tKey in binary\t: ", end="")
    i = j-1
    while i >= 0:
        print(binary_digits[i], end=" ")
        i -= 1
    print()
    return (j, binary_digits)

def main():
    if DEBUG:
        p = 193
        q = 13
    else:
        p = premier(0)
        q = premier(p)
    print("\nPrime numbers:\np=%d\tq=%d" % (p, q))

    n = p*q
    phi = (p-1)*(q-1)
    print("Phi(n)= %d\n" % phi)

    while True:
        e = int(input("Enter e: "))
        if check(phi, e):
            break

    d = 1
    while ((d*e) % phi) != 1:
        d += 1

    print("\tPublic key\t: {%d,%d}" % (e, n))
    print("\tPrivate key\t: {%d,%d}" % (d, n))

    binary_rep_d = []  
    len_d, binary_rep_d = convert_to_binary(d)

    print("\nEnter a message to encrypt:")

    pt = input()  
    code = [ encrypt(ord(m), e, n) for m in pt ]

    print()

    for c in code:
        decrypt(c, len_d, n, binary_rep_d)
    
    print("\tKey final estimate:\t", end="")

    for i in range(len_d):
        if calc[i] > (len(pt)/2):
            print("1", end="")
        else:
            print("0", end="")

    print()
    return 0
main()
