import hashlib
from os import urandom
from binascii import unhexlify, hexlify

#return 256 bit hex random key encoded into 64 bytes
def random_key(n = 32):
    return(hexlify(urandom(n)))

def sha256(message):
    return hashlib.sha256(message).hexdigest()

#message to hex utf-8 encoded
def sha256_encoded(message):
    return hashlib.sha256(str(message).encode('utf-8')).hexdigest()

#Generate private and corresponding public keys
def generate_key(size = 256):
    private_key = []
    public_key = []
    for i in range(size):
        a, b = random_key(), random_key()
        private_key.append((a,b))
        public_key.append((sha256(a),sha256(b)))
    return(private_key, public_key)


def sign_key(private_key, message):
    signature = []
    bin_lmsg = unhexlify(sha256_encoded(message))
    #print(bin_lmsg)
    z = 0
    #have a binary encoded message. Each byte convert to 8 bits and add on necessary zerso
    for i in range (len(bin_lmsg)):
        #print(bin_lmsg[i])
        l_byte = bin(bin_lmsg[i])[2:]

        while len(l_byte) < 8:
            l_byte = '0' + l_byte
        #print(l_byte)

        for j in range(0,8):
            if l_byte[-1:] == '0':
                signature.append(private_key[z][0])

            else:
                signature.append(private_key[z][1])

            l_byte = l_byte[:-1]
            z+=1

    return(signature)




def verify_lkey(signature, public_key ):  #verify lamport signature

    bin_lmsg = unhexlify(sha256_encoded(message))
    verify = []
    z = 0
    #print(bin_lmsg)
    for i in range (len(bin_lmsg)):
        l_byte = bin(bin_lmsg[i])[2:]   #generate a binary string of 8 bits for each byte of 32/256.

        #add zeros in front of bits smaller than a byte
        while len(l_byte) < 8:
                l_byte = '0'+ l_byte

        #Perform same action as signing a message but here hash the signature and concat it with the corresponding public key
        for j in range(0,8):
            if l_byte[-1:] == '0':
                verify.append((sha256(signature[z]),public_key[z][0]))
            else:
                verify.append((sha256(signature[z]),public_key[z][1]))

            l_byte = l_byte[:-1]
            z+=1


    #Check if the hashed signature matches the corresponding public key
    for p in range(len(verify)):
        if verify[p][0] == verify[p][1]:
            pass
        else:
            return False

    return True


def inputs():
    print("\n")
    print("Digital Lamport signature: Using 256 blocks containing each containint 256 bits.")
    print("sha256 is the one way function used to generate public keys.")
    print("\n")



if __name__ == "__main__":

    inputs()

    input("Press enter to generate private/public key set... ")
    private_key, public_key = generate_key()

    print("\n")
    print("private key first 10 blocks: ")
    print(private_key[0:9])

    print("\n")
    print("public key first 10 blocks: ")
    print(public_key[0:9])

    print("\n")
    message = input("Enter the message you wish to broadcast: ")


    sign = sign_key(private_key, message)
    print("\n")
    print("First 10 blocks of Signature on message: ")
    print(sign[0:9])


    ans = verify_lkey(sign, public_key)
    if ans == True:
        print("\n")
        print("Message was signed by the correct private key")
    else:
        print("\n")
        print("Message was signed by a different private key")

    #carol trying to broadcast same message to try pretend to be alice

    #carol_private_key, carol_public_key = generate_key()

    #sign_c = sign_key(carol_private_key, message)
    #ans = verify_lkey(sign_c, public_key)
    #print(ans)
