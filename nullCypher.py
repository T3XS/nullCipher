from hashlib import pbkdf2_hmac as pbkdf
import random, csv, os

useOs = False

class encrypt:
    def __init__(self, text, password):
        # text to be encrpyted 
        self.text = text
        self.password = password
        # random garbage which will be added to password so passwords wont be mixmatched
        # this is supposed to be STORED and will be used for decrpyting!
        self.salt = os.urandom(16) if useOs else random.randbytes(16)

        # creating hash key
        self.key = pbkdf("sha-512", password.encode() , self.salt, 100000).hex()

    # encryption functions which will use seed
    # we will break our hash key into 5 parts, and use them as seed!
    def randomVigenere(self):
        # key is stored as hex, and not int 
        seed = int(self.key[:12], 16)
        random.seed(seed)

        # creating random vigenere matrix
        alphabets = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z']
        vigenereMatrix = [ random.sample(alphabets, 26) for i in range(26)]

        encryptedText = []
        for _ in range(len(self.text)):
            # i here points towards column aka normal text char
            i = ord(self.text[_].upper()) - ord("A")
            #  j here points towards row aka password key stream!
            j = ord(self.password[_ % len(self.password) ].upper()) - ord("A")


            encryptedText.append(vigenereMatrix[i][j])
        
        self.text = "".join(encryptedText)

        
    def progressiveShift(self):
        shift = int(self.key[12:25], 16)

        # we will shift first character by firstShift amount, then rest of the letters will be shifted using prevShift amount + chainFactor 
        chainFactor = (shift >> 8) % 256

        encryptedText = []
        for char in self.text:
            base = ord("A") if char == char.upper() else ord("a")
            num = ord(char) - base

            new = (num + shift) % 26
            encryptedText.append(chr(new + base))
            shift = (new + chainFactor) % 26

        self.text = "".join(encryptedText)
        

    def bitRotation(self):
        rotationSeed = int(self.key[25:38], 16)
        random.seed(rotationSeed)
        rotations = [random.randint(0, 7) for i in range(len(self.text))]
        
        tempText = self.text.encode()
        encryptedText = bytearray()


        for i in range(len(tempText)):
            encryptedText.append(((tempText[i] >> rotations[i]) | (tempText[i] << (8 - rotations[i]))) & 0xFF)

        self.text = encryptedText[:].hex()





def main():
    text = "hi"
    secret = encrypt(text, text)
    # secret = encrypt((text:=input()), password:=input())
    # print(secret.key)
    secret.progressiveShift()
    print(secret.text)

main()