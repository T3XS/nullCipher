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
        # we will break our hash key into 5 parts, and use them as seed!
        self.seeds = {
            # key is stored as hex, and not int 
            "rv" : int(self.key[:12], 16),
            "ps" : int(self.key[12:25], 16),
            "br" : int(self.key[25:38], 16),
            "xor" : int(self.key[38:51], 16),
            "lm" : int(self.key[51:], 16)
        }

    # encryption functions which will use seed
    def randomVigenere(self):
        random.seed(self.seeds["rv"])

        # creating random vigenere matrix
        alphabets = ('A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z')
        vigenereMatrix = tuple( tuple(random.sample(alphabets, 26)) for i in range(26))

        encryptedText = []
        for _ in range(len(self.text)):
            # i here points towards column aka normal text char
            i = ord(self.text[_].upper()) - ord("A")
            #  j here points towards row aka password key stream!
            j = ord(self.password[_ % len(self.password) ].upper()) - ord("A")


            encryptedText.append(vigenereMatrix[i][j])
        
        self.text = "".join(encryptedText)

    def progressiveShift(self):
        shift = self.seeds["ps"]

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
        #seed for rotation and then creating rotational values
        random.seed(self.seeds["br"])
        rotations = [random.randint(0, 7) for i in range(len(self.text))]
        
        # since we working on byte levels, we must convert it to bytes 
        tempText = self.text.encode() # now string is like 97982913131...
        encryptedText = bytearray()

        # rotating bits in circular manner  
        for i in range(len(tempText)):
            encryptedText.append(((tempText[i] >> rotations[i]) | (tempText[i] << (8 - rotations[i]))) & 0xFF)

        self.text = encryptedText[:].hex()

    def XOR(self):
        # creating values for XORing using 4th part of the key
        random.seed(int(self.key[38:51], 16))
        XORkey = [random.randint(0, 255) for i in range(len(self.text))]

        tempText = self.text.encode()
        encryptedText = bytearray()

        #xoring text and values
        for i in range(len(tempText)):
            encryptedText.append(tempText[i] ^ XORkey[i])
        
        self.text = encryptedText.hex()

    def logisticMap(self):
        # since int part would be large, dividing it with 16^13 will make seed to lie between 0 and 1 which is core of logistic map 
        seed = self.seeds["lm"] / (16 ** 13)

        x = seed if 0 < seed < 1 else 0.69
        r = 0.3999
        
        encryptedText = bytearray()
        tempText = self.text.encode()

        for char in self.text.encode():
            x = r * x * (1 - x)
            c = int(x * 255)
            encryptedText.append(c ^ char)
        
        self.text = encryptedText.hex()





def main():
    text = "hi"
    secret = encrypt(text, text)
    # secret = encrypt((text:=input()), password:=input())
    # print(secret.key)
    secret.XOR()
    secret.logisticMap()
    secret.bitRotation()
    secret.randomVigenere()
    print(secret.text)

main()