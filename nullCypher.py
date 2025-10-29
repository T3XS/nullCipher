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
            "rv" : int(self.key[:25], 16),
            "ps" : int(self.key[25:50], 16),
            "br" : int(self.key[50:75], 16),
            "xor" : int(self.key[75:100], 16),
            "lm" : int(self.key[100:], 16)
        }

    # encryption functions which will use seed
    def randomVigenere(self):
        rng = random.Random(self.seeds["rv"])

        # creating random vigenere matrix
        alphabets = ('A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z')
        vigenereMatrix = tuple( tuple(rng.sample(alphabets, 26)) for i in range(26))

        encryptedText = []
        for _ in range(len(self.text)):
            # i here points towards column aka normal text char
            i = ord(self.text[_].upper()) - ord("A")
            #  j here points towards row aka password key stream!
            j = ord(self.password[_ % len(self.password) ].upper()) - ord("A")

            char = vigenereMatrix[i][j] if self.text[_] == self.text[_].upper() else vigenereMatrix[i][j].lower()
            encryptedText.append(char)

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
        rng = random.Random(self.seeds["br"])
        rotations = [rng.randint(0, 7) for i in range(len(self.text))]
        
        # since we working on byte levels, we must convert it to bytes 
        tempText = self.text.encode() # now string is like 97982913131...
        encryptedText = bytearray()

        # rotating bits in circular manner  
        for i in range(len(tempText)):
            encryptedText.append(((tempText[i] >> rotations[i]) | (tempText[i] << (8 - rotations[i]))) & 0xFF)

        self.text = encryptedText[:].hex()

    def XOR(self):
        # creating values for XORing using 4th part of the key
        rng = random.Random(self.seeds["xor"])
        XORkey = [rng.randint(0, 255) for i in range(len(self.text))]

        tempText = self.text.encode()
        encryptedText = bytearray()

        #xoring text and values
        for i in range(len(tempText)):
            encryptedText.append(tempText[i] ^ XORkey[i])
        
        self.text = encryptedText.hex()

    def logisticMap(self):
        # since int part would be large, dividing it with 16**len(seed) will make seed to lie between 0 and 1 which is core of logistic map 
        seed = self.seeds["lm"] / (16 ** 28)
        x = seed if 0 < seed < 1 else 0.7
        r = 3.999
        
        encryptedText = bytearray()
        for char in self.text.encode():
            x = r * x * (1 - x)
            c = int(x * 255)
            encryptedText.append(c ^ char)
        
        self.text = encryptedText.hex()

    #function which will be presented to user!
    def encryption(self):
        charEn = (1,2)
        bitEn = (3,4)
        
        order = tuple(random.sample(charEn, 2) + random.sample(bitEn, 2)) + (5,)
        
        for i in order:
            if i == 1: self.randomVigenere()
            elif i == 2: self.progressiveShift()
            elif i == 3: self.bitRotation()
            elif i == 4: self.XOR()
            elif i == 5: self.logisticMap()
        

        with open("secrets.csv", "a", newline="\n") as encrypting:
            writer = csv.writer(encrypting)
            writer.writerow([self.text, self.salt.hex(), order])

    # lambda function for getters
    encryptedText = lambda self: self.text


class decrypt:
    def __init__(self, text, password):
        self.text = text
        self.password = password
        
        with open("secrets.csv", "r") as decrypting:
            reader = csv.reader(decrypting)
            
            for row in reader:
                text, salt, order = row
                if text == self.text: 
                    self.salt = bytes.fromhex(salt) #since it is stored as hex!
                    self.order = [int(i) for i in order if i.isdigit()] # restoring order as list!

                    # since else would be executed if for loop ran normally, which means we have to disrupt for loop the moment it found key
                    break 
            else: 
                self.salt = os.urandom(16) if useOs else random.randbytes(16)
                self.order = [5,4,3,2,1]   

        # creating hash key
        self.key = pbkdf("sha-512", password.encode() , self.salt, 100000).hex()
        self.seeds = {
            # key is stored as hex, and not int 
            "rv" : int(self.key[:25], 16),
            "ps" : int(self.key[25:50], 16),
            "br" : int(self.key[50:75], 16),
            "xor" : int(self.key[75:100], 16),
            "lm" : int(self.key[100:], 16)
        }

    def invLogisticMap(self):
        seed = self.seeds["lm"] / (16 ** 28)
        x = seed if 0 < seed < 1 else 0.7
        r = 3.999

        decryptedText = bytearray()        

        for char in bytes.fromhex(self.text):
            x = r * x * (1 - x)
            c = int(x * 255) & 0xFF
            decryptedText.append(c ^ char)
        
        self.text = decryptedText.decode()

    def invXOR(self):
        # recreating values for XORing using 4th part of the key
        rng = random.Random(self.seeds["xor"])
        XORkey = [rng.randint(0, 255) for i in range(len(self.text))]

        #since it would be hex
        tempText = bytes.fromhex(self.text)
        decryptedText = bytearray()

        #xoring text and values
        for i in range(len(tempText)):
            decryptedText.append(tempText[i] ^ XORkey[i])
        
        self.text = decryptedText.decode()
    
    def invBitRotation(self):
        #seed for rotation and then creating rotational values
        rng = random.Random(self.seeds["br"])
        rotations = [rng.randint(0, 7) for i in range(len(self.text))]
        
        tempText = bytes.fromhex(self.text) # now string is like 97982913131...
        decryptedText = bytearray()

        # rotating bits in circular manner  
        for i in range(len(tempText)):
            decryptedText.append(((tempText[i] << rotations[i]) | (tempText[i] >> (8 - rotations[i]))) & 0xFF)

        self.text = decryptedText[:].decode()

    def invProgressiveShift(self):
        shift = self.seeds["ps"]

        # we will shift first character by firstShift amount, then rest of the letters will be shifted using prevShift amount + chainFactor 
        chainFactor = (shift >> 8) % 256

        decryptedText = []
        for char in self.text:
            base = ord("A") if char == char.upper() else ord("a")
            num = ord(char) - base

            new = (num - shift) % 26
            decryptedText.append(chr(new + base))
            shift = (num + chainFactor) % 26

        self.text = "".join(decryptedText)
    
    def invRandomVigenere(self):
        rng = random.Random(self.seeds["rv"])

        # recreating random vigenere matrix
        alphabets = ('A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z')
        vigenereMatrix = tuple( tuple(rng.sample(alphabets, 26)) for i in range(26))

        decryptedText = []
        for _ in range(len(self.text)):
            # encrypted character
            c = self.text[_]
            #  j here points towards row aka password key stream!
            j = ord(self.password[_ % len(self.password) ].upper()) - ord("A")

            for r in range(26):
                if vigenereMatrix[r][j] == c.upper():
                    base = ord("A") if c.isupper() else ord("a")
                    decryptedText.append(chr(r + base))
                    break
                    
        
        self.text = "".join(decryptedText)

    def decryption(self):
        for i in reversed(self.order):
            if i == 1: self.invRandomVigenere()
            elif i == 2: self.invProgressiveShift()
            elif i == 3: self.invBitRotation()
            elif i == 4: self.invXOR()
            elif i == 5: self.invLogisticMap()







# def main():
#     print("Would you like to Encrypt or Decrypt?","\nPress E for encrypting, D for decrypting, X for Exiting!")
#     while True:
#         c = input()
#         if c.upper() == "E":
#             print("Enter the text you wish to encrypt: ")
#             text = input()
#             print("Enter password for encrpytion: ")
#             password = input()
            
#             cyphered = encrypt(text, password)
#             cyphered.encryption()
#             print(f"Your encrypted text is {cyphered.encryptedText()}")
#             pass 
#         elif c.upper() == "D":
#             pass
#         elif c.upper() == "X":
#             print("Exiting!")
#             break
#             pass
#         else : print("Invalid. Retry!")
    

# main()

# secrets = encrypt("hmmmmm", "hi")
# secrets.encryption()
# print(secrets.encryptedText())
with open("secrets.csv", "r") as file:
    reader = csv.reader(file)
    for row in reader:
        unsecrets = decrypt(row[0], "hi")
        unsecrets.decryption()
        print(unsecrets.text)
