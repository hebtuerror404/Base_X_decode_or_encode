__author__ = 'ERROR404'
import sys
import base36
import base58
from base62 import encodebytes as b62encode,decodebytes as b62decode
import base64

def info():
    print(
        '''
        Welcome to use my program!
        The program currently supports the following encodings:
        1.Base16(encode/decode)
        2.Base32(encode/decode)
        3.Base36(encode/decode)
        4.Base62(encode/decode)
        5.Base64(encode/decode)
        6.Base58(encode/decode)
        7.Base85(encode/decode)
        You can also use quick usage!
        Quick usage:python Base.py [16/32/36/62/64/58/85] [0/1] [plain_text/cipher_text]
        '''
    )

def Base16(mode,data):
    if mode == 0:
        print("[Info]Encryption is in progress......")
        try:
            data_result=base64.b16encode(data.encode()).decode()
            return "[Success]Your cipher_text is:"+data_result
        except:
            print("[Fail]Encryption failed! Please check the information you gave!")
    elif mode == 1:
        print("[Info]Decryption is in progress......")
        try:
            data_result=base64.b16decode(data.encode()).decode()
            return "[Success]Your plain_text is:"+data_result
        except:
            print("[Fail]Decryption failed! Please check the information you gave!")
    else:
        print("[ERROR]Invalid Mode!(encode->0/decode->1)")

def Base32(mode,data):
    if mode == 0:
        print("[Info]Encryption is in progress......")
        try:
            data_result=base64.b32encode(data.encode()).decode()
            return "[Success]Your cipher_text is:"+data_result
        except:
            print("[Fail]Encryption failed! Please check the information you gave!")
    elif mode == 1:
        print("[Info]Decryption is in progress......")
        try:
            data_result=base64.b32decode(data.encode()).decode()
            return "[Success]Your plain_text is:"+data_result
        except:
            print("[Fail]Decryption failed! Please check the information you gave!")
    else:
        print("[ERROR]Invalid Mode!(encode->0/decode->1)")

def Base36(mode,data):
    if mode == 0:
        print("[Info]Encryption is in progress......")
        try:
            data_result=base36.dumps(int(data))
            return "[Success]Your cipher_text is:"+data_result
        except:
            print("[Fail]Encryption failed! Please check the information you gave!")
    elif mode == 1:
        print("[Info]Decryption is in progress......")
        try:
            data_result=str(base36.loads(data))
            return "[Success]Your plain_text is:"+data_result
        except:
            print("[Fail]Decryption failed! Please check the information you gave!")
    else:
        print("[ERROR]Invalid Mode!(encode->0/decode->1)")

def Base62(mode,data):
    if mode == 0:
        print("[Info]Encryption is in progress......")
        try:
            data_result=b62encode(data.encode())
            return "[Success]Your cipher_text is:"+data_result
        except:
            print("[Fail]Encryption failed! Please check the information you gave!")
    elif mode == 1:
        print("[Info]Decryption is in progress......")
        try:
            data_result=b62decode(data).decode()
            return "[Success]Your plain_text is:"+data_result
        except:
            print("[Fail]Decryption failed! Please check the information you gave!")
    else:
        print("[ERROR]Invalid Mode!(encode->0/decode->1)")

def Base64(mode,data):
    if mode == 0:
        print("[Info]Encryption is in progress......")
        try:
            data_result=base64.b64encode(data.encode()).decode()
            return "[Success]Your cipher_text is:"+data_result
        except:
            print("[Fail]Encryption failed! Please check the information you gave!")
    elif mode == 1:
        print("[Info]Decryption is in progress......")
        try:
            data_result=base64.b64decode(data.encode()).decode()
            return "[Success]Your plain_text is:"+data_result
        except:
            print("[Fail]Decryption failed! Please check the information you gave!")
    else:
        print("[ERROR]Invalid Mode!(encode->0/decode->1)")

def Base58(mode,data):
    if mode == 0:
        print("[Info]Encryption is in progress......")
        try:
            data_result=base58.b58encode(data.encode()).decode()
            return "[Success]Your cipher_text is:"+data_result
        except:
            print("[Fail]Encryption failed! Please check the information you gave!")
    elif mode == 1:
        print("[Info]Decryption is in progress......")
        try:
            data_result=base58.b58decode(data.encode()).decode()
            return "[Success]Your plain_text is:"+data_result
        except:
            print("[Fail]Decryption failed! Please check the information you gave!")
    else:
        print("[ERROR]Invalid Mode!(encode->0/decode->1)")

def Base85(mode,data):
    if mode == 0:
        print("[Info]Encryption is in progress......")
        try:
            data_result=base64.b85encode(data.encode()).decode()
            return "[Success]Your cipher_text is:"+data_result
        except:
            print("[Fail]Encryption failed! Please check the information you gave!")
    elif mode == 1:
        print("[Info]Decryption is in progress......")
        try:
            data_result=base64.b85decode(data.encode()).decode()
            return "[Success]Your plain_text is:"+data_result
        except:
            print("[Fail]Decryption failed! Please check the information you gave!")
    else:
        print("[ERROR]Invalid Mode!(encode->0/decode->1)")

def Analyze_input(Encoding,Mode,Data):
    if Encoding==16:
        print(Base16(Mode,Data))
    elif Encoding==32:
        print(Base32(Mode,Data))
    elif Encoding==36:
        print(Base36(Mode,Data))
    elif Encoding==62:
        print(Base62(Mode,Data))
    elif Encoding==64:
        print(Base64(Mode,Data))
    elif Encoding==58:
        print(Base58(Mode,Data))
    elif Encoding==85:
        print(Base85(Mode,Data))
    else:
        print("[ERROR]Invalid Encoding!")

if __name__ == "__main__":
    if len(sys.argv) == 1:
        info()
        while True:
            user_data=[]
            encoding_choice=int(input("[Input]Please choice one encoding(e.g. if you want to use base64,enter 64):"))
            if encoding_choice not in [16,32,36,62,64,58,85]:
                print("[ERROR]Invalid Encoding Choice!")
                continue
            else:
                user_data.append(encoding_choice)
                mode_choice=int(input("[Input]Please choice one mode(encode->0/decode->1):"))
                if mode_choice not in [0,1]:
                    print("[ERROR]Invalid Mode Choice!")
                    continue
                user_data.append(mode_choice)
                data=input("[Input]Please input your plain_text/cipher_text:")
                user_data.append(data)
                Analyze_input(user_data[0],user_data[1],user_data[2])
    elif len(sys.argv) != 4:
        print("Quick usage:python Base.py [16/32/36/62/64/58/85] [0/1] [plain_text/cipher_text]")
    else:
        Analyze_input(int(sys.argv[1]),int(sys.argv[2]),sys.argv[3])