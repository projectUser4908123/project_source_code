import re
import random
import string
import sys

path = sys.argv[1]

CODE_OBFUSICATION_INTENSITY = 3

functionCalls = [[''.join(random.choice(string.ascii_letters) for i in range(20)), "(8);\r\n"], [
    ''.join(random.choice(string.ascii_letters) for i in range(20)), "(6,3);\r\n"]]
supportFunctionsString = """
char* dec(char* str, char* key, int len){
    char* decrypted = (char*)malloc(len+1);
    for (int i = 0; i < len; i++){
        decrypted[i] = str[i] ^ key[i];
    }
    decrypted[len] = 0;
    return decrypted;
}


void %s (int a){
    int b = 2;
    for (int i=0; i<a;i++) {
        b ++;
    }
    for (int i=0; i < (a%%8); i++) {
        b = b<<1;
    }
}

int %s (int a, int b){
    return a+b;
}
""" % (functionCalls[0][0], functionCalls[1][0])


# Translate Python-style hex to C-stlye hex
def toCHex(c):
    return hex(c).replace("0x", "\\x")


# Builds string payload of decrypt function call
def buildPayload(decPayload, key):
    hexString = "".join([toCHex(i) for i in decPayload])
    hexKey = "".join([toCHex(i) for i in key])

    return "dec(\"%s\",\"%s\",%d)" % (hexString, hexKey, len(key))


# Builds encrypted strings from plaintext.
def buildStrings(plainString):
    # Generates random key everytime.
    keyChars = [random.randint(0, 255) for i in range(len(plainString))]
    dec = []
    for keyChar, stringChar in zip(keyChars, plainString):
        dec.append(keyChar ^ ord(stringChar))
    return dec, keyChars


# Function that builds the encrypted string into source code like encrypted string.
def enc(plainString):
    decryptedString, keyChars = buildStrings(plainString)
    return buildPayload(decryptedString, keyChars)


# Encrypts data blocks (C-style strigns)
def obfusticateDataBlokcs(data):
    strings = re.findall(
        r"^[^#]*?(\"[^\r\n]*?[^\\]\")", data, re.M)

    for i in strings:

        encrypted = enc(i[0: -1].replace("\\n", "\n".replace("\\r",
                                                             "\r").replace("\\t", "\t").replace("\\0", "\0")))

        data = data.replace(i, encrypted)

    return data


# Adds all support function - decrypt function and noise functions.
def addSupportFunctions(data):

    # Try to find main function in order to write support function before it.
    mainSig = re.findall(".*main\(.*", data, re.M | re.I)
    if mainSig == []:
        print("failed to find main.")
        exit(0)
    print(f"Found main function! {mainSig}")
    if len(mainSig) != 1:
        print("Ambigious main function. Please choose the real main line.")
        for line, i in zip(mainSig, range(len(mainSig))):
            print(f"main line: {line}, choose number: {i}")
        realMainLine = input("Choose line: ")
        if (realMainLine < len(mainSig) and realMainLine > 0):
            print("error: please choose a valid number")
            exit(0)
        mainSig = mainSig[realMainLine]
    # Findall returns list - we want the string.
    else:
        mainSig = mainSig[0]

    data = data.replace(mainSig, supportFunctionsString + mainSig)
    return data


# Add noise calls to source code.
def obfusticateCodeBlocks(data):
    lines = data.split(";\n")

    # Last line doesnt include ;\r\n, so i cant count it in the regular lines. I wiil add it back in the end
    last_part = lines[-1]
    lines = lines[: -1]

    newData = []
    # Add noise function every X lines, where X = CODE_OBSUFICATION_INTENSITY
    for i in range(int((len(lines)/CODE_OBFUSICATION_INTENSITY))):
        newData.append(";\r\n".join(lines[i*CODE_OBFUSICATION_INTENSITY: i *
                                          CODE_OBFUSICATION_INTENSITY + CODE_OBFUSICATION_INTENSITY]) + ";\r\n")
        newData.append("".join(functionCalls[i % len(functionCalls)]))

    # We dont have exactly X times CODE_OBFUSICATION_INTESITY lines, so we add the rest.
    if (len(lines) % CODE_OBFUSICATION_INTENSITY != 0):
        newData.append(";\r\n".join(
            lines[int(len(lines)/CODE_OBFUSICATION_INTENSITY) * CODE_OBFUSICATION_INTENSITY:]) + ";\r\n")

    # We add the last line we ommited in the start.
    newData.append(last_part)
    return "".join(newData)


def main():
    with open(path, "r") as f:
        data = f.read()  # .decode("utf-16")
    print(f"Opened file {path}")
    data = obfusticateCodeBlocks(data)
    print("Added noise function calls")
    data = addSupportFunctions(data)
    print("Added support function")
    data = obfusticateDataBlokcs(data)
    print("Finished encrypting strings")

    with open(path.replace(".bkp", ""), "w") as f:
        # Python3 add CR before any LF, so if we have CR already we'll have CRCRLF :()
        f.write(data.replace("\r", ""))


if __name__ == "__main__":
    main()
