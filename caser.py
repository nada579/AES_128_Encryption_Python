def caesar_encrypt(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base + shift) % 26 + base)
        else:
            result += char
    return result

def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)

print("----- Caesar Cipher -----")
print("(1)encpyption")
print("(2)decryption")

choice = input("choose transaction Num 1 or 2: ")

text = input("enter the text: ")
shift = int(input("enter the number of shift steps: "))

if choice == "1":
    result = caesar_encrypt(text, shift)
    print("text after encryption:", result)

elif choice == "2":
    result = caesar_decrypt(text, shift)
    print("text after decryption:", result)

else:
    print("wrong choise !")
