#! python3
# pass.py - A password locker program

import sys, json, os, pyperclip, argparse, base64, hashlib
from Crypto.Cipher import AES
from Crypto import Random
import pickle

PATH = 'passdb'

# Pad the raw input so it is divide by 16 in order to use AES 256 encryption
BLOCK_SIZE = 32
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE) 
unpad = lambda s : s[:-ord(s[len(s)-1:])]


class AESCipher:
	def __init__(self, key):
		self.key = hashlib.sha256(key.encode('utf-8')).digest() #key needs to be divisible by 16
	def encrypt(self, raw):
		raw = pad(raw) # pads the password so the password input needs to be divisible by 16
		iv = Random.new().read(AES.block_size)
		cipher = AES.new(self.key, AES.MODE_CBC, iv)
		return base64.b64encode(iv+cipher.encrypt(raw))
	def decrypt(self, enc):
		enc = base64.b64decode(enc)
		iv = enc[:16]
		cipher = AES.new(self.key, AES.MODE_CBC, iv)
		return unpad(cipher.decrypt(enc[16:]))

parser = argparse.ArgumentParser()
parser.add_argument('-l', '--list', help='lists the accounts stored in database')
parser.add_argument('-d', '--delacc', help='deletes account from database')
parser.add_argument('account',nargs='?', help='website for the password that you want')
parser.add_argument('keypass',nargs='?', help='keypass for the passwords')
parser.add_argument('password', nargs='?', help='password for the website you would like to add')

args = parser.parse_args()

# Used pickle module for serialization in order to save byte data
if os.path.exists(PATH):
	PASSWORD = pickle.load(open('passdb','rb'))
else:
	PASSWORD = {}
if args.list:
	print("These are the saved accounts in this database: ")
	for v in PASSWORD.keys():
		print(v)


if (args.account in PASSWORD) and args.keypass:
	temp_pass = AESCipher(args.keypass)
	passwords = temp_pass.decrypt(PASSWORD[args.account])
	if not passwords.decode('utf-8'):
		print('The passkey is incorrect. ')
	else:
		pyperclip.copy(passwords.decode("utf-8")) # decode so that string is copied to clipboard instead of bytes
		print('Passsword for ' + args.account + ' copied to clipboard.')
elif args.account not in PASSWORD and not args.list:
	addtodb = input("This account is not in the database. Would you like to add it? ")
	if addtodb.lower() ==  'y':
		account_name = input("Account name: ")
		account_pass = input("Password: ")
		temp_key = input("Please enter passkey: ")
		temp_pass = AESCipher(temp_key)
		passw = temp_pass.encrypt(account_pass)
		PASSWORD[account_name] = passw
		try:
			pickle.dump(PASSWORD, open('passdb','wb'))
			print("The password has been added to the database.")
		except:
			print("The password as not saved.")

if args.delacc:
	PASSWORD.pop(args.account, None)
	pickle.dump(PASSWORD, open('passdb','wb'))