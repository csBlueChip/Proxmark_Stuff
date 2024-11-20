#!/usr/bin/env python3
import sys

#++============================================================================
def main():
	help = f"  Usage: {sys.argv[0]} <UID>\n" \
	        "       : {sys.argv[0]} test\n" \
	        "      ...where <UID> is specified in hex as '11223344' or '11' '22' '33' '44'"

	argc = len(sys.argv)

	# --- Set 'uid' from CLI ---

	if sys.argv[1].lower() == "test":
		uida = ["5c", "b4", "9c", "a6"]
		test = [ \
			bytes.fromhex("8693fc621e12"),  \
			bytes.fromhex("40a282c042aa"),  \
			bytes.fromhex("184e3a2e94ca"),  \
			bytes.fromhex("dd706a9ee951"),  \
			bytes.fromhex("cd3a76149582"),  \
			bytes.fromhex("091a165322eb"),  \
			bytes.fromhex("d0d277bc5c94"),  \
			bytes.fromhex("cd9edfd14d29"),  \
			bytes.fromhex("ae46323d85b5"),  \
			bytes.fromhex("7758739e39b3"),  \
			bytes.fromhex("f87d61e37cf0"),  \
			bytes.fromhex("ad44d2c7b55c"),  \
			bytes.fromhex("f9aa7ada600d"),  \
			bytes.fromhex("9743553d9ead"),  \
			bytes.fromhex("ae19cd0a6e4e"),  \
			bytes.fromhex("a12932a626a7")   \
		]

	elif argc == 4+1:
		uida = sys.argv[-4:]

	elif argc == 1+1:
		if len(sys.argv[1]) != 8:
			print("! Key must be 8 hex digits (higits/nybbles/___?)")
			print(help)
			sys.exit(2)
		uida = [sys.argv[1][i:i+2] for i in range(0, 8, 2)]

	else:
		print(help)
		sys.exit(3)

	# --- convert array of hex strings -to- array of bytes, size 4 ---

	try:
		uid = bytes([int(b, 16) for b in uida[0:3+1]])

	except ValueError:
		print("! Key must be given in hex")
		print(help)
		sys.exit(1)

	# --- CLI parsed. Game on ---

	print(f"# UID: {uid[0]:02X} {uid[1]:02X} {uid[2]:02X} {uid[3]:02X} ", end='')
	print(" - Test UID" if 'test' in locals() else "")

	keyA = bambuKDF(uid)
	if keyA == False:  exit(4)

	for sec in range(0, 15+1):
		print(f"  {sec:02d}/A: {keyA[sec].hex()}", end='')
		if 'test' in locals():
			print(" .. OK" if keyA[sec] == test[sec] else " .. Error!")
		else:
			print("")

	sys.exit(0)

#+=============================================================================
def bambuKDF(uid):

	from Cryptodome.Protocol.KDF import HKDF
	from Cryptodome.Hash         import SHA256

	try:
		salt = bytes([0x9a,0x75,0x9c,0xf2,0xc4,0xf7,0xca,0xff,0x22,0x2c,0xb9,0x76,0x9b,0x41,0xbc,0x96])
		keys = HKDF(uid, 6, salt, SHA256, 16, context=b"RFID-A\0")
	except Exception as e:
		print(f"{e}")
		return False

	return keys

#++============================================================================
if __name__ == "__main__": main()
