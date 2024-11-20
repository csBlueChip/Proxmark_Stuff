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
			[bytes.fromhex("8693fc621e12"), bytes.fromhex("d538def7b725")], \
			[bytes.fromhex("40a282c042aa"), bytes.fromhex("f4c0c55efc6a")], \
			[bytes.fromhex("184e3a2e94ca"), bytes.fromhex("4422b9889125")], \
			[bytes.fromhex("dd706a9ee951"), bytes.fromhex("5e5b3758858d")], \
			[bytes.fromhex("cd3a76149582"), bytes.fromhex("51c3d96a0662")], \
			[bytes.fromhex("091a165322eb"), bytes.fromhex("674f46f05025")], \
			[bytes.fromhex("d0d277bc5c94"), bytes.fromhex("b48ba097d7b5")], \
			[bytes.fromhex("cd9edfd14d29"), bytes.fromhex("8c10fbbe4bcf")], \
			[bytes.fromhex("ae46323d85b5"), bytes.fromhex("92e3f0e07b4c")], \
			[bytes.fromhex("7758739e39b3"), bytes.fromhex("4f252e68091e")], \
			[bytes.fromhex("f87d61e37cf0"), bytes.fromhex("4da6db3303e0")], \
			[bytes.fromhex("ad44d2c7b55c"), bytes.fromhex("37355580af8a")], \
			[bytes.fromhex("f9aa7ada600d"), bytes.fromhex("0ab78eae4708")], \
			[bytes.fromhex("9743553d9ead"), bytes.fromhex("96947eab2af6")], \
			[bytes.fromhex("ae19cd0a6e4e"), bytes.fromhex("1be13ff8cda1")], \
			[bytes.fromhex("a12932a626a7"), bytes.fromhex("6715bbd7a562")] \
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

	keyA, keyB = bambuKDF(uid)
	if keyA == False:
		print("! bambuKDF() failed")
		exit(4)

	for sec in range(0, 15+1):
		print(f"  {sec:2d}/A: {keyA[sec].hex()}", end='')
		if 'test' in locals():
			print(" .. OK" if keyA[sec] == test[sec][0] else " .. Error!")
		else:
			print("")

	for sec in range(0, 15+1):  # uncomment this line to get KEY-A's before KEY-B's
		print(f"  {sec:2d}/B: {keyB[sec].hex()}", end='')
		if 'test' in locals():
			print(" .. OK" if keyB[sec] == test[sec][1] else " .. Error!")
		else:
			print("")

	sys.exit(0)

#+=============================================================================
# The keys for the hidden sector-formatted area of the 08S card 
# is a completely separate problem to the Bambu (or, in fact, any) KDF
#
def bambuKDF(uid):

	from Cryptodome.Protocol.KDF import HKDF
	from Cryptodome.Hash         import SHA256

	try:
		# extracted from Bambu firmware
		salt = bytes([0x9a,0x75,0x9c,0xf2,0xc4,0xf7,0xca,0xff,0x22,0x2c,0xb9,0x76,0x9b,0x41,0xbc,0x96])
		keyA = HKDF(uid, 6, salt, SHA256, 16, context=b"RFID-A\0")
		keyB = HKDF(uid, 6, salt, SHA256, 16, context=b"RFID-B\0")
	except Exception as e:
		print(f"{e}")
		return False, False

	return keyA, keyB

#++============================================================================
if __name__ == "__main__": main()
