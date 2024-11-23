#!/usr/bin/env python3

#------------------------------------------------------------------------------
author = "@csBlueChip"
ver = "1.0.0"
"""
1.0.0 - BC  - Initial release
"""

#------------------------------------------------------------------------------
import sys
import argparse
import pm3

#------------------------------------------------------------------------------
# Exit codes
#
ERR_OK     = 0
ERR_ABC    = 1
ERR_KEYSET = 2
ERR_RETRY  = 3
ERR_KEY12  = 4
ERR_BLK    = 5
ERR_KEYHEX = 6

#------------------------------------------------------------------------------
tool = "Aerial Alignment Tool"
details = f"""
---------
 Details 
---------

NFC tags (and, to a lesser extent, cards) can be difficult to read on a Proxmark
because of the difficulties in lining up the nfc-aerial with the reader-aerial.
[Considerably more expensive/rare readers exist which minimise this problem]

This script attempts to find a single block on the card which it can read,
or you may specify a key, keyhole, and block number.

It will then just keep reading that block while you line up the tag/card.

This is especially valuable with scripts that interpret "bad reads" as failures
eg. during the "brute-force" phase of the fm11rf08s_recovery script.

The per-read retry-count defaults to 2, but can be changed to match the retry
count in the taget script.
For clarity "retry=N" means N attempts per read, not 1+N

There is MUCH scope to improve the coverage of this PoC script.
Tested against: MIFare Classic (only)
"""

#------------------------------------------------------------------------------
# The default keyset:-
#
xkey = [
#    .--block number
#    |  .--keyhole
#    |  |  .---- key ---.
	[0, 4, "A396EFA4E24F"],  # FM11RF08S
	[0, 4, "A31667A8CEC1"],  # FM11RF08
	[0, 4, "518b3354E760"],  # FM11RF32
	[0, 0, "a0a1a2a3a4a5"]   # MAD
]
for blk in range(0, 15+1):
	for hole in [0, 1]:
		xkey.append([blk, hole, "FFFFFFFFFFFF"])  # key not set

#++============================================================================
def  main ():
	p = pm3.pm3()  # console interface

	# --- Parse CLI ---
	parser = argparse.ArgumentParser(description=f"{tool} v{ver}")
	parser.add_argument('-a',            action="store_true",  help='Use keyhole A  [-c 0]')
	parser.add_argument('-b',            action="store_true",  help='Use keyhole B  [-c 1]')
	parser.add_argument('-c',            type=int,             help='Use keyhole #C [-c C]')
	parser.add_argument('-n',            type=int, default=64, help='Stop after N consecutive successfull reads [64]')
	parser.add_argument(      '--blk',   type=int,             help='Specify a block {BLK >= 0}')
	parser.add_argument('-k', '--key',   type=str, default="", help='Specify a key {112233AABBCC}')
	parser.add_argument('-r', '--retry', type=int, default=2,  help='Block retry count [2]')
	parser.add_argument('-?', action="store_true",  help='Detailed help')
	args = parser.parse_args()

	# extended help
	if args.__dict__.get('?'):
		parser.print_help()
		print(details, end='')
		sys.exit(ERR_OK)

	# --- Validate CLI args ---
	if args.retry < 1:
		print("[!] Retry count must be >= 1")
		sys.exit(ERR_RETRY)

	if args.blk != None and args.blk < 0:
		print("[!] Block number must be >= 0")
		sys.exit(ERR_BLK)

	hole = -1
	hcnt = 0
	if args.a:  hcnt += 1 ; hole = 0
	if args.b:  hcnt += 1 ; hole = 1
	if args.c:  hcnt += 1 ; hole = args.c
	if hcnt > 1:
		print("[!] Only specify -a, -b, xor -c N")
		sys.exit(ERR_ABC)

	gotkey = True if args.key != "" else False

	if gotkey:
		try:
			int(args.key, 16)
		except Exception as e:
			print("[!] Key may only contain hex digits")
			sys.exit(ERR_KEYHEX)

	if gotkey and len(args.key) != 12:
		print("[!] Key must be 12 hex digits")
		sys.exit(ERR_KEY12)

	if (gotkey == True) or (hcnt > 0) or (args.blk != None and args.blk >= 0):
		if (gotkey != True) or (hcnt == 0) or (args.blk < 0):
			print("[!] --key, --blk, and {-a, -b, or -c} must be specified as a set (or not at all)")
			sys.exit(ERR_KEYSET)

	# --- Here we go ---
	print("    Use ^C to abort. After a few seconds you will be able to restart PM3\n")

	cmd = f"hf mf rdbl --blk {args.blk} -c {hole} --key {args.key}"

	# --- If no key specified, try to find one ---
	xcnt = len(xkey)
	while gotkey == False:
		for i in range(xcnt):
			k = xkey[i]
			# if successful, this cmd will be used by the main read loop
			cmd = f"hf mf rdbl --blk {k[0]} -c {k[1]} --key {k[2]}"
			print(f"\r    Trying key {i:3}/{xcnt} :  `{cmd}`", end='', flush=True)
			res = p.console(cmd)

			err = -1
			for line in p.grabbed_output.split('\n'):
				if   "ascii"            in line:  err = 0
				elif "Can't select"     in line:  err = 1
				elif "Auth error"       in line:  err = 2
				elif "Read block error" in line:  err = 3
			if err == 0:
				print(" .. Success\n")
				gotkey = True
				break

	print( "    Key: _ No card       ; ? Unknown error")
	print( "         - Auth error    ; ~ Read error")
	print( "         * Read OK first ; + Read OK retry")

	print(f"\n    Polling for {args.n} consecutive successful reads", end='')
	print(f"; {args.retry} attempt{'s' if args.retry != 1 else ''} per read")

	print(f"    Using: `{cmd}`")

	cntGood = 0  # good read
	cntMiss = 0  # missing card
	while (cntGood < args.n) and (cntMiss < args.n):
		for r in range(args.retry):
			p.console(cmd)
			err = 0
			for line in p.grabbed_output.split('\n'):
				if   "ascii"            in line:  err = 1 if r==0 else 2
				elif "Can't select"     in line:  err = -1
				elif "Auth error"       in line:  err = -2
				elif "Read block error" in line:  err = -1
			if err > 0:  break  # good read - stop retrying

		if   err == 0 :  print("?", end='', flush=True) ; cntGood  = 0 ; cntMiss += 1
		elif err == 1 :  print("*", end='', flush=True) ; cntGood += 1 ; cntMiss  = 0
		elif err == 2 :  print("+", end='', flush=True) ; cntGood += 1 ; cntMiss  = 0
		elif err == -1:  print("_", end='', flush=True) ; cntGood  = 1 ; cntMiss += 1
		elif err == -2:  print("-", end='', flush=True) ; cntGood  = 0 ; cntMiss  = 0
		elif err == -3:  print("~", end='', flush=True) ; cntGood  = 0 ; cntMiss  = 0

	if cntGood == args.n:  print("\n[*] Card Aligned")
	if cntMiss == args.n:  print("\n[!] Card Lost")

	sys.exit(ERR_OK)

#++============================================================================
if __name__ == "__main__":
	main()
