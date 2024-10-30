#!/usr/bin/env python3

#import ast
import os
import sys
import time
import argparse
import pm3
import struct
import json
import requests

from fm11rf08s_recovery import recovery


#------------------------------------------------------------------------------
# Revision log:
#------------------------------------------------------------------------------
'''
1.0.0 - BC  - Initial release
'''
script_ver = "1.0.0"

#------------------------------------------------------------------------------
# Print and Log
#------------------------------------------------------------------------------
def startlog(uid,  append = False):
	global logfile
	logfile = f"{dpath}hf-mf-{uid:08X}-log.txt"
	if append == False:
		with open(logfile, 'w'):   pass


def lprint(s,  end='\n', flush=False):
	print(s, end=end, flush=flush)

	if logfile is not None:
		with open(logfile, 'a') as f:
			f.write(s + end)

#------------------------------------------------------------------------------
# optional color support
# `pip install ansicolors`
#------------------------------------------------------------------------------
try:
	from colors import color
except ModuleNotFoundError:
	def color(s, fg=None):
		_ = fg
		return str(s)

#------------------------------------------------------------------------------
# version requirements
#------------------------------------------------------------------------------
required_version = (3, 8)
if sys.version_info < required_version:
	print(f"Python version: {sys.version}")
	print(f"The script needs at least Python v{required_version[0]}.{required_version[1]}. Abort.")
	exit()

#------------------------------------------------------------------------------
# cli arguments
#------------------------------------------------------------------------------
parser = argparse.ArgumentParser(description='Full recovery of Fudan FM11RF08* cards.')

parser.add_argument('-n', '--nokeys',   action='store_true', help='extract data even if keys are missing')
parser.add_argument('-r', '--recover',  action='store_true', help='run key recovery script if required')
parser.add_argument('-b', '--bambu',    action='store_true', help='decode data as Bambu tag')
parser.add_argument('-v', '--validate', action='store_true', help='check Fudan signature (requires internet)')

args   = parser.parse_args()

#------------------------------------------------------------------------------
# console interface
#------------------------------------------------------------------------------
p       = pm3.pm3()
prompt  = "[bc]"

#------------------------------------------------------------------------------
# welcome
# v1.0.0 - initial release (probably misses some edge cases - please report)
#------------------------------------------------------------------------------
print(f"{prompt} Fudan FM11RF08[S] full card recovery")
print(f"{prompt} (C)Copyright BlueChip 2024")
print(f"{prompt} Licence: MIT (\"Free as in free.\")")

#------------------------------------------------------------------------------
# preferences
#------------------------------------------------------------------------------
p.console("prefs show --json")
prefs = json.loads(p.grabbed_output)
dpath = prefs['file.default.dumppath'] + os.path.sep

print(prompt)
print(f"{prompt} Dump folder: {dpath}")

#------------------------------------------------------------------------------
# find backdoor key
#------------------------------------------------------------------------------
#          FM11RF08S        FM11RF08        FM11RF32
dklist = ["A396EFA4E24F", "A31667A8CEC1", "518b3354E760"]
dkey   = ""

print(prompt)
print(f"{prompt} Trying known backdoor keys...")

for k in dklist:
	cmd = f"hf mf rdbl -c 4 --key {k} --blk 0"
	print(f"{prompt} `{cmd}`", end='', flush=True)
	res = p.console(f"{cmd}")
	if res == 0:
		print(" - success")
		dkey = k;
		break;
	print(f" - fail [{res}]")
	for flush in p.grabbed_output:  _ = flush

if dkey == "":
	print(f"{prompt} Unknown key, or card not detected.")
	exit(1)

'''
[=]   # | sector 00 / 0x00                                | ascii
[=] ----+-------------------------------------------------+-----------------
[=]   0 | 5C B4 9C A6 D2 08 04 00 04 59 92 25 BF 5F 70 90 | \........Y.%._p.
'''
for line in p.grabbed_output.split('\n'):
#	print(line)
	if " | " in line and "# | s" not in line:
		blk0 = line[10:56+1]

#------------------------------------------------------------------------------
# extract data from block 0
#------------------------------------------------------------------------------

# We do this early so we can name the logfile!
uids = blk0[0:11]                            # UID string  : "11 22 33 44"
uid  = int(uids.replace(' ', ''), 16)        # UID (value) : 0x11223344
startlog(uid, append=False)

lprint(prompt)
lprint(f"{prompt}              UID         BCC         ++----- RF08 ID -----++")
lprint(f"{prompt}              !           !  SAK      !!                   !!")
lprint(f"{prompt}              !           !  !  ATQA  !!     RF08 Hash     !!")
lprint(f"{prompt}              !---------. !. !. !---. VV .---------------. VV")
#                             0           12 15 18    24 27                45
#                             !           !  !  !     !  !                 !
#                             00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF
lprint(f"{prompt}   Block 0  : {blk0}")

bcc  = int(blk0[12:14], 16)                  # BCC
chk  = 0                                     # calcualte checksum
for h in uids.split():
	chk ^= int(h, 16)

sak  = int(blk0[15:17], 16)                  # SAK
atqa = int(blk0[18:23].replace(' ',''), 16)  # 0x7788

fida = int(blk0[24:26], 16)                  # Fudan ID 0x88
fidb = int(blk0[45:47], 16)                  # Fudan ID 0xFF
fid  = (fida<<8)|fidb                        # Fudan ID 0x88FF

hash = blk0[27:44]                           # Fudan hashC "99 AA BB CC DD EE"

type = f"[{fida:02X}:{fidb:02X}]"            # type/name
if fidb == 0x90:
	if fida == 0x01 or fida == 0x03 or fida == 0x04:
		type += " - Fudan FM11RF08S"

elif fidb == 0x1D:
	if fida == 0x01 or fida == 0x02 or fida == 0x03:
		type += " - Fudan FM11RF08"

elif fidb == 0x91 or fidb == 0x98:
	type += " - Fudan FM11RF08 (never seen in the wild)"

else:
	type += " - Unknown (please report)"

#
# Show results
#

lprint(prompt)

lprint(f"{prompt}   UID/BCC  : {uid:08X}/{bcc:02X} - ", end='')
if bcc == chk:
	lprint("verified")
else:
	lprint(f"fail. Expected {chk:02X}")

lprint(f"{prompt}   SAK      : {sak:02X} - ", end='')
if   sak == 0x01:  lprint("NXP MIFARE TNP3xxx 1K")
elif sak == 0x08:  lprint("NXP MIFARE CLASSIC 1k | Plus 1k | Ev1 1K")
elif sak == 0x09:  lprint("NXP MIFARE Mini 0.3k")
elif sak == 0x10:  lprint("NXP MIFARE Plus 2k")
elif sak == 0x18:  lprint("NXP MIFARE Classic 4k | Plus 4k | Ev1 4k")
else:              lprint("{unknown}")

lprint(f"{prompt}   ATQA     : {atqa:04X}")   # show ATQA
lprint(f"{prompt}   Fudan ID : {type}")       # show type
lprint(f"{prompt}   Hash     : {hash}")       # show ?Partial HMAC?
lprint(f"{prompt}   Dark Key : {dkey}")       # show key


#------------------------------------------------------------------------------
# crteate validation URL/command/POST
#------------------------------------------------------------------------------

url  = "https://rfid.fm-uivs.com/nfcTools/api/M1KeyRest"
hdr  = "Content-Type: application/text; charset=utf-8"
post = f"{blk0.replace(' ','')}"

lprint(prompt)
lprint(f"{prompt}   Validator: `wget -q  -O -"
       f"  --header=\"{hdr}\""
       f"  --post-data \"{post}\""
       f"  {url}"
       "  | json_pp`")

if args.validate:
	lprint(prompt)
	lprint(f"{prompt} Check Fudan signature (requires internet)...")

	headers = { "Content-Type" : "application/text; charset=utf-8" }
	resp = requests.post(url, headers=headers, data=post)

	if resp.status_code != 200:
		lprint(f"{prompt} HTTP Error {resp.status_code} - check request not processed")

	else:
		r = json.loads(resp.text)
		lprint(f"{prompt} The man from Fudan says: {r['code']} - {r['message']}", end='')
		if r['data'] is not None:
			lprint(f" {{{r['data']}}}")
		else:
			lprint("")
else:
	lprint(prompt)
	lprint(f"{prompt}   ...Use --validate to perform Fudan signature check automatically")

#------------------------------------------------------------------------------
# load keys from file
#------------------------------------------------------------------------------
keyfile = f"{dpath}hf-mf-{uid:08X}-key.bin"

key     = [[0 for _ in range(2)] for _ in range(17)]
keyok   = True  # assume success
badrk   = 0     # 'bad recovered key' count (ie. not recovered)

for i in [0, 1]:
	lprint(prompt)
	lprint(f"{prompt} Load Keys from file: |{keyfile}|")
	try:
		with (open(keyfile, "rb")) as fh:
			for ab in [0, 1]:
				for sec in range(16 +(2-1)):
					key[sec][ab] = fh.read(6)
			break

	except IOError as e:
		lprint(f"{prompt} ! Failed: {str(e)}")
		if i == 1:
			lprint("{prompt} ! Recovery script failed to create keyfile")
			keyok = False

		elif args.recover == False:
			lprint(f"{prompt} * Keys not loaded, use --recover to run recovery script [slow]")
			keyok = False
			break

		else:
			lprint(f"{prompt} Running recovery script, ETA: Less than 30 minutes")
			cmd = "foo.py"

			lprint(prompt)
			lprint(f'{prompt} `-._,-\'"`-._,-"`-._,-\'"`-._,-\'"`-._,-\'"`-._,-\'"`-._,-\'"`-._,-\'"`-._,')

			r = recovery(quiet=False)
			keyfile = r['keyfile']
			rkey    = r['found_keys']
			fdump   = r['dumpfile']
			rdata   = r['data']

			lprint(f'{prompt} `-._,-\'"`-._,-"`-._,-\'"`-._,-\'"`-._,-\'"`-._,-\'"`-._,-\'"`-._,-\'"`-._,')

			for k in range(0, 17):
				for ab in [0, 1]:
					if rkey[k][ab] == "":
						if badrk == 0:  lprint(f"{prompt} Some keys were not recovered: ", end='')
						else:           lprint(f", ", end='')
						badrk += 1

						kn = k
						if kn > 15:  kn += 16
						lprint(f"[{kn}/", end='')
						lprint("A]" if ab == 0 else "B]", end='')
			if badrk > 0:  lprint("")

#------------------------------------------------------------------------------
# verify keys are OK
#------------------------------------------------------------------------------
if keyok:
	bad = 0

	lprint(f"{prompt} Check keys..")

	for sec in range (0,16+1):  # 16 normal, 1 dark
		sn = sec
		if (sn > 15):  sn = sn + 16

		for ab in [0, 1]:
			bn  = (sec * 4) + 3
			if bn >= 64:  bn += 64

			cmd = f"hf mf rdbl -c {ab} --key {key[sec][ab].hex()} --blk {bn}"
			lprint(f"{prompt}   `{cmd}`", end='', flush=True)

			res = p.console(f"{cmd}")
			lprint(" " * (3-len(str(bn))), end="")
			if res == 0:
				lprint(" ... PASS");
			else:
				lprint(" ... FAIL");
				bad += 1

	if bad > 0:
		lprint(f"{prompt} ! {bad} bad key", end='')
		lprint("s exist" if bad != 1 else " exists")
		lprint("{prompt} ! Processing halted")
		exit(101)

	lprint(f"{prompt} All keys verified OK")

	# We need to do this to flush all the output we just collected <shrug>
	for flush in p.grabbed_output.split('\n'):  _ = flush

#------------------------------------------------------------------------------
# read all block data (incl Dark blocks)
#------------------------------------------------------------------------------
'''
[=]   # | sector 00 / 0x00                                | ascii
[=] ----+-------------------------------------------------+-----------------
[=]   0 | 5C B4 9C A6 D2 08 04 00 04 59 92 25 BF 5F 70 90 | \........Y.%._p.
'''

# The user   uses keyhole #1 (-a)
# The vendor uses keyhole #2 (-b)
# The thief  uses keyhole #4 (backdoor)
#                   |___
rdbl = f"hf mf rdbl -c 4 --key {dkey} --blk"
data = []
blkn = list(range(0, 63+1)) + list(range(128, 135+1))

lprint(prompt)
lprint(prompt + " Load blocks {0..63, 128..135}[64+8=72] from the card")

for n in blkn:
	cmd = f"{rdbl} {n}"
	print(f"\r{prompt} `{cmd}`", end='', flush=True)
	p.console(f"{cmd}")

	for line in p.grabbed_output.split('\n'):
		if " | " in line and "# | s" not in line:
			l = line[4:76]
			data.append(l)

print(" .. OK")

#------------------------------------------------------------------------------
#- Patch keys in to data
#------------------------------------------------------------------------------

'''
  3 | 00 00 00 00 00 00 87 87 87 69 00 00 00 00 00 00 | .........i......
'''

lprint(prompt)
lprint(f"{prompt} Patch keys in to data")

for sec in range(0, 17):
	blk = (sec * 4) +3  # find "trailer" for this sector
	if keyok:
		kstr = key[sec][0].hex()
		keyA = "".join([kstr[i:i+2] + " " for i in range(0, len(kstr), 2)])

		kstr = key[sec][1].hex()
		keyB = "".join([kstr[i:i+2] + " " for i in range(0, len(kstr), 2)])

		data[blk] = data[blk][:6] + keyA + data[blk][24:36] + keyB

	else:
		data[blk] = data[blk][:6] + "-- -- -- -- -- -- " + data[blk][24:36] + "-- -- -- -- -- --"

	secn = sec
	if (secn > 15):
		secn += 16

#------------------------------------------------------------------------------
#- Dump data
#------------------------------------------------------------------------------
lprint(prompt)
lprint(f"{prompt} Dump Card Data")

cnt = 0
for n in blkn:
	sec = (cnt // 4)
	if sec > 15:
		sec = sec + 16

	if (n % 4 == 0):
		lprint(f"{prompt} {sec:2d}:{data[cnt]}")
	else:
		lprint(f"{prompt}   :{data[cnt]}")

	cnt += 1
	if (cnt % 4 == 0) and (n != blkn[-1]):  # Space between sectors
		lprint(prompt)

#------------------------------------------------------------------------------
#- Dump bambu details
#- https://github.com/Bambu-Research-Group/RFID-Tag-Guide/blob/main/README.md
#------------------------------------------------------------------------------
'''
      6           18          30          42         53
      |           |           |           |          |
  3 | 00 00 00 00 00 00 87 87 87 69 00 00 00 00 00 00 | .........i......
'''

try:
	if args.bambu == True:
		lprint(f"{prompt}")
		lprint(f"{prompt} Decompose as Bambu tag .. ", end='')

		MaterialVariantIdentifier_s = bytes.fromhex(data[1][ 6:29]).decode('ascii')
		UniqueMaterialIdentifier_s  = bytes.fromhex(data[1][30:53]).decode('ascii')  #[**] 8not16

		FilamentType_s              = bytes.fromhex(data[2][ 6:53]).decode('ascii')

		DetailedFilamentType_s      = bytes.fromhex(data[4][ 6:53]).decode('ascii')

		Colour_rgba                 = int(data[5][ 6:17].replace(' ',''), 16)
		SpoolWeight_g               = int(data[5][21:23] + data[5][18:20], 16)
		Block5_7to8                 = data[5][24:29]
		FilamentDiameter_mm         = struct.unpack('f', bytes.fromhex(data[5][30:41].replace(' ','')))[0]
		Block5_12to15               = data[5][42:50]

		DryingTemperature_c         = int(data[6][ 9:11] + data[6][ 6: 8], 16)
		DryingTime_h                = int(data[6][15:17] + data[6][12:14], 16)
		BedTemperatureType_q        = int(data[6][21:23] + data[6][18:20], 16)
		BedTemperature_c            = int(data[6][27:29] + data[6][24:26], 16)
		MaxTemperatureForHotend_c   = int(data[6][33:35] + data[6][30:32], 16)
		MinTemperatureForHotend_c   = int(data[6][39:41] + data[6][36:38], 16)
		Block6_12to15               = data[6][42:50]

#		XCamInfo_x                  = bytes.fromhex(data[8][ 6:41].replace(' ',''))
		XCamInfo_x                  = data[8][ 6:41]
		NozzleDiameter_q            = struct.unpack('f', bytes.fromhex(data[8][42:53].replace(' ','')))[0]

#		TrayUID_s                   = bytes.fromhex(data[9][ 6:53]).decode('ascii') #[**] !ascii
		TrayUID_s                   = data[9][ 6:53]

		Block10_0to3                = data[10][ 6:17]
		SppolWidth_um               = int(data[10][21:23] + data[14][18:20], 16)
		Block10_6to15               = data[10][24:50]

		ProductionDateTime_s        = bytes.fromhex(data[12][ 6:53]).decode('ascii')

		ShortProductionDateTime_s   = bytes.fromhex(data[13][ 6:53]).decode('ascii')

		Block14_0to3                = data[14][ 6:17]
		FilamentLength_m            = int(data[14][21:23] + data[14][18:20], 16)
		Block14_6to15               = data[14][24:51]

		# (16blocks * 16bytes = 256) * 8bits = 2048 bits
		hblk = [42, 44,45,46, 48,49,50, 52,53,54, 56,57,58, 60,61,62]
		Hash = []
		for b in hblk:
			Hash.append(data[b][6:53])

		lprint("[offset:length]")
		lprint(f"{prompt}   Block 1:")
		lprint(f"{prompt}     [ 0: 8] MaterialVariantIdentifier_s = \"{MaterialVariantIdentifier_s}\"")
		lprint(f"{prompt}     [ 8: 8] UniqueMaterialIdentifier_s  = \"{UniqueMaterialIdentifier_s}\"")
		lprint(f"{prompt}   Block 2:")
		lprint(f"{prompt}     [ 0:16] FilamentType_s              = \"{FilamentType_s}\"")
		lprint(f"{prompt}   Block 4:")
		lprint(f"{prompt}     [ 0:16] DetailedFilamentType_s      = \"{DetailedFilamentType_s}\"")
		lprint(f"{prompt}   Block 5:")
		lprint(f"{prompt}     [ 0: 4] Colour_rgba                 = 0x{Colour_rgba:08X}")
		lprint(f"{prompt}     [ 4: 2] SpoolWeight_g               = {SpoolWeight_g}g")
		lprint(f"{prompt}     [ 6: 2] Block5_7to8                 = {{{Block5_7to8}}}")
		lprint(f"{prompt}     [ 8: 4] FilamentDiameter_mm         = {FilamentDiameter_mm}mm")
		lprint(f"{prompt}     [12: 4] Block5_12to15               = {{{Block5_12to15}}}")
		lprint(f"{prompt}   Block 6:")
		lprint(f"{prompt}     [ 0: 2] DryingTemperature_c         = {DryingTemperature_c}^C")
		lprint(f"{prompt}     [ 2: 2] DryingTime_h                = {DryingTime_h}hrs")
		lprint(f"{prompt}     [ 4: 4] BedTemperatureType_q        = {BedTemperatureType_q}")
		lprint(f"{prompt}     [ 6: 2] BedTemperature_c            = {BedTemperature_c}^C")
		lprint(f"{prompt}     [ 8: 2] MaxTemperatureForHotend_c   = {MaxTemperatureForHotend_c}^C")
		lprint(f"{prompt}     [10: 2] MinTemperatureForHotend_c   = {MinTemperatureForHotend_c}^C")
		lprint(f"{prompt}     [12: 4] Block6_12to15               = {{{Block6_12to15}}}")
		lprint(f"{prompt}   Block 8:")
		lprint(f"{prompt}     [ 0:12] XCamInfo_x                  = {{{XCamInfo_x}}}")
		lprint(f"{prompt}     [12: 4] NozzleDiameter_q            = {NozzleDiameter_q:.6f}__")
		lprint(f"{prompt}   Block 9:")
#		lprint(f"{prompt}     [ 0:16] TrayUID_s                   = \"{TrayUID_s}\"")
		lprint(f"{prompt}     [ 0:16] TrayUID_s                   = {{{TrayUID_s}}}  ; not ASCII")
		lprint(f"{prompt}   Block 10:")
		lprint(f"{prompt}     [ 0: 4] Block10_0to3                = {{{Block10_0to3}}}")
		lprint(f"{prompt}     [ 4: 2] SppolWidth_um               = {SppolWidth_um}um")
		lprint(f"{prompt}     [ 6:10] Block10_6to15               = {{{Block10_6to15}}}")
		lprint(f"{prompt}   Block 12:")
		lprint(f"{prompt}     [ 0:16] ProductionDateTime_s        = \"{ProductionDateTime_s}\"")
		lprint(f"{prompt}   Block 13:")
		lprint(f"{prompt}     [ 0:16] ShortProductionDateTime_s   = \"{ShortProductionDateTime_s}\"")
		lprint(f"{prompt}   Block 14:")
		lprint(f"{prompt}     [ 0: 4] Block10_0to3                = {{{Block10_0to3}}}")
		lprint(f"{prompt}     [ 4: 2] FilamentLength_m            = {FilamentLength_m}m")
		lprint(f"{prompt}     [ 6:10] Block10_6to15               = {{{Block10_6to15}}}")
		lprint(f"{prompt}")
		lprint(f"{prompt}   Blocks {hblk}:")
		for i in range(0, len(hblk)):
			lprint(f"{prompt}     [ 0:16] HashBlock[{i:2d}]  =  {{{Hash[i]}}}   // #{hblk[i]:2d}")

except Exception as e:
	lprint(f"Failed: {e}")

#------------------------------------------------------------------------------
# dump full card to file
#------------------------------------------------------------------------------
dump18 = f"{dpath}hf-mf-{uid:08X}-dump18.bin"

lprint(prompt)
lprint(f"{prompt} Dump Card Data to file: {dump18}")

with open(dump18, 'wb') as f:
	for d in data:
		b = bytes.fromhex(d[6:53].replace(" ", ""))
		f.write(b)

#------------------------------------------------------------------------------
lprint(prompt)
lprint(f"{prompt} Tadah!")
print(prompt)

exit(0)
