#!/bin/bash

#------------------------------------------------------------------------------
#- Sanitise the input
#------------------------------------------------------------------------------

BLK0=`sed 's/ //g' <<<$*`

if ((${#*} != 16)) || (( ${#BLK0} != 32 )) || ! ((16#${BLK0})) 2>/dev/null; then
	echo "Use: $0 <block 0 data as bytes>"
	echo "Ie.  $0 00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF"
	exit 1
fi

#------------------------------------------------------------------------------
#- Start
#------------------------------------------------------------------------------

byte=($*)

echo "                   BCC         ++---- RF08S ID -----++"
echo "       UID         !  SAK      !!                   !!"
echo "       !           !  !  ATQA  !!     RF08S Hash    !!"
echo "       !---------. !. !. !---. VV .---------------. VV"
echo "Data : ${byte[@]}"

#------------------------------------------------------------------------------
#- Break it down
#------------------------------------------------------------------------------

# "UID" is reserved!
CUID=${byte[0]}${byte[1]}${byte[2]}${byte[3]}
BCC=${byte[4]}

SAK=${byte[5]}
ATQA=${byte[6]}${byte[7]}

IDA=${byte[8]}
IDB=${byte[15]}
ID="${IDA}${IDB}"

HMAC=${byte[9]}${byte[10]}${byte[11]}${byte[12]}${byte[13]}${byte[14]}

#echo "Check: ${BLK0:0:8} ${BLK0:8:2} ${BLK0:10:2} ${BLK0:12:4} ${BLK0:16:2} ${BLK0:18:12} ${BLK0:30:2}"

#------------------------------------------------------------------------------
#- Check UID BCC
#------------------------------------------------------------------------------

echo -n "UID  : ${CUID}/${BCC}"

CRC=0
for b in ${byte[@]:0:4} ; do (( CRC ^= 0x${b} )) ; done

(( ${CRC} == 16#${BCC} )) && {
	echo " - valid"
} || {
	printf " - invalid, expecting %02X\n" ${CRC}
}

#------------------------------------------------------------------------------
#- Check SAK  --  qv.  hf_mf_autopwn.lua
#- Full alorithm:  https://www.nxp.com/docs/en/application-note/AN10833.pdf
#------------------------------------------------------------------------------

echo -n "SAK  : ${SAK} - "
case ${SAK} in
	01) echo "NXP MIFARE TNP3xxx 1K"                     ;;
	08) echo "NXP MIFARE CLASSIC 1k | Plus 1k | Ev1 1K"  ;;
	09) echo "NXP MIFARE Mini 0.3k"                      ;;
	10) echo "NXP MIFARE Plus 2k"                        ;;
	18) echo "NXP MIFARE Classic 4k | Plus 4k | Ev1 4k"  ;;
	*)  echo "{unknown}"                                 ;;
esac

#------------------------------------------------------------------------------
#- ATQA
#------------------------------------------------------------------------------

echo "ATQA : ${ATQA}"

#------------------------------------------------------------------------------
#- Fudan card identity
#------------------------------------------------------------------------------

echo -n "Card : ${ID} - "

card=0  # assume failure

if   [[ ${IDB} == 90 ]] ; then
	if [[ ${IDA} == 01 ||  ${IDA} == 03 ||  ${IDA} == 04 ]] ; then
		echo -n "Fudan FM11RF08S"
		card=1
	fi

elif [[ ${IDB} == 1D ]] ; then
	if [[ ${IDA} == 01 ||  ${IDA} == 02 ||  ${IDA} == 03 ]] ; then
		echo -n "Fudan FM11RF08"
		card=1;
	fi

elif [[ ${IDB} == 91 || ${IDB} == 98 ]] ; then
		echo -n "Fudan FM11RF08 (never seen)"
		card=1;
fi

# --- Either abort (for unknown cards), or display the card info
((card == 0)) && {
	echo "Unknown - submission aborted."
	exit 9
} || {
	echo " .. HMAC=${HMAC}"
}

#------------------------------------------------------------------------------
#- Doit!
#------------------------------------------------------------------------------

URL=https://rfid.fm-uivs.com/nfcTools/api/M1KeyRest
HDR="Content-Type: application/text; charset=utf-8"

echo "Submit \"${BLK0}\" to ${URL}"

wget -q  -O -  --header="${HDR}"  --post-data "${BLK0}"  ${URL}  \
| json_pp
