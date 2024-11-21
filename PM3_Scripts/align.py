#!/usr/bin/env python3

import sys
import argparse
import pm3

def main():
    p = pm3.pm3()  # console interface

    # --- Parse CLI ---
    parser = argparse.ArgumentParser(description='Tag Alignment Tool."')
    parser.add_argument('-a',    action="store_true",  help='Use keyhole A (#0)')
    parser.add_argument('-b',    action="store_true",  help='Use keyhole B (#1)')
    parser.add_argument('-c',    type=int,             help='Use keyhole #N')
    parser.add_argument('-n',    type=int, default=64, help='Stop after N consecutive successfull reads [64]')
    parser.add_argument('--blk', type=int,             help='Specify a block {0..N}')
    parser.add_argument('--key', type=str,             help='Specify a key [112233445566]')
    args = parser.parse_args()

    #            FM11RF08S            FM11RF08            FM11RF32           not-set              MAD
    xkey = [["A396EFA4E24F",4], ["A31667A8CEC1",4], ["518b3354E760",4], ["FFFFFFFFFFFF",0], ["a0a1a2a3a4a5", 0]]

    # --- Validate CLI args ---
    hole = -1
    hcnt = 0
    if args.a in locals():  hcnt += 1 ; hole = 0
    if args.b in locals():  hcnt += 1 ; hole = 1
    if args.c in locals():  hcnt += 1 ; hole = args.c
    if hcnt > 1:
        show("Only specify -a, -b, or -c N")
        sys.exit(1)

    gotkey = True if args.key in locals() else False

    if gotkey and hcnt == 0:
        show("--key requires a companion -a, -b, or -c N")
        sys.exit(2)
    if not gotkey and hcnt > 0:
        show("keyhole specifiers {-a, -b, -c N} require a companion --key")
        sys.exit(3)

    # --- If no key specified, try to find one ---
    xcnt = len(xkey)
    while not gotkey:
        for i in range(xcnt):
            k = xkey[i]
            print(f"\r    Trying key {i}/{xcnt} : -c {k[1]} -k {k[0]}", end='', flush=True)
            cmd = f"hf mf rdbl -c {k[1]} --key {k[0]} --blk 0"
            res = p.console(cmd)

            err = -1
            for line in p.grabbed_output.split('\n'):
                if   "ascii"            in line:  err = 0
                elif "Can't select"     in line:  err = 1
                elif "Auth error"       in line:  err = 2
                elif "Read block error" in line:  err = 3
            if err == 0:
                print(" - OK\n")
                gotkey = True
                break

    print(f"    Use ^C to abort, this will kill the pm3 interface")
    print(f"    ...but when you restart it, your tag wil be nicely aligned :)\n")

    print(f"    Key: _ No card ; - Auth error ; ~ Read error ; * Read OK\n")

    print(f"    Polling for {args.n} consecutive successful reads: ", end='', flush=True)

    pcnt = args.n
    while pcnt:
        res = p.console(cmd)
        for line in p.grabbed_output.split('\n'):
            if   "ascii"            in line:  print("*", end='', flush=True) ; pcnt -= 1
            elif "Can't select"     in line:  print("_", end='', flush=True) ; pcnt = args.n
            elif "Auth error"       in line:  print("-", end='', flush=True) ; pcnt = args.n
            elif "Read block error" in line:  print("~", end='', flush=True) ; pcnt = args.n

if __name__ == "__main__":
    main()
