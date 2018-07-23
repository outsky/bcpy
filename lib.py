# coding=utf-8

import random
import config

def printb(bs):
    col = 0
    for b in bs:
        print("%.2X" % b, end = '')
        col += 1
        if col == 8:
            print("  ", end = '')
        elif col == 16:
            col = 0
            print("")
        else:
            print(" ", end = '')
    print("")

def err(s):
	print("[x] {}".format(s))

def info(s):
	print("{}".format(s))

def debug(s):
	if not config.debug_enabled:
		return
	print("[dbg] {}".format(s))

def random64():
	return random.randint(1, 1000000000)