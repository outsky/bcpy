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

def err(fmt, *args):
	fmt = "[x] " + fmt
	if not args:
		print(fmt)
	else:
		print(fmt.format(*args))

def info(fmt, *args):
	if not args:
		print(fmt)
	else:
		print(fmt.format(*args))

def debug(fmt, *args):
	if not config.debug_enabled:
		return
	fmt = "[dbg] " + fmt
	if not args:
		print(fmt)
	else:
		print(fmt.format(*args))

def random64():
	return random.randint(1, 1000000000)