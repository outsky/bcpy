import random
import config
import hashlib

def printb(bs):
    col = 0
    for b in bs:
        print("%.2X" % b, end = '')
        col += 1
        if col == 8:
            #print("  ", end = '')
            print(" ", end = '')
        elif col == 16:
            col = 0
            print("")
        else:
            print(" ", end = '')
    print("")

def hexstr2bytes(hex):
	if hex[:2] == "0x":
		hex = hex[2:]
	return bytes.fromhex(hex)

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

def double_hash(v):
	return hashlib.sha256(hashlib.sha256(v).digest()).digest()

def single_hash(v):
	return hashlib.sha256(v).digest()

def _merkle_root(nodes):
	nodes = [double_hash(node)[::-1] for node in nodes]
	while len(nodes) > 1:
		if len(nodes) % 2 != 0:
			nodes.append(nodes[-1])
		nodes = [double_hash(nodes[2 * i] + nodes[2 * i + 1]) for i in range(len(nodes) // 2)]
	return nodes[0][::-1]

def merkle_root(txs):
	if len(txs) <= 0:
		return b""

	nodes = [tx.tobytes() for tx in txs]
	return _merkle_root(nodes)
