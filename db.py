# coding: utf-8

# using Berkeley DB

import bsddb3

class DataBase:
	def __init__(self, db_name):
		self.db = bsddb3.btopen(db_name, "c")

	def get(self, key):
		if key in self.db:
			return self.db[key]
		else:
			return None

	def add(self, key, value):
		self.db[key] = value

	def save(self):
		self.db.sync()

	def keys(self):
		return self.db.keys()