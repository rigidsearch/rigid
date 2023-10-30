#!/usr/bin/env python3

from waitress import serve
from flask import Flask, request, render_template, session, jsonify, redirect, url_for
import sqlite3
import os
import logging
from hashlib import sha1, md5
import base64
import random
import json
logger = logging.getLogger('waitress')
logger.setLevel(logging.INFO)


app = Flask(__name__)
app.secret_key = sha1(open("/dev/urandom",'rb').read(30)).hexdigest()

if os.getenv("SECRET_KEY"):
	app.secret_key = os.getenv("SECRET_KEY")



# base64 basic auth for admin and readonly user
ADMIN_AUTH = os.getenv("ADMIN_AUTH")
RO_AUTH = os.getenv("RO_AUTH")

AUTH_ADMIN_USERPASS = None
AUTH_RO_USERPASS = None

if not ADMIN_AUTH: # terrible default creds!
	default_creds = f"admin:rigid"
	ADMIN_AUTH = base64.b64encode(default_creds.encode()).decode()
	logger.warning("ADMIN_AUTH not set, default_creds:" + default_creds)

if ADMIN_AUTH:
	AUTH_ADMIN_USERPASS = base64.b64decode(ADMIN_AUTH).decode().split(":")

if RO_AUTH:
	AUTH_RO_USERPASS = base64.b64decode(RO_AUTH).decode().split(":")

DB_CONNSTR = os.getenv("DB_CONNSTR")
if not DB_CONNSTR:
	DB_CONNSTR = ":memory:"

db = sqlite3.connect(DB_CONNSTR, check_same_thread=False)
# prepare tables
cur = db.cursor()
cur.execute('CREATE TABLE logs (source TEXT, log TEXT, ts DATETIME DEFAULT CURRENT_TIMESTAMP)')
cur.execute('CREATE TABLE ingest (source TEXT PRIMARY KEY, token TEXT, time_added DATETIME DEFAULT CURRENT_TIMESTAMP)')


class Condition():

	def __init__(self, source, keyword, inverse=False, delimiter=" ", field=None):
		self.source = source
		self.keyword = keyword
		self.inverse = inverse
		self.field = field
		self.delimiter = delimiter

	def get_matches(self, existing_logs=None) -> bool:
		'''
		return true if it matches the log, false otherwise
		always case insensitive
		'''
		result = []
		delimited = [] # same as above, but just the logs delimited

		if not existing_logs:
			if not self.inverse:
				cur = db.cursor()
				cur.execute("SELECT source,log,ts FROM logs WHERE source = ? AND log LIKE ? ORDER BY ts DESC", (self.source, '%'+self.keyword+'%'))
				rows = cur.fetchall()
				result.extend(rows)
			else:
				cur = db.cursor()
				cur.execute("SELECT source,log,ts FROM logs WHERE source = ? AND log NOT LIKE ? ORDER BY ts DESC", (self.source, '%'+self.keyword+'%'))
				rows = cur.fetchall()
				result.extend(rows)


		if self.field != None:
			for source,log,ts in result:
				try:
					delimited.append(log.split(self.delimiter)[self.field])
				except IndexError:
					delimited.append("INDEX_ERROR")

		return result, delimited

	def to_dict(self):
		return {"source": self.source, "keyword": self.keyword, "delimiter":self.delimiter, "field": self.field, "inverse":self.inverse}
		



def parse_conditions_from_q(q):
	'''
	parse a search query string and return conditions
	'''
	conditions = []
	statements = q.split(" AND ")
	for s in statements:
		inverse = False
		delimiter = None
		field = None
		keyword = ''
		if s.strip().startswith("NOT"):
			inverse = True
		source = s.split('source=')[1].split()[0]
		if 'keyword=' in s:
			keyword = s.split('keyword="')[1].split('"')[0]
		if "delimiter=" in s:
			delimiter = s.split('delim=^^')[1].split('^^')[0]
		if "field=" in s: # field number
			field = int(s.split('field=')[1].split()[0])

		# in order
		conditions.append(Condition(source, keyword, inverse=inverse, delimiter=delimiter, field=field))

	return conditions

@app.route("/")
def index():
	if session.get("role"): # admin or readonly; if logged in
		sources = []
		cur = db.cursor()
		cur.execute("SELECT source FROM ingest")
		r = cur.fetchall()
		if r:
			sources.extend(r)
		return render_template('index.html.j2', role=session['role'], sources=sources)
	else:
		return render_template('login.html.j2')

@app.route("/login", methods=["POST"])
def login():
	username = request.form["username"]
	password = request.form["password"]

	if AUTH_ADMIN_USERPASS and username == AUTH_ADMIN_USERPASS[0] and password == AUTH_ADMIN_USERPASS[1]:
		session['role'] = 'admin'
		return redirect(url_for('index'))
	elif AUTH_RO_USERPASS and username == AUTH_RO_USERPASS[0] and password == AUTH_RO_USERPASS[1]:
		session['role'] = 'readonly'
		return redirect(url_for('index'))
	else:
		return render_template('login.html.j2', msg="Invalid credentials.")



@app.route("/api/ingest/add/<source>", methods=["GET","POST"])
def add_source(source):
	'''
	add source to db and return ingest secret token
	'''
	if session.get('role') == 'admin':
		token = md5(open("/dev/urandom", "rb").read(30)).hexdigest()
		cur = db.cursor()
		cur.execute("INSERT OR IGNORE INTO ingest (source, token) values (?, ?)", (source, token))
		db.commit()
		cur.execute("SELECT token FROM ingest where source = ?", (source,))
		token = cur.fetchone()[0]

		return jsonify({"source":source, "token":token})
	else:
		return jsonify({"error":"unauthorized"}), 403

@app.route("/api/ingest/rotate/<source>", methods=["GET","POST"])
def rotate_source_token(source):
	'''
	add source to db and return ingest secret token
	'''
	if session.get('role') == 'admin':
		token = md5(open("/dev/urandom", "rb").read(30)).hexdigest()
		cur = db.cursor()
		cur.execute("UPDATE ingest SET token = ? WHERE source = ?", (token, source))
		db.commit()
		return jsonify({"source":source, "token":token})
	else:
		return jsonify({"error":"unauthorized"}), 403

@app.route("/api/ingest/<source>/<token>", methods=["POST"])
def ingest(source, token):
	'''
	ingest logs
	'''
	log = 'INGEST_ERROR'
	try:
		log = request.get_data().decode()
	except UnicodeDecodeError:
		log = str(request.get_data())


	cur = db.cursor()
	cur.execute("SELECT * FROM ingest WHERE source = ? and token = ?", (source, token))
	d = cur.fetchone()
	if not d:
		return jsonify({"error":"bad token"})
	if d[0] == source: # match
		cur.execute("INSERT INTO logs (source, log) VALUES (?,?)", (source,log))
		db.commit()
	else:
		return jsonify({"error":"bad token"})

	if log == 'INGEST_ERROR':
		logger.info(f'bad ingest: {source} {token[:5]}*****')

		
	return jsonify({"status":"OK"})

@app.route("/services/collector", methods=["POST"])
def splunk_json_collector():
	'''
	splunk HEC compat.. lol
	the auth header contains the ingest token. the source will be 
	automagically selected from the token

	if sent in UUID format, the dashes will be stripped out, and 
	the result is the same length as a md5 hash of the token.
	you can format your tokens by adding in dashes and uppercasing them
	if splunk clients complain.

	e.g. "Authorization: Splunk CF179AE4-3C99-45F5-A7CC-3284AA91CF67"
	will use the ingest token cf179ae43c9945f5a7cc3284aa91cf67
	'''
	token = None
	auth_header = request.headers.get("Authorization")

	if auth_header:
		if auth_header.startswith("Splunk "):
			token = auth_header.split("Splunk ")[1]
		elif auth_header.startswith("Basic "):
			token = base64.b64decode(auth_header.split("Basic ")[1]).decode().split(':')[1]
	else:
		return "Unauthorized", 401

	if '-' in token:
		token = token.replace('-','').lower()


	log = 'INGEST_ERROR'
	try:
		log = request.get_data().decode()
	except UnicodeDecodeError:
		log = str(request.get_data())
	cur = db.cursor()
	cur.execute("SELECT source FROM ingest WHERE token = ?", (token,))
	r = cur.fetchone()
	if r:
		source = r[0]

		# decode multiple json events like 
		# {"event": "Pony 1 has left the barn"}{"event": "Pony 2 has left the barn"}{"event": "Pony 3 has left the barn", "nested": {"key1": "value1"}}
		if log.startswith('{"'): # decode json
			jsonl = '['+log+']' # should work even with just one event
			for d in json.loads(jsonl):
				# ingest them as separate events	
				cur.execute("INSERT INTO logs (source, log) VALUES (?,?)", (source, json.dumps(d)))
			db.commit()
		else:
			logger.info('splunk bad json log: ' + log)
			# ingest it anyway
			cur.execute("INSERT INTO logs (source, log) VALUES (?,?)", (source, log))
			db.commit()

		return "OK"
	else:
		return "Bad token", 401


	
@app.route("/services/collector/<subpath>", methods=["POST"])
def splunk_raw(subpath):
	'''
	splunk HEC compat.. lol
	'''
	token = None
	auth_header = request.headers.get("Authorization")

	if auth_header:
		if auth_header.startswith("Splunk "):
			token = auth_header.split("Splunk ")[1]
		elif auth_header.startswith("Basic "):
			token = base64.b64decode(auth_header.split("Basic ")[1]).decode().split(':')[1]
	else:
		return "Unauthorized", 401
	log = 'INGEST_ERROR'
	try:
		log = request.get_data().decode()
	except UnicodeDecodeError:
		log = str(request.get_data())

	if '-' in token:
		token = token.replace('-','').lower()

	cur = db.cursor()
	cur.execute("SELECT source FROM ingest WHERE token = ?", (token,))
	r = cur.fetchone()
	if r:
		source = r[0]
		# logger.info("splunk source: "+source)

		if subpath == "raw":

			try:
				log = request.get_data().decode()
			except UnicodeDecodeError:
				log = str(request.get_data())
			
			cur.execute("SELECT source FROM ingest WHERE token = ?", (token,))
			r = cur.fetchone()
			if r:
				source = r[0]
				for l in log.split("\n"): # line sep'd
					cur.execute("INSERT INTO logs (source, log) VALUES (?,?)", (source, l))
				db.commit()

		if subpath == "event":
			# explicit json fields

			jsonl = '['+log+']' # should work even with just one event
			try:
				for d in json.loads(jsonl):
					cur.execute("INSERT INTO logs (source, log) VALUES (?,?)", (source, json.dumps(d)))
				db.commit()
			except:
				logger.warning("Could not load json" + jsonl)
				cur.execute("INSERT INTO logs (source, log) VALUES (?,?)", (source, log))
				db.commit()


		cur.close()
		return "OK"
	else:
		return "Bad token", 401



@app.route("/api/search", methods=["GET","POST"])
def search():
	'''
	correlation is a first class citizen
	'''
	q = None
	if request.method == "GET":
		q = request.args.get("q")
	elif request.method == "POST":
		q = request.form.get("q")
		if request.is_json:
			q = request.get_json().get("q")

	search_results = []
	results_delim = []

	if session.get("role") == "readonly" or session.get("role") == "admin":
		# parse query
		conditions = parse_conditions_from_q(q)
		for cond in conditions:
			tmp_results, tmp_delim = cond.get_matches()

			if results_delim != []:
				for source,log,ts in tmp_results:
					for d in set(results_delim):
						if d.lower() in log.lower(): #case insensitive
							search_results.append((source,log,ts))
			else:
				search_results.extend(tmp_results)

			results_delim.extend(tmp_delim)

		return jsonify({"conditions": [c.to_dict() for c in conditions], "results":[search_results]})

	else:
		return jsonify({"error":"unauthorized"}), 403

if os.getenv("FLASK_DEBUG"):
	app.run(host='127.0.0.1', port=5000, debug=True)
else:
	port = 5000
	serve(app, host='0.0.0.0', port=port)

