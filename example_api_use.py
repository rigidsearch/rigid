#!/usr/bin/env python3

import requests
import json

base_url = 'http://localhost:5000'
log_source = "testing"
s = requests.Session()

# login
r = s.post(base_url+'/login', data={"username":"admin", "password":"supersecurepassw0rd"})

if "Invalid credentials" in r.text:
	print("login failed")
	exit(1)

r = s.get(base_url+f'/api/ingest/add/{log_source}')
ingest_token = r.json()['token']

# ingest log; no need for auth, just use ingestion secret token
r = requests.post(base_url+f'/api/ingest/{log_source}/{ingest_token}', data="TEST hello admin")
print(r.status_code, r.text)

# search
query = f'source={log_source} keyword="TEST"'
# need to be logged in, use session
r = s.post(base_url+f'/api/search', json={"q":query})
print(json.dumps(r.json(), indent=2))