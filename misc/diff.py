#!/bin/env python3
"""
Quick script to compare results from old and new API.
"""
import json
import os
import subprocess

import requests

OLD_SERVER = "https://sertifikatsok.no/api"
NEW_SERVER = "http://localhost:7000/api"

# The new API checks that the type of the returning certificate matches
# the search, and the old one doesn't. So searching for a business with
# type=person will yield totally different results. So none of that.
PARAMS = [
    {"query": "Magnus Horsgård Watn", "type": "person", "env": "prod"},
    {"query": "9578-4050-127091783", "type": "person", "env": "prod"},
    {"query": "9578-4050-127091783", "type": "person", "env": "test"},
    {"query": "Silje Fos Port", "type": "person", "env": "test"},
    {"query": "9578-4050-100105758", "type": "person", "env": "test"},
    {"query": "HELSEDIREKTORATET", "type": "enterprise", "env": "test"},
    {"query": "HELSEDIREKTORATET", "type": "enterprise", "env": "prod"},
    {"query": "983 544 622", "type": "enterprise", "env": "test"},
    {"query": "983544622", "type": "enterprise", "env": "test"},
    {"query": "983 544 622", "type": "enterprise", "env": "prod"},
    {"query": "994598759", "type": "enterprise", "env": "prod"},
    {"query": "994598759", "type": "enterprise", "env": "test"},
    {"type": "enterprise", "env": "test"},
    {"query": "HELSEDIREKTORATET", "type": "enterprise", "env": "testdsa"},
    {"query": "HELSEDIREKTORATET", "type": "enterprise", "envda": "test"},
    {"query": "HELSEDIREKTORATET", "env": "test"},
    {"query": "KJERNEJOURNAL", "type": "enterprise", "env": "test"},
    {"query": "KJERNEJOURNAL", "type": "enterprise", "env": "prod"},
]

session = requests.Session()

for params in PARAMS:
    old_response = session.get(OLD_SERVER, params=params)
    new_response = session.get(NEW_SERVER, params=params)

    with open("old", "w") as open_file:
        open_file.write(json.dumps(old_response.json(), indent=4, sort_keys=True))

    with open("new", "w") as open_file:
        open_file.write(json.dumps(new_response.json(), indent=4, sort_keys=True))

    print("###################################################")
    print("DIFF FOR PARAMS: {}".format(params))
    subprocess.run(["diff", "old", "new"])
    print("###################################################")

os.remove("old")
os.remove("new")
