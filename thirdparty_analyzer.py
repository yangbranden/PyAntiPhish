#!/usr/bin/python3

# copypasting a script from another project; will add these in tomorrow
from googleapiclient.discovery import build

api_key = ""
cse_id = ""
query = ""

def google_search(search_term, **kwargs):
    service = build("customsearch", "v1", developerKey=api_key)
    res = service.cse().list(q=search_term, cx=cse_id, **kwargs).execute()
    return res.get("items", None)

# Google makes it so that you can't get more than 10 results at a time
results = google_search(query, num=10)
    