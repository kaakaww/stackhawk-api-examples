import requests
import os
import time
import math
from ratelimiter import RateLimiter
import json
from dotenv import load_dotenv

api_host = "https://api.stackhawk.com"
auth_token = None
auth_token_expiration = time.time()
orgId = None


def get_auth_token():
    global auth_token
    global auth_token_expiration
    auth_url = "/api/v1/auth/login"
    headers = {"X-ApiKey": os.environ.get('APIKEY')}
    try:
        response = requests.get(api_host + auth_url, headers=headers)
        response.raise_for_status()
    except Exception as e:
        print(e)
        return False
    else:
        auth_token = response.json()['token']
        auth_token_expiration = time.time()+1800
        return True


def refresh_token():
    def decorator(func):
        def wrapper(*args, **kwargs):
            if time.time() > auth_token_expiration:
                get_auth_token()
            return func(*args, **kwargs)
        return wrapper
    return decorator


@RateLimiter(max_calls=240, period=1)
@refresh_token()
def get_audit_events():
    start_time, end_time = get_time_range()
    page_size = 100
    current_page = 0
    audit_url = "/api/v1/org/{}/audit".format(orgId)
    params = {'start': start_time, 'end': end_time, 'sortfield': 'createdDate',
              'pageToken': current_page, 'pageSize': page_size}
    headers = {"Authorization": "Bearer " + auth_token}
    response = requests.get(api_host+audit_url, headers=headers, params=params)
    total_records = response.json()['totalCount']
    pages = math.ceil(int(total_records) / page_size)
    for i in range(current_page, pages):
        next_page_token = response.json()['nextPageToken']
        records = response.json()['auditRecords']
        if len(records) > 0:
            for record in records:
                record['payload'] = json.loads(record['payload'].replace('\\',''))
                print(json.dumps(record))
        else:
            next()
        params = {'start': start_time, 'end': end_time, 'sortfield': 'createdDate',
                  'pageToken': next_page_token, 'pageSize': page_size}
        response = requests.get(api_host + audit_url, headers=headers, params=params)
    return True


def get_time_range():
    # Look for a file with the start time in UnixTS
    # If we find it, extract and use the time
    # If we don't find it use no begin time and meow as the end time
    # write back the end time to the file for the next run
    file_name = "last_audit_run_ts.txt"
    start_time = 0
    end_time = time.time()
    if os.path.isfile(file_name):
        try:
            f = open(file_name, "r")
            start_time = f.readline()
            f.close()
            if start_time == '' or start_time is None:
                start_time = 0
        except Exception as e:
            print('File did not exist or was empty. Using {}').format('0')
    start_time = float(start_time)
    f = open(file_name, "w")
    f.write(str(end_time))
    f.close()
    # ahh milliseconds
    return int(start_time*1000), int(end_time*1000)


if __name__ == '__main__':
    load_dotenv()
    orgId = os.environ.get('ORGID')
    if orgId is None:
        exit()
    get_auth_token()
    get_audit_events()

