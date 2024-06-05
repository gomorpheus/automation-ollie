## Script to poll alerts from Morpheus
## Creates new alert in BMC Helix
## Updates existing alerts over their lifecycle in BMC Helix
## Manages state changes between polls of the Morpheus API using a file cache
## which should be located in the NFS share of a 3 node Morpheus appliance

import requests
from datetime import datetime
import urllib3
from os.path import exists
import json
import sys
##sys.path.append('/usr/lib/python3.6/site-packages/')
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

##from morpheuscypher import Cypher
##c = Cypher(morpheus=morpheus, ssl_verify=False)

## remove this we fake the morpheus dict in development
import fake
c = fake
morpheus = fake.morpheus

## debug mode
debug = True

## configuration
helixUser = c.get("secret/helixUser")
helixPassword = c.get("secret/helixPassword")
helixBaseUrl = "https://nexio-dev-restapi.onbmc.com"

morpheusToken = "Bearer %s" %(morpheus["morpheus"]["apiAccessToken"])
morpheusBaseUrl = morpheus["morpheus"]["applianceHost"]

##alertsStateCacheFile = "/var/opt/morpheus/morpheus-ui/caches/alertsStateCache.json"
alertsStateCacheFile = "./alertsStateCache1.json"
alertsState = []
alertsStateAvailable = False
newAlerts = False
updatedAlerts = False
## TODO review use of these globals
pollIntervalSecs = 300

## gives us the time since last poll
## in format required for lastUpdated in query
## TODO we won't use this remove if not, incidents cannot be queried by lastUpdated
def getSince(pollInt):
    ## we need this format
    ## 2019-03-06T17:52:29+0000
    now = datetime.now().timestamp()
    since = int(now) - pollInt
    formatted = datetime.utcfromtimestamp(since).strftime('%Y-%m-%d %H:%M:%S')
    msg = "Since: %s" % formatted
    debugP(msg)
    return formatted

## in preflight we have some simple debugging plus
## we either load the previous state from the state cache if it exists
## or we make an initial call to incidents endpont to get the current items
## we use this to create the first state file against which we can start to compare
## subsequent calls, each time updating the state with the latest results
def preflight():
    global alertsStateAvailable
    global alertsState
    global morpheusBaseUrl
    global morpheusToken

    msg = "\nuser: %s\npassword: %s\n" % (helixUser, helixPassword)
    debugP(msg)

    ## check for cache, if exists load it
    if exists(alertsStateCacheFile):
        alertsStateAvailable = True
        f = open(alertsStateCacheFile, "r")
        state = f.read()
        alertsState = json.loads(state)
        print("INFO: cached alerts have been read from disk")
        msg = "alertsStateAvailable: %s" % alertsStateAvailable
        debugP(msg)
        debugP("alerts from state:")
        debugP(alertsState)
    else:
        ## if not exist make an initial api call and use this as state
        alerts = pollIncidents(morpheusBaseUrl, morpheusToken)
        alertsState = alerts
        debugP("alerts from initial pull:")
        debugP(alertsState)

## login with username & password to obtain JWT for session
def authenticate(user, password):
    print("INFO: authenticating with remedy server to get JWT")
    authUrl = "%s/api/jwt/login" % helixBaseUrl

    form = {
        "username": user,
        "password": password
    }

    ## only text/plain here
    header = {
        "accept": "text/plain",
        "authString": "",
        "content-type": "application/x-www-form-urlencoded"
    }

    r = requests.post(authUrl, headers=header, verify=False, data=form)
    if not r.ok:
        ## error for some reason
        print("ERROR: authenticating, response code %s: %s" % (r.status_code, r.text))
        raise Exception("Error authenticating, response code %s: %s" % (r.status_code, r.text))
    else:
        ## authenthicated
        print("INFO: authenticated with helix server")
        jwt = r.text
        token = "AR-JWT %s" % jwt
        debugP("token with prefix: %s" % token)

        ## set up and return header map for subsequent requests
        headers = {
            "accept": "application/json",
            "content-type" : "application/json",
            "authorization": token
        }

    return headers

## close the session
def logout(headers):
    logoutUrl = "%s/api/jwt/logout" % helixBaseUrl

    r = requests.post(logoutUrl, headers=headers, verify=False, data=None)
    if not r.ok:
        print("WARN: problem logging out of helix server, response code %s: %s" % (r.status_code, r.text))
    else:
        print("INFO: logged out of helix server")


## additional debug logging
def debugP(message):
    if debug:
        print("DEBUG:", message)

## get incidents from morpheus with API
def pollIncidents(baseURL, token):
    ##lastUpdated = getSince(pollIntervalSecs)
    alertsAPI = "https://%s/api/monitoring/incidents?max=1000&offset=0&Status=open" % (baseURL)
    headers = {
        "accept": "application/json",
        "authorization": token
    }
    res = requests.get(alertsAPI, headers=headers, verify=False)
    alerts = res.json()["incidents"]
    debugP("%s incident(s) found" % len(alerts))
    debugP(alerts)
    return alerts


def main():
    ## pre-flight, prints some debug, checks for existence of cache and if exists loads it
    preflight()

    ## poll morpheus alerts
    morpheusAlerts = pollIncidents(morpheusBaseUrl, morpheusToken)

    ## we have state and we have polled API, we need to compare JSON objects
    ## if in API call and not state file it is new incident
    ## if in state file and not the API call it is closed incident (we only poll for open incidents)
    ## make this calculations, fill two lists, if either list > 0 we need to open a Helix session
    ## and make the appropriate API calls by interating through both lists

    ##headers = authenticate(helixUser, helixPassword)

    ## if we opened a session we need to logout before exit
    ##logout(headers)

    ## we need to update the state file


## start main execution
main()