## Script to poll incidents from Morpheus
## Creates new incident in BMC Helix
## Updates existing incidents from open to closed in BMC Helix
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

##incidentStateCacheFile = "/var/opt/morpheus/morpheus-ui/caches/incidentStateCache.json"
incidentStateCacheFile = "./incidentStateCache.json"
incidentState = []
firstPass = False

## in preflight we have some simple debugging plus
## we either load the previous state from the state cache if it exists
## or we make an initial call to incidents endpont to get the current items
## we use this to create the first state file against which we can start to compare
## subsequent calls, each time updating the state with the latest results
def preflight():
    global incidentState
    global morpheusBaseUrl
    global morpheusToken
    global firstPass

    if debug:
        print("INFO: script is running in debug mode, expect verbose logging")

    msg = "\nuser: %s\npassword: %s\n" % (helixUser, helixPassword)
    debugP(msg)

    ## check for cache, if exists load it
    if exists(incidentStateCacheFile):
        f = open(incidentStateCacheFile, "r")
        state = f.read()
        incidentState = json.loads(state)
        print("INFO: cached incidents have been read from disk")
        debugP("incidents from state:")
        debugP(incidentState)
    else:
        ## if not exist make an initial api call and use this as state
        incidents = pollIncidents(morpheusBaseUrl, morpheusToken)
        incidentState = incidents
        firstPass = True
        debugP("incidents from initial pull:")
        debugP(incidentState)

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
    incidentsAPI = "https://%s/api/monitoring/incidents?max=1000&offset=0&status=open" % (baseURL)
    headers = {
        "accept": "application/json",
        "authorization": token
    }
    res = requests.get(incidentsAPI, headers=headers, verify=False)
    incidents = res.json()["incidents"]
    debugP("API response: %s incident(s) found" % len(incidents))
    debugP(incidents)
    return incidents

def writeIncidentStateFile(incidents):
    global incidentStateCacheFile
    f = open(incidentStateCacheFile, "w")
    f.write(json.dumps(incidents))
    f.close()
    print("INFO: incidents cached for tracking in file: %s" % incidentStateCacheFile)


def main():
    newIncidents = []
    closedIncidents = []

    ## pre-flight, prints some debug, checks for existence of cache and if exists loads it
    ## if not exist makes an initial call to Morpheus API to create baseline state
    ## which should only be needed on first run
    preflight()

    ## poll morpheus incidents
    morpheusIncidents = pollIncidents(morpheusBaseUrl, morpheusToken)

    ## TODO refactor to functions at some point

    ## we have state and we have polled API, we need to compare JSON objects
    ## if in API call and not state file it is new incident
    print("INFO: checking for new incidents")
    for mInc in morpheusIncidents:
        foundInState = False
        for sInc in incidentState:
            if mInc["id"] == sInc["id"]:
                foundInState = True

        if foundInState == False:
            ## new incident
            newIncidents.append(mInc)

    print("INFO: new incidents: %s" %(len(newIncidents)))

    ## if in state file and not the API call it is closed incident (we only poll for open incidents)
    print("INFO: checking for closed incidents")
    for sInc in incidentState:
        foundInAPI = False
        for mInc in morpheusIncidents:
            if sInc["id"] == mInc["id"]:
                foundInAPI = True
                ## capture existig helix IDs in state including dummy
                if not firstPass:
                    mInc["helixID"] = sInc["helixID"]

        if foundInAPI == False:
            ## closed incident
            closedIncidents.append(sInc)

    print("INFO: closed incidents: %s" %(len(closedIncidents)))

    if (len(closedIncidents) > 0 or len(newIncidents) > 0):
        ## we have changes, we need a session on helix
        print("INFO: there are updates needed on helix")
        headers = authenticate(helixUser, helixPassword)

        if len(newIncidents) > 0:
            ## add new
            ## we will track the array element and use to add the helix incident ref

            for nInc in newIncidents:
                debugP("newIncidents %s, incident %s" % (newIncidents, nInc['id']))

                ## call to helix to create incident
                debugP("creating incident: %s in helix" % cInc["id"])

                ## we need to add the helix ID
                for mInc in morpheusIncidents:
                    if nInc["id"] == mInc["id"]:
                        mInc["helixID"] = "new"


        if len(closedIncidents) > 0:
            ## close the open incidents

            for cInc in closedIncidents:
                ## some incidents formed initial state and were not created in helix
                ## ignore all closed incidents with helixID of "dummy"
                if cInc["helixID"] != "dummy":
                    ## call to helix to update the incident to closed
                    debugP("closing morpheus incident id: %s, helix id: %s in helix" % (cInc["id"], cInc["helixID"]))

        ## if we opened a session we need to logout before exit
        logout(headers)
    else:
        print("INFO: there are no updates to make on helix")

    ## if this is a first pass we need to add a dummy helix id, so we can ignore these and not attempt to close them
    ## because we will not have created them in Helix
    if firstPass:
        debugP("first pass adding dummy helixID")
        for mInc in morpheusIncidents:
            morpheusIncidents[dummyCounter]["helixID"] = "dummy"

    ## we need to update the state file even if no changes, as we haven't written it yet
    writeIncidentStateFile(morpheusIncidents)

    print("INFO: script execution complete")


## start main execution
main()