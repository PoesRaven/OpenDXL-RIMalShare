#ri_malshare.py (Reputation Ingest - MalShare) 
#This code employes ETL to import new threat indicators from
#malshare.com into your TIE reputation database.
#We assume that anything on the malshare sight is a confirmed
#conviction.

import requests
import json
import os
import sys
import logging
import pprint

import ConfigParser
from datetime import datetime, timedelta

from dxlclient.client import DxlClient
from dxlclient.client_config import DxlClientConfig
from dxltieclient import TieClient
from dxltieclient.constants import HashType, TrustLevel, FileProvider


# Import common logging and configuration
# Assume the common.py is in the CWD. Otherwise you'll need to add its location to the path
# sys.path.append(os.path.dirname(os.path.abspath(__file__)) + "/..")
from common import *


# Configure local logger
logging.getLogger().setLevel(logging.ERROR)
logger = logging.getLogger(__name__)

# Create DXL configuration from file
config = DxlClientConfig.create_dxl_config_from_file(CONFIG_FILE)

# Create config information for MalShare
msConfig = ConfigParser.ConfigParser()
msConfig.read(MS_CONFIG_FILE)


# For now, assume not resolving hashes to filenames... default filename is MalShare.unknown
MALSHARE_APIKEY = msConfig.get("malshare", "apikey")
MALSHARE_API_HOST = msConfig.get("malshare", "ms_host")

logger.info("Pulling data from " + MALSHARE_API_HOST)

strMSResult = requests.get(MALSHARE_API_HOST + '/api.php?api_key=' + MALSHARE_APIKEY + '&action=getlistraw', verify=False).text.encode('utf-8').strip()

MSResult = {}

childcounter=0

logger.info("Enumerating results")

for item in strMSResult.split('\n'):

    # Build a dictionary of results that should be in scope for updating TIE
    MSResult[childcounter] = {}
    MSResult[childcounter]['md5']=item
    MSResult[childcounter]['trustlevel']=TrustLevel.MOST_LIKELY_MALICIOUS
    MSResult[childcounter]['filename'] = "MALSHARE.unknown"
        
    childcounter+=1


logger.info("Pulled {0} hashes from MalShare.".format(childcounter))


# Loop through each file and check with the TIE Server to determine if
# it already exists.
with DxlClient(config) as client:

    #Connect to DXL fabric
    client.connect()

    #Create TIE Client
    tie_client=TieClient(client)

    
    for fileKey in MSResult:
        #unset reusables
        reputations_dict = None
        #MalShare provides only MD5's
        currentMD5 = None
        currentFilename = None
        currentTrustLevel = None        

        currentMD5= MSResult[fileKey]['md5']
        currentFilename=MSResult[fileKey]['filename']
        currentTrustLevel=MSResult[fileKey]['trustlevel']

        reputations_dict = \
                tie_client.get_file_reputation({
                    HashType.MD5: currentMD5
                    })

        
        #Check if there is an enterprise (custom set) reputation
        if (reputations_dict[FileProvider.ENTERPRISE]["trustLevel"]==TrustLevel.NOT_SET and \
            reputations_dict[FileProvider.GTI]["trustLevel"]==TrustLevel.NOT_SET) or \
            reputations_dict[FileProvider.ENTERPRISE]["trustLevel"]==TrustLevel.UNKNOWN or \
            reputations_dict[FileProvider.ENTERPRISE]["trustLevel"]==TrustLevel.MIGHT_BE_TRUSTED or \
            reputations_dict[FileProvider.ENTERPRISE]["trustLevel"]==TrustLevel.MOST_LIKELY_TRUSTED:
            # If not set, go ahead and set it
            tie_client.set_file_reputation(
                currentTrustLevel, {
                    HashType.MD5: currentMD5},
                filename=currentFilename,
                comment="Reputation set via OpenDXL MalShare Integration")
            print "Reputation set for: " + str(fileKey) + ": " + currentMD5 

        else:
            print "Skipping: " + str(fileKey) + ": " + currentMD5
