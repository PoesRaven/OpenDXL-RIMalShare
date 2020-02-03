#ri_malshare.py (Reputation Ingest - MalShare) 
#This code employes ETL to import new threat indicators from
#malshare.com into your TIE reputation database.
#We assume that anything on the malshare sight is a confirmed
#conviction.

import requests
import logging

import csv
import configparser as ConfigParser
from datetime import datetime, timedelta

from dxlclient.client import DxlClient
from dxlclient.client_config import DxlClientConfig
from dxltieclient import TieClient
from dxltieclient.constants import HashType, TrustLevel, FileProvider


# Import common logging and configuration
# Assume the common.py is in the CWD. Otherwise you'll need to add its location to the path
# sys.path.append(os.path.dirname(os.path.abspath(__file__)) + "/..")
from common import *

convert_trust = {}
convert_trust[TrustLevel.KNOWN_TRUSTED_INSTALLER] = "Known Trusted Installer"
convert_trust[TrustLevel.KNOWN_TRUSTED] = "Known Trusted"
convert_trust[TrustLevel.MOST_LIKELY_TRUSTED] = "Most Likely Trusted"
convert_trust[TrustLevel.MIGHT_BE_TRUSTED] = "Might Be Trusted"
convert_trust[TrustLevel.UNKNOWN] = "Unknown"
convert_trust[TrustLevel.MIGHT_BE_MALICIOUS] = "Might Be Malicious"
convert_trust[TrustLevel.MOST_LIKELY_MALICIOUS] = "Most Likely Malicious"
convert_trust[TrustLevel.KNOWN_MALICIOUS] = "Known Malicious"
convert_trust[TrustLevel.NOT_SET] = "Not Set"


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

for item in strMSResult.split(b'\n'):

    if childcounter > 5:
        break
    # Build a dictionary of results that should be in scope for updating TIE
    MSResult[childcounter] = {}
    MSResult[childcounter]['md5']=item
    MSResult[childcounter]['trustlevel']=TrustLevel.MOST_LIKELY_MALICIOUS
    MSResult[childcounter]['filename'] = "MALSHARE.unknown"
        
    childcounter+=1


logger.info("Pulled {0} hashes from MalShare.".format(childcounter))

csv_document = {}
fieldnames = []
fieldnames.append('md5')

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

        currentMD5= MSResult[fileKey]['md5'].split()[0]
        currentFilename=MSResult[fileKey]['filename']
        currentTrustLevel=MSResult[fileKey]['trustlevel']

        reputations_dict = \
                tie_client.get_file_reputation({
                    HashType.MD5: currentMD5
                    })


        print(reputations_dict)
        csv_row = {}
        csv_row['md5'] = currentMD5.decode('ascii')
        if FileProvider.GTI in reputations_dict.keys():
            if 'gti' not in fieldnames:
                fieldnames.append('gti')
            csv_row['gti'] = convert_trust[reputations_dict[FileProvider.GTI]["trustLevel"]]
        if FileProvider.ENTERPRISE in reputations_dict.keys():
            if 'enterprise' not in fieldnames:
                fieldnames.append('enterprise')
            csv_row['enterprise'] = convert_trust[reputations_dict[FileProvider.ENTERPRISE]["trustLevel"]]
        if FileProvider.ATD in reputations_dict.keys():
            if 'atd' not in fieldnames:
                fieldnames.append('atd')
            csv_row['atd'] = convert_trust[reputations_dict[FileProvider.ATD]["trustLevel"]]
        if FileProvider.MWG in reputations_dict.keys():
            if 'mwg' not in fieldnames:
                fieldnames.append('mwg')
            csv_row['mwg'] = convert_trust[reputations_dict[FileProvider.MWG]["trustLevel"]]
        if FileProvider.EXTERNAL in reputations_dict.keys():
            if 'external' not in fieldnames:
                fieldnames.append('external')
            csv_row['external'] = convert_trust[reputations_dict[FileProvider.EXTERNAL]["trustLevel"]]

        csv_document[currentMD5.decode('ascii')] = csv_row

        #Check if there is an enterprise (custom set) reputation
        if (reputations_dict[FileProvider.ENTERPRISE]["trustLevel"] == TrustLevel.NOT_SET and \
            reputations_dict[FileProvider.GTI]["trustLevel"] == TrustLevel.NOT_SET) or \
            reputations_dict[FileProvider.ENTERPRISE]["trustLevel"] == TrustLevel.UNKNOWN or \
            reputations_dict[FileProvider.ENTERPRISE]["trustLevel"] == TrustLevel.MIGHT_BE_TRUSTED or \
            reputations_dict[FileProvider.ENTERPRISE]["trustLevel"] == TrustLevel.MOST_LIKELY_TRUSTED:
            # If not set, go ahead and set it
            tie_client.set_file_reputation(
                currentTrustLevel, {
                    HashType.MD5: currentMD5},
                filename=currentFilename,
                comment="Reputation set via OpenDXL MalShare Integration")
            print("Reputation set for: " + str(fileKey) + ": " + str(currentMD5))

        else:
            print("Skipping: {}: {}".format(fileKey, currentMD5.decode('ascii')))
            print("MD5: {}".format(currentMD5.decode('ascii')))
            print("GTI: {}".format(convert_trust[reputations_dict[FileProvider.GTI]["trustLevel"]]))
            print("Enterprise: {}".format(convert_trust[reputations_dict[FileProvider.ENTERPRISE]["trustLevel"]]))


with open('reputations.csv', 'w', newline='') as file:
    writer = csv.DictWriter(file, fieldnames=fieldnames, quoting=csv.QUOTE_NONNUMERIC)

    writer.writeheader()
    for row in csv_document:
        writer.writerow(csv_document[row])
