# OpenDXL-RIMalShare
RIMalShare (Reputation Ingest - MalShare) employs ETL to import new threat indicators from malshare.com into your TIE Enterprise Reputations.

## Introduction

RI MalShare takes advantage of newly posted malware hashes submitted to the malshare.com repository. This allows Cyber System Administrators the ability to quickly innoculate all systems in their environment by making them aware of these critical updates.

Several steps take Place
### Extract
  During extraction, RIMalShare pulls the new content for the last 24 hours. You can run this as often as you'd like but I recommend at least every 24 hours. If its an entry which we've already addressed, the process will scope handling it.
 
### Transform

  MalShare returns a simple list seperated by newlines of MD5 hashes. To transform into a Python dictionary object we can use, the process splits on the newline character and enumerates through each.
  No filenames are recorded from MalShare, so we enter MALSHARE.unknown as the filename in transformed data structure.
  
### Load
  
  During the load process, RIMalShare checks that several conditions are met.
  * Both enterprise and GTI trustlevels must not be set
  or
  * The enterprise trust level is unkown or lower. 
  Note: RIMalShare will overwrite trusted enterprise scores with untrusted trust levels.
  
  
  
RIMalShare uses [McAfee TIE DXL Python Client Library](https://github.com/opendxl/opendxl-tie-client-python) for gets and sets

Add pictures here

## Setup

### MalShare

https://www.malshare.com/

* Generate an API key - https://www.malshare.com/register.php
* Update ms.config with the API key
#### edit the ms.config
```
[malshare]
apikey=<API KEY>
ms_host=https://www.malshare.com

```

### McAfee OpenDXL SDK

https://www.mcafee.com/us/developers/open-dxl/index.aspx

McAfee Threat Intelligence Exchange (TIE) DXL Python Client Library at the follow link:

https://github.com/opendxl/opendxl-tie-client-python/wiki

* Certificate Files Creation [link](https://opendxl.github.io/opendxl-client-python/pydoc/certcreation.html)
* ePO Certificate Authority (CA) Import [link](https://opendxl.github.io/opendxl-client-python/pydoc/epocaimport.html)
* ePO Broker Certificates Export  [link](https://opendxl.github.io/opendxl-client-python/pydoc/epobrokercertsexport.html)



#### edit the dxlclient.config
```
[Certs]
BrokerCertChain=certs/brokercert.crt
CertFile=certs/client.crt
PrivateKey=certs/client.key

[Brokers]
{}={};8883;
```
