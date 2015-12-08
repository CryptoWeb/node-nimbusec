Nimbusec client API library for Node.js
=======================================

## Usage Example
```javascript
var nimbusecAPI = require('nimbusec');

var api = new nimbusecAPI('NIMBUSEC-KEY', 'NIMBUSEC-SECRET');
api.findDomains(null, function(err, domains) {

    if (err) {
        console.log('An error occured : ');
        console.log(' - code : '+ err.statusCode);
        console.log(' - message : '+ err.message);
        process.exit(1);
    }

    console.log('My domains are :');
    for (var i = 0; i < domains.length; i++) {
        console.log('  - ' + domains[i].name);
    }
});
```

## Commands

### Generate HTML documentation
```bash
$ grunt doc
```

### Generate README.md file
```bash
$ grunt shell:generateReadme
```

### Check the coding style
```bash
$ grunt shell:checkCodingStyle
```

## To Do
* Implement /v2/user/* part of the API
* Implement /v2/domain/<id>/screenshot/* part of the API when available

## API Reference
<a name="NimbusecAPI"></a>
### NimbusecAPI
**Kind**: global class  
**Access:** public  

* [NimbusecAPI](#NimbusecAPI)
  * [new NimbusecAPI(key, secret, [options])](#new_NimbusecAPI_new)
  * _instance_
    * [.findBundles(filter, callback)](#NimbusecAPI+findBundles)
    * [.findDomains(filter, callback)](#NimbusecAPI+findDomains)
    * [.createDomain(domain, callback)](#NimbusecAPI+createDomain)
    * [.updateDomain(domain, domainID, callback)](#NimbusecAPI+updateDomain)
    * [.deleteDomain(domainID, callback)](#NimbusecAPI+deleteDomain)
    * [.findAgentToken(filter, callback)](#NimbusecAPI+findAgentToken)
    * [.createAgentToken(agentToken, callback)](#NimbusecAPI+createAgentToken)
    * [.deleteAgentToken(agentToken, callback)](#NimbusecAPI+deleteAgentToken)
    * [.findInfectedDomains(filter, callback)](#NimbusecAPI+findInfectedDomains)
    * [.findDomainResults(domainID, filter, callback)](#NimbusecAPI+findDomainResults)
    * [.updateDomainResult(resultID, result, callback)](#NimbusecAPI+updateDomainResult)
    * [.getDomainMetadata(domainID, callback)](#NimbusecAPI+getDomainMetadata)
    * [._getOrDelete(getOrDeleteFn, uri, callback)](#NimbusecAPI+_getOrDelete) ℗
    * [._postOrPut(postOrPutFn, uri, filter, callback)](#NimbusecAPI+_postOrPut) ℗
    * [._get(uri, filter, callback)](#NimbusecAPI+_get) ℗
    * [._delete(uri, callback)](#NimbusecAPI+_delete) ℗
    * [._post(uri, obj, callback)](#NimbusecAPI+_post) ℗
    * [._put(uri, obj, callback)](#NimbusecAPI+_put) ℗
  * _inner_
    * [~findBundlesCallback](#NimbusecAPI..findBundlesCallback) : <code>function</code>
    * [~findDomainsCallback](#NimbusecAPI..findDomainsCallback) : <code>function</code>
    * [~createDomainCallback](#NimbusecAPI..createDomainCallback) : <code>function</code>
    * [~updateDomainCallback](#NimbusecAPI..updateDomainCallback) : <code>function</code>
    * [~deleteDomainCallback](#NimbusecAPI..deleteDomainCallback) : <code>function</code>
    * [~findAgentTokenCallback](#NimbusecAPI..findAgentTokenCallback) : <code>function</code>
    * [~createAgentTokenCallback](#NimbusecAPI..createAgentTokenCallback) : <code>function</code>
    * [~deleteAgentTokenCallback](#NimbusecAPI..deleteAgentTokenCallback) : <code>function</code>
    * [~findInfectedDomainsCallback](#NimbusecAPI..findInfectedDomainsCallback) : <code>function</code>
    * [~findDomainResultsCallback](#NimbusecAPI..findDomainResultsCallback) : <code>function</code>
    * [~updateDomainResultCallback](#NimbusecAPI..updateDomainResultCallback) : <code>function</code>
    * [~getDomainMetadataCallback](#NimbusecAPI..getDomainMetadataCallback) : <code>function</code>
    * [~Domain](#NimbusecAPI..Domain) : <code>object</code>
    * [~DomainMetadata](#NimbusecAPI..DomainMetadata) : <code>object</code>
    * [~Result](#NimbusecAPI..Result) : <code>object</code>
    * [~Package](#NimbusecAPI..Package) : <code>object</code>
    * [~Agent](#NimbusecAPI..Agent) : <code>object</code>
    * [~AgentToken](#NimbusecAPI..AgentToken) : <code>object</code>
    * [~User](#NimbusecAPI..User) : <code>object</code>
    * [~Notification](#NimbusecAPI..Notification) : <code>object</code>
    * [~CMS](#NimbusecAPI..CMS) : <code>object</code>
    * [~Error](#NimbusecAPI..Error) : <code>object</code>

<a name="new_NimbusecAPI_new"></a>
#### new NimbusecAPI(key, secret, [options])
Construct a new NimbusecAPI object.


| Param | Type | Description |
| --- | --- | --- |
| key | <code>string</code> | nimbusec API key |
| secret | <code>string</code> | nimbusec API secret |
| [options] | <code>Object</code> |  |
| options.baseURL | <code>string</code> | Nimbusec base URL |

<a name="NimbusecAPI+findBundles"></a>
#### nimbusecAPI.findBundles(filter, callback)
Read all existing bundles depending on an optional filter.

**Kind**: instance method of <code>[NimbusecAPI](#NimbusecAPI)</code>  
**Access:** public  

| Param | Type | Description |
| --- | --- | --- |
| filter | <code>string</code> | optional filter |
| callback | <code>[findBundlesCallback](#NimbusecAPI..findBundlesCallback)</code> |  |

<a name="NimbusecAPI+findDomains"></a>
#### nimbusecAPI.findDomains(filter, callback)
Read all existing domains depending on an optional filter.

**Kind**: instance method of <code>[NimbusecAPI](#NimbusecAPI)</code>  
**Access:** public  

| Param | Type | Description |
| --- | --- | --- |
| filter | <code>string</code> | optional filter |
| callback | <code>[findDomainsCallback](#NimbusecAPI..findDomainsCallback)</code> |  |

<a name="NimbusecAPI+createDomain"></a>
#### nimbusecAPI.createDomain(domain, callback)
Create a domain from the given object.

**Kind**: instance method of <code>[NimbusecAPI](#NimbusecAPI)</code>  
**Access:** public  

| Param | Type | Description |
| --- | --- | --- |
| domain | <code>[Domain](#NimbusecAPI..Domain)</code> | domain to be created. id will be ignored. |
| callback | <code>[createDomainCallback](#NimbusecAPI..createDomainCallback)</code> |  |

<a name="NimbusecAPI+updateDomain"></a>
#### nimbusecAPI.updateDomain(domain, domainID, callback)
Update an existing domain by the given object. To modify only certain fields
of the domain you can include just these fields inside of the domain object
you pass. The destination path for the request is determined by the ID.

**Kind**: instance method of <code>[NimbusecAPI](#NimbusecAPI)</code>  
**Access:** public  

| Param | Type | Description |
| --- | --- | --- |
| domain | <code>[Domain](#NimbusecAPI..Domain)</code> | the domain object with the fields to be updated |
| domainID | <code>integer</code> | the domain's assigned ID (must be valid) |
| callback | <code>[updateDomainCallback](#NimbusecAPI..updateDomainCallback)</code> |  |

<a name="NimbusecAPI+deleteDomain"></a>
#### nimbusecAPI.deleteDomain(domainID, callback)
Delete a specific domain.
The destination path for the request is determined by the ID.

**Kind**: instance method of <code>[NimbusecAPI](#NimbusecAPI)</code>  
**Access:** public  

| Param | Type | Description |
| --- | --- | --- |
| domainID | <code>integer</code> | the domain's assigned ID (must be valid) |
| callback | <code>[deleteDomainCallback](#NimbusecAPI..deleteDomainCallback)</code> |  |

<a name="NimbusecAPI+findAgentToken"></a>
#### nimbusecAPI.findAgentToken(filter, callback)
Read all existing tokens depending on an optional filter.

**Kind**: instance method of <code>[NimbusecAPI](#NimbusecAPI)</code>  
**Access:** public  

| Param | Type | Description |
| --- | --- | --- |
| filter | <code>string</code> | optional filter |
| callback | <code>[findAgentTokenCallback](#NimbusecAPI..findAgentTokenCallback)</code> |  |

<a name="NimbusecAPI+createAgentToken"></a>
#### nimbusecAPI.createAgentToken(agentToken, callback)
Create an server agent token from the given object.
In the following step this token can be used to run the server agent.

**Kind**: instance method of <code>[NimbusecAPI](#NimbusecAPI)</code>  
**Access:** public  

| Param | Type | Description |
| --- | --- | --- |
| agentToken | <code>[AgentToken](#NimbusecAPI..AgentToken)</code> | token to be created |
| callback | <code>[createAgentTokenCallback](#NimbusecAPI..createAgentTokenCallback)</code> |  |

<a name="NimbusecAPI+deleteAgentToken"></a>
#### nimbusecAPI.deleteAgentToken(agentToken, callback)
Delete a specific agent token.
The destination path for the request is determined by the ID.

**Kind**: instance method of <code>[NimbusecAPI](#NimbusecAPI)</code>  
**Access:** public  

| Param | Type | Description |
| --- | --- | --- |
| agentToken | <code>[AgentToken](#NimbusecAPI..AgentToken)</code> | token to be created |
| callback | <code>[createAgentTokenCallback](#NimbusecAPI..createAgentTokenCallback)</code> |  |

<a name="NimbusecAPI+findInfectedDomains"></a>
#### nimbusecAPI.findInfectedDomains(filter, callback)
Read list of infected domains depending on an optional filter.

**Kind**: instance method of <code>[NimbusecAPI](#NimbusecAPI)</code>  
**Access:** public  

| Param | Type | Description |
| --- | --- | --- |
| filter | <code>string</code> | optional filter |
| callback | <code>[findInfectedDomainsCallback](#NimbusecAPI..findInfectedDomainsCallback)</code> |  |

<a name="NimbusecAPI+findDomainResults"></a>
#### nimbusecAPI.findDomainResults(domainID, filter, callback)
Read list of results of a domain depending on an optional filter.

**Kind**: instance method of <code>[NimbusecAPI](#NimbusecAPI)</code>  
**Access:** public  

| Param | Type | Description |
| --- | --- | --- |
| domainID | <code>integer</code> |  |
| filter | <code>string</code> | optional filter |
| callback | <code>[findDomainResultsCallback](#NimbusecAPI..findDomainResultsCallback)</code> |  |

<a name="NimbusecAPI+updateDomainResult"></a>
#### nimbusecAPI.updateDomainResult(resultID, result, callback)
Update an existing DomainResult by the given object. Only status can be
modified to acknowledge a specific result. The destination path for the
request is determined by the ID.

**Kind**: instance method of <code>[NimbusecAPI](#NimbusecAPI)</code>  
**Access:** public  

| Param | Type | Description |
| --- | --- | --- |
| resultID | <code>integer</code> | the result assigned ID (must be valid) |
| result | <code>[Result](#NimbusecAPI..Result)</code> | the result object. Only the status field will be modified. |
| callback | <code>[updateDomainResultCallback](#NimbusecAPI..updateDomainResultCallback)</code> |  |

<a name="NimbusecAPI+getDomainMetadata"></a>
#### nimbusecAPI.getDomainMetadata(domainID, callback)
Retrieve domain metadata.
The destination path for the request is determined by the ID.

**Kind**: instance method of <code>[NimbusecAPI](#NimbusecAPI)</code>  
**Access:** public  

| Param | Type |
| --- | --- |
| domainID | <code>integer</code> | 
| callback | <code>[getDomainMetadataCallback](#NimbusecAPI..getDomainMetadataCallback)</code> | 

<a name="NimbusecAPI+_getOrDelete"></a>
#### nimbusecAPI._getOrDelete(getOrDeleteFn, uri, callback) ℗
Execute a HTTP GET or DELETE request on the API server.
Called by _get and _delete.

**Kind**: instance method of <code>[NimbusecAPI](#NimbusecAPI)</code>  
**Access:** private  

| Param | Type | Description |
| --- | --- | --- |
| getOrDeleteFn | <code>function</code> | reference to the get or delete function of the oauth requester |
| uri | <code>string</code> | URI of the resource |
| callback | <code>string</code> | callback function |

<a name="NimbusecAPI+_postOrPut"></a>
#### nimbusecAPI._postOrPut(postOrPutFn, uri, filter, callback) ℗
Execute a HTTP POST or PUT request on the API server.
Called by _post and _put.

**Kind**: instance method of <code>[NimbusecAPI](#NimbusecAPI)</code>  
**Access:** private  

| Param | Type | Description |
| --- | --- | --- |
| postOrPutFn | <code>function</code> | reference to the post or put function of the oauth requester |
| uri | <code>string</code> | URI of the resource |
| filter | <code>string</code> | optional filter |
| callback | <code>string</code> | callback function |

<a name="NimbusecAPI+_get"></a>
#### nimbusecAPI._get(uri, filter, callback) ℗
Execute a HTTP GET request on the API server.

**Kind**: instance method of <code>[NimbusecAPI](#NimbusecAPI)</code>  
**Access:** private  

| Param | Type | Description |
| --- | --- | --- |
| uri | <code>string</code> | URI of the resource |
| filter | <code>string</code> | optional filter |
| callback | <code>string</code> | callback function |

<a name="NimbusecAPI+_delete"></a>
#### nimbusecAPI._delete(uri, callback) ℗
Execute a HTTP DELETE request on the API server.

**Kind**: instance method of <code>[NimbusecAPI](#NimbusecAPI)</code>  
**Access:** private  

| Param | Type | Description |
| --- | --- | --- |
| uri | <code>string</code> | URI of the resource |
| callback | <code>string</code> | callback function |

<a name="NimbusecAPI+_post"></a>
#### nimbusecAPI._post(uri, obj, callback) ℗
Execute a HTTP POST request on the API server.

**Kind**: instance method of <code>[NimbusecAPI](#NimbusecAPI)</code>  
**Access:** private  

| Param | Type | Description |
| --- | --- | --- |
| uri | <code>string</code> | URI of the resource |
| obj | <code>Object</code> | Object to be posted |
| callback | <code>string</code> | callback function |

<a name="NimbusecAPI+_put"></a>
#### nimbusecAPI._put(uri, obj, callback) ℗
Execute a HTTP PUT request on the API server.

**Kind**: instance method of <code>[NimbusecAPI](#NimbusecAPI)</code>  
**Access:** private  

| Param | Type | Description |
| --- | --- | --- |
| uri | <code>string</code> | URI of the resource |
| obj | <code>Object</code> | Object to be put |
| callback | <code>string</code> | callback function |

<a name="NimbusecAPI..findBundlesCallback"></a>
#### NimbusecAPI~findBundlesCallback : <code>function</code>
**Kind**: inner typedef of <code>[NimbusecAPI](#NimbusecAPI)</code>  

| Param | Type | Description |
| --- | --- | --- |
| error | <code>[Error](#NimbusecAPI..Error)</code> |  |
| packages | <code>[Array.&lt;Package&gt;](#NimbusecAPI..Package)</code> | array of selected packages objects |

<a name="NimbusecAPI..findDomainsCallback"></a>
#### NimbusecAPI~findDomainsCallback : <code>function</code>
**Kind**: inner typedef of <code>[NimbusecAPI](#NimbusecAPI)</code>  

| Param | Type | Description |
| --- | --- | --- |
| error | <code>[Error](#NimbusecAPI..Error)</code> |  |
| domains | <code>[Array.&lt;Domain&gt;](#NimbusecAPI..Domain)</code> | array of selected domain objects |

<a name="NimbusecAPI..createDomainCallback"></a>
#### NimbusecAPI~createDomainCallback : <code>function</code>
**Kind**: inner typedef of <code>[NimbusecAPI](#NimbusecAPI)</code>  

| Param | Type | Description |
| --- | --- | --- |
| error | <code>[Error](#NimbusecAPI..Error)</code> |  |
| domain | <code>[Domain](#NimbusecAPI..Domain)</code> | the created domain object |

<a name="NimbusecAPI..updateDomainCallback"></a>
#### NimbusecAPI~updateDomainCallback : <code>function</code>
**Kind**: inner typedef of <code>[NimbusecAPI](#NimbusecAPI)</code>  

| Param | Type | Description |
| --- | --- | --- |
| error | <code>[Error](#NimbusecAPI..Error)</code> |  |
| domain | <code>[Domain](#NimbusecAPI..Domain)</code> | the created domain object |

<a name="NimbusecAPI..deleteDomainCallback"></a>
#### NimbusecAPI~deleteDomainCallback : <code>function</code>
**Kind**: inner typedef of <code>[NimbusecAPI](#NimbusecAPI)</code>  

| Param | Type |
| --- | --- |
| error | <code>[Error](#NimbusecAPI..Error)</code> | 

<a name="NimbusecAPI..findAgentTokenCallback"></a>
#### NimbusecAPI~findAgentTokenCallback : <code>function</code>
**Kind**: inner typedef of <code>[NimbusecAPI](#NimbusecAPI)</code>  

| Param | Type | Description |
| --- | --- | --- |
| error | <code>[Error](#NimbusecAPI..Error)</code> |  |
| agentToken | <code>[AgentToken](#NimbusecAPI..AgentToken)</code> | array of selected agent token objects |

<a name="NimbusecAPI..createAgentTokenCallback"></a>
#### NimbusecAPI~createAgentTokenCallback : <code>function</code>
**Kind**: inner typedef of <code>[NimbusecAPI](#NimbusecAPI)</code>  

| Param | Type | Description |
| --- | --- | --- |
| error | <code>[Error](#NimbusecAPI..Error)</code> |  |
| agentToken | <code>[AgentToken](#NimbusecAPI..AgentToken)</code> | the created agent token object |

<a name="NimbusecAPI..deleteAgentTokenCallback"></a>
#### NimbusecAPI~deleteAgentTokenCallback : <code>function</code>
**Kind**: inner typedef of <code>[NimbusecAPI](#NimbusecAPI)</code>  

| Param | Type |
| --- | --- |
| error | <code>[Error](#NimbusecAPI..Error)</code> | 

<a name="NimbusecAPI..findInfectedDomainsCallback"></a>
#### NimbusecAPI~findInfectedDomainsCallback : <code>function</code>
**Kind**: inner typedef of <code>[NimbusecAPI](#NimbusecAPI)</code>  

| Param | Type | Description |
| --- | --- | --- |
| error | <code>[Error](#NimbusecAPI..Error)</code> |  |
| domains | <code>[Array.&lt;Domain&gt;](#NimbusecAPI..Domain)</code> | array of selected domains |

<a name="NimbusecAPI..findDomainResultsCallback"></a>
#### NimbusecAPI~findDomainResultsCallback : <code>function</code>
**Kind**: inner typedef of <code>[NimbusecAPI](#NimbusecAPI)</code>  

| Param | Type | Description |
| --- | --- | --- |
| error | <code>[Error](#NimbusecAPI..Error)</code> |  |
| results | <code>[Array.&lt;Result&gt;](#NimbusecAPI..Result)</code> | array of selected results |

<a name="NimbusecAPI..updateDomainResultCallback"></a>
#### NimbusecAPI~updateDomainResultCallback : <code>function</code>
**Kind**: inner typedef of <code>[NimbusecAPI](#NimbusecAPI)</code>  

| Param | Type | Description |
| --- | --- | --- |
| error | <code>[Error](#NimbusecAPI..Error)</code> |  |
| domain | <code>[Domain](#NimbusecAPI..Domain)</code> | the domain object |

<a name="NimbusecAPI..getDomainMetadataCallback"></a>
#### NimbusecAPI~getDomainMetadataCallback : <code>function</code>
**Kind**: inner typedef of <code>[NimbusecAPI](#NimbusecAPI)</code>  

| Param | Type | Description |
| --- | --- | --- |
| error | <code>[Error](#NimbusecAPI..Error)</code> |  |
| domainMetadata | <code>[DomainMetadata](#NimbusecAPI..DomainMetadata)</code> | the metadata object |

<a name="NimbusecAPI..Domain"></a>
#### NimbusecAPI~Domain : <code>object</code>
**Kind**: inner typedef of <code>[NimbusecAPI](#NimbusecAPI)</code>  
**Properties**

| Name | Type | Description |
| --- | --- | --- |
| id | <code>integer</code> | unique identification of domain |
| bundle | <code>string</code> | id of assigned package |
| scheme | <code>string</code> | whether the domain uses http or https |
| name | <code>string</code> | name of domain (usually DNS name) |
| deepScan | <code>string</code> | starting point for the domain deep scan |
| fastScans | <code>Array.&lt;string&gt;</code> | landing pages of the domain scanned |

<a name="NimbusecAPI..DomainMetadata"></a>
#### NimbusecAPI~DomainMetadata : <code>object</code>
**Kind**: inner typedef of <code>[NimbusecAPI](#NimbusecAPI)</code>  
**Properties**

| Name | Type | Description |
| --- | --- | --- |
| lastDeepScan | <code>date</code> | timestamp (in ms) of last external scan of the whole site |
| nextDeepScan | <code>date</code> | timestamp (in ms) for next external scan of the whole site |
| lastFastScan | <code>date</code> | timestamp (in ms) of last external scan of the landing pages |
| nextFastScan | <code>date</code> | timestamp (in ms) for next external scan of the landing pages |
| agent | <code>date</code> | last date server agent sent results to the domain |
| cms | <code>string</code> | detected CMS vendor and version |
| httpd | <code>string</code> | detected HTTP server vendor and version |
| php | <code>string</code> | detected PHP version |
| files | <code>integer</code> | number of downloaded files/URLs for last deep scan |
| size | <code>integer</code> | size of downloaded files for last deep scan (in byte) |

<a name="NimbusecAPI..Result"></a>
#### NimbusecAPI~Result : <code>object</code>
**Kind**: inner typedef of <code>[NimbusecAPI](#NimbusecAPI)</code>  
**Properties**

| Name | Type | Description |
| --- | --- | --- |
| id | <code>integer</code> | unique identification of a result |
| status | <code>string</code> | status of the result (pending, acknowledged, falsepositive, removed) |
| event | <code>string</code> | event type of result, possible values are : <ul> <li>webshell</li> <li>malware</li> <li>renamed-executable</li> <li>defacement</li> <li>cms-version</li> <li>cms-vulnerable</li> <li>blacklist</li> <li>blacklist-ref</li> <li>changed-file</li> <li>changed-template</li> <li>ssl-expires</li> <li>ssl-expired</li> <li>ssl-ciphersuite</li> <li>ssl-notrust</li> <li>ssl-protocol</li> </ul> |
| category | <code>string</code> | category of result, possible values are : <ul> <li>applications</li> <li>blacklist</li> <li>webshell</li> <li>text</li> <li>blacklist-ref</li> <li>configuration</li> </ul> |
| severity | <code>integer</code> | severity level of result (1 = medium to 3 = severe) |
| probability | <code>float</code> | probability the result is critical |
| safeToDelete | <code>boolean</code> | flag indicating if the file can be safely deleted without loosing user data |
| createDate | <code>date</code> | timestamp (in ms) of the first occurrence |
| lastDate | <code>date</code> | timestamp (in ms) of the last occurrence the following fields contain more details about the result. Not all fields must be filled or present. |
| threatname | <code>string</code> | name identifying the threat of a result. meaning differs per category : <ul> <li> malware & webshell: the virus database name of the malicious software </li> <li> blacklist: the name of the blacklist containing the domain </li> </ul> Blacklist names are : <ul> <li>Google Safe Browsing</li> <li>Web of Trust</li> <li>Malc0de</li> <li>Malware Domain List</li> <li>Phishtank</li> <li>Zeus Tracker</li> </ul> |
| resource | <code>string</code> | affected resource (e.g. file path or URL) |
| md5 | <code>string</code> | MD5 hash sum of the affected file |
| filesize | <code>integer</code> | filesize of the affected file |
| owner | <code>string</code> | file owner of the affected file |
| group | <code>string</code> | file group of the affected file |
| permission | <code>integer</code> | permission of the affected file as decimal integer |
| diff | <code>string</code> | diff of a content change between two scans |
| reason | <code>string</code> | reason why a domain/URL is blacklisted |

<a name="NimbusecAPI..Package"></a>
#### NimbusecAPI~Package : <code>object</code>
**Kind**: inner typedef of <code>[NimbusecAPI](#NimbusecAPI)</code>  
**Properties**

| Name | Type | Description |
| --- | --- | --- |
| id | <code>string</code> | unique identification of a bundle |
| name | <code>string</code> | given name for a bundle |
| startDate | <code>date</code> | timestamp in milliseconds when bundle was added / set active |
| endDatet | <code>date</code> | timestamp in milliseconds when bundle will expire |
| quota | <code>string</code> | maximum size of files that will be downloaded per scan |
| depth | <code>integer</code> | maximum link depth that will be followed (-1 means no limit) |
| fast | <code>integer</code> | interval of fast scans in minutes (-1 means disabled) |
| deep | <code>integer</code> | interval of deep scans in minutes (-1 means disabled) |
| contingent | <code>integer</code> | maximum number of domains that can be assigned |
| active | <code>integer</code> | number of currently assigned domain |
| engines | <code>Array.&lt;string&gt;</code> | list of used anti-virus engines |

<a name="NimbusecAPI..Agent"></a>
#### NimbusecAPI~Agent : <code>object</code>
**Kind**: inner typedef of <code>[NimbusecAPI](#NimbusecAPI)</code>  
**Properties**

| Name | Type | Description |
| --- | --- | --- |
| os | <code>string</code> | operating system of agent (windows, macosx, linux) |
| arch | <code>string</code> | cpu architecture of agent (32bit, 64bit) |
| version | <code>int</code> | version of agent |
| md5 | <code>string</code> | MD5 hash of download file |
| sha1 | <code>string</code> | SHA1 hash of download file |
| format | <code>string</code> | format of downloaded file (zip) |
| url | <code>string</code> | URL were agent can be downloaded from |

<a name="NimbusecAPI..AgentToken"></a>
#### NimbusecAPI~AgentToken : <code>object</code>
**Kind**: inner typedef of <code>[NimbusecAPI](#NimbusecAPI)</code>  
**Properties**

| Name | Type | Description |
| --- | --- | --- |
| id | <code>integer</code> | unique identification of a token |
| name | <code>string</code> | given name for a token |
| key | <code>string</code> | oauth key |
| secret | <code>string</code> | oauth secret |
| lastCall | <code>date</code> | last timestamp (in ms) an agent used the token |
| version | <code>integer</code> | last agent version that was seen for this key |

<a name="NimbusecAPI..User"></a>
#### NimbusecAPI~User : <code>object</code>
**Kind**: inner typedef of <code>[NimbusecAPI](#NimbusecAPI)</code>  
**Properties**

| Name | Type | Description |
| --- | --- | --- |
| id | <code>integer</code> | unique identification of a user |
| login | <code>string</code> | login name of user |
| mail | <code>string</code> | e-mail contact where mail notificatins are sent to |
| role | <code>string</code> | role of an user (`administrator` or `user`) |
| company | <code>string</code> | company name of user |
| surname | <code>string</code> | surname of user |
| forename | <code>string</code> | surname of user |
| title | <code>string</code> | academic title of user |
| mobile | <code>string</code> | phone contact where sms notificatins are sent to |
| password | <code>string</code> | password of user (only used when creating or updating a user) |
| signatureKey | <code>string</code> | secret for SSO (only used when creating or updating a user) |

<a name="NimbusecAPI..Notification"></a>
#### NimbusecAPI~Notification : <code>object</code>
**Kind**: inner typedef of <code>[NimbusecAPI](#NimbusecAPI)</code>  
**Properties**

| Name | Type | Description |
| --- | --- | --- |
| id | <code>integer</code> | unique identification of a notification |
| domain | <code>integer</code> | id of a domain |
| transport | <code>string</code> | type of contact (mail, sms) |
| serverside | <code>integer</code> | level for server side notifications (see result severity, >3 = disabled) |
| content | <code>integer</code> | level for content notifications (see result severity, >3 = disabled) |
| blacklist | <code>integer</code> | level for blacklist notifications (see result severity, >3 = disabled) |

<a name="NimbusecAPI..CMS"></a>
#### NimbusecAPI~CMS : <code>object</code>
**Kind**: inner typedef of <code>[NimbusecAPI](#NimbusecAPI)</code>  
**Properties**

| Name | Type |
| --- | --- |
| CpeId | <code>string</code> | 
| LatestStable | <code>string</code> | 
| Path | <code>string</code> | 

<a name="NimbusecAPI..Error"></a>
#### NimbusecAPI~Error : <code>object</code>
Error object passed in first argument of callbacks.

**Kind**: inner typedef of <code>[NimbusecAPI](#NimbusecAPI)</code>  
**Properties**

| Name | Type | Description |
| --- | --- | --- |
| statusCode | <code>integer</code> | HTTP reponse status code |
| message | <code>string</code> | Error message (from X-Nimbusec-Error header) |
| data | <code>object</code> | HTTP error details |
| data.timestamp | <code>integer</code> | HTTP response date |
| data.status | <code>string</code> | HTTP reponse status code |
| data.error | <code>string</code> | short error message |
| data.message | <code>string</code> | detailed error message |
| data.path | <code>string</code> | path of the request |

