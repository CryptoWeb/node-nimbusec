/* eslint-disable max-lines */

/**
 * @file Main file of nimbusec client API library for Node.js
 * @author CryptoWeb <contact@cryptoweb.fr>
 * @copyright CryptoWeb
 * @license MIT
 * @require module:oauth
 */

var request = require('request');

/**
 * Construct a new NimbusecAPI object.
 *
 * @method NimbusecAPI
 * @public
 * @constructor
 * @param {string} key nimbusec API key
 * @param {string} secret nimbusec API secret
 * @param {Object=} options
 * @param {string} options.baseURL Nimbusec base URL
 */
var NimbusecAPI = function (key, secret, options) {

	// Replace default options by defined ones
	if (options && options.baseURL) {
		this._options.baseURL = options.baseURL;
	}

	this._key = key;
	this._secret = secret;
	this._signature = 'HMAC-SHA1';
};

NimbusecAPI.prototype._options = {
	baseURL: 'https://api.nimbusec.com/v2'
};

/**
 * Read all existing bundles depending on an optional filter.
 *
 * @method findBundles
 * @public
 * @param {?string} filter optional filter
 * @param {NimbusecAPI~findBundlesCallback} callback
 * @memberof NimbusecAPI
 * @instance
 */
/**
 * @callback NimbusecAPI~findBundlesCallback
 * @param {?NimbusecAPI~Error} error
 * @param {?NimbusecAPI~Package[]} packages array of selected packages objects
 */


NimbusecAPI.prototype.findBundles = function (filter, callback) {
	this._get('/bundle', filter, callback);
};

/**
 * Read all existing domains depending on an optional filter.
 *
 * @method findDomains
 * @public
 * @param {?string} filter optional filter
 * @param {NimbusecAPI~findDomainsCallback} callback
 * @memberof NimbusecAPI
 * @instance
 */
/**
 * @callback NimbusecAPI~findDomainsCallback
 * @param {?NimbusecAPI~Error} error
 * @param {?NimbusecAPI~Domain[]} domains array of selected domain objects
 */
NimbusecAPI.prototype.findDomains = function (filter, callback) {
	this._get('/domain', filter, callback);
};

/**
 * Create a domain from the given object.
 *
 * @method createDomain
 * @public
 * @param {NimbusecAPI~Domain} domain domain to be created. id will be ignored.
 * @param {NimbusecAPI~createDomainCallback} callback
 * @memberof NimbusecAPI
 * @instance
 */
/**
 * @callback NimbusecAPI~createDomainCallback
 * @param {?NimbusecAPI~Error} error
 * @param {?NimbusecAPI~Domain} domain the created domain object
 */
NimbusecAPI.prototype.createDomain = function (domain, callback) {
	this._post('/domain', domain, callback);
};

/**
 * Update an existing domain by the given object. To modify only certain fields
 * of the domain you can include just these fields inside of the domain object
 * you pass. The destination path for the request is determined by the ID.
 *
 * @method updateDomain
 * @public
 * @param {NimbusecAPI~Domain} domain the domain object with the fields to be
 * updated
 * @param {integer} domainID the domain's assigned ID (must be valid)
 * @param {NimbusecAPI~updateDomainCallback} callback
 * @memberof NimbusecAPI
 * @instance
 */
/**
 * @callback NimbusecAPI~updateDomainCallback
 * @param {?NimbusecAPI~Error} error
 * @param {?NimbusecAPI~Domain} domain the created domain object
 */
NimbusecAPI.prototype.updateDomain = function (domainID, domain, callback) {
	this._put('/domain/' + domainID, domain, callback);
};

/**
 * Delete a specific domain.
 * The destination path for the request is determined by the ID.
 *
 * @method deleteDomain
 * @public
 * @param {integer} domainID the domain's assigned ID (must be valid)
 * @param {NimbusecAPI~deleteDomainCallback} callback
 * @memberof NimbusecAPI
 * @instance
 */
/**
 * @callback NimbusecAPI~deleteDomainCallback
 * @param {?NimbusecAPI~Error} error
 */
NimbusecAPI.prototype.deleteDomain = function (domainID, domain, callback) {
	this._delete('/domain/' + domainID, callback);
};

/**
 * Read all existing tokens depending on an optional filter.
 *
 * @method findAgentToken
 * @public
 * @param {?string} filter optional filter
 * @param {NimbusecAPI~findAgentTokenCallback} callback
 * @memberof NimbusecAPI
 * @instance
 */
/**
 * @callback NimbusecAPI~findAgentTokenCallback
 * @param {?NimbusecAPI~Error} error
 * @param {?NimbusecAPI~AgentToken} agentToken array of selected agent token
 * objects
 */
NimbusecAPI.prototype.findAgentToken = function (filter, callback) {
	this._get('/agent/token', filter, callback);
};

/**
 * Create an server agent token from the given object.
 * In the following step this token can be used to run the server agent.
 *
 * @method createAgentToken
 * @public
 * @param {NimbusecAPI~AgentToken} agentToken token to be created
 * @param {NimbusecAPI~createAgentTokenCallback} callback
 * @memberof NimbusecAPI
 * @instance
 */
/**
 * @callback NimbusecAPI~createAgentTokenCallback
 * @param {?NimbusecAPI~Error} error
 * @param {?NimbusecAPI~AgentToken} agentToken the created agent token object
 */
NimbusecAPI.prototype.createAgentToken = function (agentToken, callback) {
	this._post('/agent/token', agentToken, callback);
};

/**
 * Delete a specific agent token.
 * The destination path for the request is determined by the ID.
 *
 * @method deleteAgentToken
 * @public
 * @param {NimbusecAPI~AgentToken} agentToken token to be created
 * @param {NimbusecAPI~createAgentTokenCallback} callback
 * @memberof NimbusecAPI
 * @instance
 */
/**
 * @callback NimbusecAPI~deleteAgentTokenCallback
 * @param {?NimbusecAPI~Error} error
 */
NimbusecAPI.prototype.deleteAgentToken = function (agentTokenID, callback) {
	this._delete('/agent/token' + agentTokenID, callback);
};

/**
 * Read list of infected domains depending on an optional filter.
 *
 * @method findInfectedDomains
 * @public
 * @param {?string} filter optional filter
 * @param {NimbusecAPI~findInfectedDomainsCallback} callback
 * @memberof NimbusecAPI
 * @instance
 */
/**
 * @callback NimbusecAPI~findInfectedDomainsCallback
 * @param {?NimbusecAPI~Error} error
 * @param {?NimbusecAPI~Domain[]} domains array of selected domains
 */
NimbusecAPI.prototype.findInfectedDomains = function (filter, callback) {
	this._get('/infected', filter, callback);
};

/**
 * Read list of results of a domain depending on an optional filter.
 *
 * @method findDomainResults
 * @public
 * @param {integer} domainID
 * @param {?string} filter optional filter
 * @param {NimbusecAPI~findDomainResultsCallback} callback
 * @memberof NimbusecAPI
 * @instance
 */
/**
 * @callback NimbusecAPI~findDomainResultsCallback
 * @param {?NimbusecAPI~Error} error
 * @param {?NimbusecAPI~Result[]} results array of selected results
 */
NimbusecAPI.prototype.findDomainResults = function (domainID, filter, callback) {
	this._get('/domain/' + domainID + '/result', filter, callback);
};

/**
 * Update an existing DomainResult by the given object. Only status can be
 * modified to acknowledge a specific result. The destination path for the
 * request is determined by the ID.
 *
 * @method updateDomainResult
 * @public
 * @param {integer} domainID
 * @param {integer} resultID the result assigned ID (must be valid)
 * @param {NimbusecAPI~Result} result the result object. Only the status field
 * will be modified.
 * @param {NimbusecAPI~updateDomainResultCallback} callback
 * @memberof NimbusecAPI
 * @instance
 */
/**
 * @callback NimbusecAPI~updateDomainResultCallback
 * @param {?NimbusecAPI~Error} error
 * @param {?NimbusecAPI~Domain} domain the domain object
 */
NimbusecAPI.prototype.updateDomainResult = function (domainID, resultID, result, callback) {
	this._put('/domain/' + domainID + '/result/' + resultID, result, callback);
};

/**
 * Retrieve domain metadata.
 * The destination path for the request is determined by the ID.
 *
 * @method getDomainMetadata
 * @public
 * @param {integer} domainID
 * @param {NimbusecAPI~getDomainMetadataCallback} callback
 * @memberof NimbusecAPI
 * @instance
 */
/**
 * @callback NimbusecAPI~getDomainMetadataCallback
 * @param {?NimbusecAPI~Error} error
 * @param {?NimbusecAPI~DomainMetadata} domainMetadata the metadata object
 */
NimbusecAPI.prototype.getDomainMetadata = function (domainID, callback) {
	this._get('/domain/' + domainID + '/metadata', null, callback);
};

/**
 * Parse the HTTP response.
 * Will get the error message in x-nimbusec-error header if present.
 * Will parse JSON into JavaScript Object if present.
 *
 * @method _parseResponse
 * @private
 * @param {Object} err oauth requester error object
 * @param {string} data body of the HTTP response
 * @param {Object} response oauth requester response object
 * @param {NimbusecAPI~apiCallCallback} callback callback called at end of
 * parsing
 * @memberof NimbusecAPI
 * @instance
 */
NimbusecAPI.prototype._parseResponse = function (err, data, response, callback) {

	if (err && response && response.headers) {
		err.message = response.headers['x-nimbusec-error'];
	}

	if (response && response.headers && (response.headers['content-type'] === 'application/json;charset=UTF-8')) {
		data = JSON.parse(data);
	}

	callback(err, data);
};

/**
 * Execute a HTTP GET request on the API server.
 *
 * @method _get
 * @private
 * @param {string} uri URI of the resource
 * @param {?string} filter optional filter
 * @param {string} callback callback function
 * @memberof NimbusecAPI
 * @instance
 */
NimbusecAPI.prototype._get = function (uri, filter, callback) {
	var that = this;

	if (filter) {
		uri = uri + '?q=' + encodeURIComponent(filter);
	}

	request.get(this._options.baseURL  + uri, {
		oauth: {
			'consumer_key': this._key,
			'consumer_secret':  this._secret,
			'token': '',
			'token_secret': '',
			'session_handle': '',
			'signature_method': this._signature
		}
	}, function (err, res, body) {
		that._parseResponse(err, body, res, callback);
	});
};

/**
 * Execute a HTTP DELETE request on the API server.
 *
 * @method _delete
 * @private
 * @param {string} uri URI of the resource
 * @param {string} callback callback function
 * @memberof NimbusecAPI
 * @instance
 */
NimbusecAPI.prototype._delete = function (uri, callback) {
	var that = this;

	request.delete(this._options.baseURL  + uri, {
		oauth: {
			'consumer_key': this._key,
			'consumer_secret':  this._secret,
			'token': '',
			'token_secret': '',
			'session_handle': '',
			'signature_method': this._signature
		}
	}, function (err, res, body) {
		that._parseResponse(err, body, res, callback);
	});
};

/**
 * Execute a HTTP POST request on the API server.
 *
 * @method _post
 * @private
 * @param {string} uri URI of the resource
 * @param {Object} obj Object to be posted
 * @param {string} callback callback function
 * @memberof NimbusecAPI
 * @instance
 */
NimbusecAPI.prototype._post = function (uri, obj, callback) {
	var that = this;
	request.delete(this._options.baseURL  + uri, {
		json: obj,
		oauth: {
			'consumer_key': this._key,
			'consumer_secret':  this._secret,
			'token': '',
			'token_secret': '',
			'session_handle': '',
			'signature_method': this._signature
		}
	}, function (err, res, body) {
		that._parseResponse(err, body, res, callback);
	});
};

/**
 * Execute a HTTP PUT request on the API server.
 *
 * @method _put
 * @private
 * @param {string} uri URI of the resource
 * @param {Object} obj Object to be put
 * @param {string} callback callback function
 * @memberof NimbusecAPI
 * @instance
 */
NimbusecAPI.prototype._put = function (uri, obj, callback) {
	var that = this;

	request.put(this._options.baseURL  + uri, {
		json: obj,
		oauth: {
			'consumer_key': this._key,
			'consumer_secret':  this._secret,
			'token': '',
			'token_secret': '',
			'session_handle': '',
			'signature_method': this._signature
		}
	}, function (err, res, body) {
		that._parseResponse(err, body, res, callback);
	});
};

module.exports = NimbusecAPI;

 /**
 * @typedef NimbusecAPI~Domain
 * @type {object}
 * @property {integer} id unique identification of domain
 * @property {string} bundle id of assigned package
 * @property {string} scheme whether the domain uses http or https
 * @property {string} name name of domain (usually DNS name)
 * @property {string} deepScan starting point for the domain deep scan
 * @property {string[]} fastScans landing pages of the domain scanned
 */

 /**
 * @typedef NimbusecAPI~DomainMetadata
 * @type {object}
 * @property {date} lastDeepScan timestamp (in ms) of last external scan of the
 * whole site
 * @property {date} nextDeepScan timestamp (in ms) for next external scan of the
 * whole site
 * @property {date} lastFastScan timestamp (in ms) of last external scan of the
 * landing pages
 * @property {date} nextFastScan timestamp (in ms) for next external scan of the
 * landing pages
 * @property {date} agent last date server agent sent results to the domain
 * @property {string} cms detected CMS vendor and version
 * @property {string} httpd detected HTTP server vendor and version
 * @property {string} php detected PHP version
 * @property {integer} files number of downloaded files/URLs for last deep scan
 * @property {integer} size size of downloaded files for last deep scan (in
 * byte)
 */

/**
 * @typedef NimbusecAPI~Result
 * @type {object}
 * @property {integer} id unique identification of a result
 * @property {string} status status of the result (1 = pending,
 * 2 = acknowledged, 3 = falsepositive, 4 = removed)
 * @property {string} event event type of result, possible values are :
 * <ul>
 * <li>webshell</li>
 * <li>malware</li>
 * <li>renamed-executable</li>
 * <li>defacement</li>
 * <li>cms-version</li>
 * <li>cms-vulnerable</li>
 * <li>blacklist</li>
 * <li>blacklist-ref</li>
 * <li>changed-file</li>
 * <li>changed-template</li>
 * <li>ssl-expires</li>
 * <li>ssl-expired</li>
 * <li>ssl-ciphersuite</li>
 * <li>ssl-notrust</li>
 * <li>ssl-protocol</li>
 * </ul>
 * @property {string} category category of result, possible values are :
 * <ul>
 * <li>applications</li>
 * <li>blacklist</li>
 * <li>webshell</li>
 * <li>text</li>
 * <li>blacklist-ref</li>
 * <li>configuration</li>
 * </ul>
 * @property {integer} severity severity level of result (1 = medium to
 * 3 = severe)
 * @property {float} probability probability the result is critical
 * @property {boolean} safeToDelete flag indicating if the file can be safely
 * deleted without loosing user data
 * @property {date} createDate timestamp (in ms) of the first occurrence
 * @property {date} lastDate timestamp (in ms) of the last occurrence the
 * following fields contain more details about the result. Not all fields must
 * be filled or present.
 * @property {string} threatname name identifying the threat of a result.
 * meaning differs per category :
 * <ul>
 * <li> malware & webshell: the virus database name of the malicious
 * software </li>
 * <li> blacklist: the name of the blacklist containing the domain </li>
 * </ul>
 * Blacklist names are :
 * <ul>
 * <li>Google Safe Browsing</li>
 * <li>Web of Trust</li>
 * <li>Malc0de</li>
 * <li>Malware Domain List</li>
 * <li>Phishtank</li>
 * <li>Zeus Tracker</li>
 * </ul>
 * @property {string} resource affected resource (e.g. file path or URL)
 * @property {string} md5 MD5 hash sum of the affected file
 * @property {integer} filesize filesize of the affected file
 * @property {string} owner file owner of the affected file
 * @property {string} group file group of the affected file
 * @property {integer} permission permission of the affected file as decimal
 * integer
 * @property {string} diff diff of a content change between two scans
 * @property {string} reason reason why a domain/URL is blacklisted
 *
 */

/**
 * @typedef NimbusecAPI~Package
 * @type {object}
 * @property {string} id unique identification of a bundle
 * @property {string} name given name for a bundle
 * @property {date} startDate timestamp in milliseconds when bundle was added /
 * set active
 * @property {date} endDatet timestamp in milliseconds when bundle will expire
 * @property {string} quota maximum size of files that will be downloaded per
 * scan
 * @property {integer} depth maximum link depth that will be followed (-1 means
 * no limit)
 * @property {integer} fast interval of fast scans in minutes (-1 means
 * disabled)
 * @property {integer} deep interval of deep scans in minutes (-1 means
 * disabled)
 * @property {integer} contingent maximum number of domains that can be assigned
 * @property {integer} active number of currently assigned domain
 * @property {string[]} engines list of used anti-virus engines
 */

 /**
 * @typedef NimbusecAPI~Agent
 * @type {object}
 * @property {string} os operating system of agent (windows, macosx, linux)
 * @property {string} arch cpu architecture of agent (32bit, 64bit)
 * @property {int} version version of agent
 * @property {string} md5 MD5 hash of download file
 * @property {string} sha1 SHA1 hash of download file
 * @property {string} format format of downloaded file (zip)
 * @property {string} url URL were agent can be downloaded from
 */

 /**
 * @typedef NimbusecAPI~AgentToken
 * @type {object}
 * @property {integer} id unique identification of a token
 * @property {string} name given name for a token
 * @property {string} key oauth key
 * @property {string} secret oauth secret
 * @property {date} lastCall last timestamp (in ms) an agent used the token
 * @property {integer} version last agent version that was seen for this key
 */

 /**
 * @typedef NimbusecAPI~User
 * @type {object}
 * @property {integer} id unique identification of a user
 * @property {string} login login name of user
 * @property {string} mail e-mail contact where mail notificatins are sent to
 * @property {string} role role of an user (`administrator` or `user`)
 * @property {string} company company name of user
 * @property {string} surname surname of user
 * @property {string} forename surname of user
 * @property {string} title academic title of user
 * @property {string} mobile phone contact where sms notificatins are sent to
 * @property {string} password password of user (only used when creating or
 * updating a user)
 * @property {string} signatureKey secret for SSO (only used when creating or
 * updating a user)
 */

 /**
 * @typedef NimbusecAPI~Notification
 * @type {object}
 * @property {integer} id unique identification of a notification
 * @property {integer} domain id of a domain
 * @property {string} transport type of contact (mail, sms)
 * @property {integer} serverside level for server side notifications (see
 * result severity, >3 = disabled)
 * @property {integer} content level for content notifications (see result
 * severity, >3 = disabled)
 * @property {integer} blacklist level for blacklist notifications (see result
 * severity, >3 = disabled)
 */

 /**
 * @typedef NimbusecAPI~CMS
 * @type {object}
 * @property {string} CpeId
 * @property {string} LatestStable
 * @property {string} Path
 */

/**
 * Error object passed in first argument of callbacks.
 * @typedef NimbusecAPI~Error
 * @type {object}
 * @property {integer} statusCode HTTP reponse status code
 * @property {?string} message Error message (from X-Nimbusec-Error header)
 * @property {object} data  HTTP error details
 * @property {integer} data.timestamp HTTP response date
 * @property {string} data.status HTTP reponse status code
 * @property {string} data.error short error message
 * @property {string} data.message detailed error message
 * @property {string} data.path path of the request
 */
