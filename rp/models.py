# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from __future__ import print_function
from __future__ import division
from __future__ import absolute_import

try: # Python3
	from urllib.parse import urlparse, parse_qs, unquote
except: # Python2
    from urlparse import urlparse, parse_qs, unquote
import string
import random
import time
from datetime import datetime,timedelta
import pytz
import requests
from requests.auth import HTTPBasicAuth
import json
import base64
import logging
import hmac
import hashlib
from jose import jwk, jws, jwt
from jose.utils import base64url_decode, base64url_encode
from furl import furl
from django.conf import settings
from django.db import models

# Create your models here.

class OPSettings(models.Model):
	opId = models.CharField(max_length=200,db_index=True)
	displayName = models.CharField(max_length=200,db_index=True)
	issuer = models.CharField(max_length=200,db_index=True)
	clientId = models.CharField(max_length=200,blank=True)
	clientSecret = models.CharField(max_length=200,blank=True)
	redirect_url = models.CharField(max_length=200,blank=True)
	authorizationEndpoint = models.CharField(max_length=200,blank=True)
	tokenizationEndpoint = models.CharField(max_length=200,blank=True)
	userinfoEndpoint = models.CharField(max_length=200,blank=True)
	revocationEndpoint = models.CharField(max_length=200,blank=True)
	introspectionEndpoint = models.CharField(max_length=200,blank=True)
	responseType = models.CharField(max_length=200,blank=True)
	scope = models.TextField(blank=True)
	supportPkce = models.BooleanField(default=False)
	options = models.CharField(max_length=200,blank=True)
	createDate = models.DateTimeField(auto_now_add=True)
	updateDate = models.DateTimeField(auto_now=True)

	class Meta:
		db_table = 'opsettings'

class OPConfigurations(models.Model):
	opId = models.CharField(max_length=200,db_index=True)
	configurations = models.TextField(blank=True)
	jwkSet = models.TextField(blank=True)
	createDate = models.DateTimeField(auto_now_add=True)
	updateDate = models.DateTimeField(auto_now=True)

	class Meta:
		db_table = 'opconfigurations'


#
#
#

logging.config.dictConfig(settings.LOGGING)
logger = logging.getLogger("oOPp")

keyMap = {
	'methods' : {
		'GET' :    'GET',
		'POST' :   'POST',
		'PUT' :    'PUT',
		'PATCH' :  'PATCH',
		'DELETE' : 'DELETE',
	},
	'specAPIs' : {
		'Authz' :         { 'apiName': 'Authorization', 'settingsName': 'authorizationEndpoint', 'configName': 'authorization_endpoint', 'method': 'GET',  'contentType': 'none', 'authorizationHeader': 'none'   },
		'Token' :         { 'apiName': 'Tokenization',  'settingsName': 'tokenizationEndpoint',  'configName': 'token_endpoint',         'method': 'POST', 'contentType': 'form', 'authorizationHeader': 'basic'  },
		'Refresh' :       { 'apiName': 'Refresh Token', 'settingsName': 'tokenizationEndpoint',  'configName': 'token_endpoint',         'method': 'POST', 'contentType': 'form', 'authorizationHeader': 'basic'  },
		'UserInfo' :      { 'apiName': 'UserInfo',      'settingsName': 'userinfoEndpoint',      'configName': 'userinfo_endpoint',      'method': 'GET',  'contentType': 'none', 'authorizationHeader': 'bearer' },
		'Revocation' :    { 'apiName': 'Revoke Token',  'settingsName': 'revocationEndpoint',    'configName': 'revocation_endpoint',    'method': 'POST', 'contentType': 'form', 'authorizationHeader': 'basic'  },
		'Introspection' : { 'apiName': 'Introspection', 'settingsName': 'introspectionEndpoint', 'configName': 'introspection_endpoint', 'method': 'POST', 'contentType': 'form', 'authorizationHeader': 'basic'  },
		'Registration' :  { 'apiName': 'Registration',  'settingsName': 'registrationEndpoint',  'configName': 'registration_endpoint',  'method': 'POST', 'contentType': 'json', 'authorizationHeader': 'bearer' },
	},
	'response' : {
		'Authz' :         { 'sessionName': 'authzResponse',         'paramNames' : ['state','code','id_token','access_token','refresh_token','codeVerifier','codeChallenge','challengeMethod'] },
		'Token' :         { 'sessionName': 'tokenResponse',         'paramNames' : ['state','id_token','access_token','refresh_token']                                                         },
		'Refresh' :       { 'sessionName': 'refreshResponse',       'paramNames' : ['id_token', 'access_token','refresh_token']                                                                },
		'Introspection' : { 'sessionName': 'introspectionResponse', 'paramNames' : ['id_token', 'access_token','refresh_token']                                                                },
	},
	'blockDeleteKeys': ['codeVerifier','codeChallenge','challengeMethod'],
	'hmacType': {
		'HS256' : hashlib.sha256,
		'HS384' : hashlib.sha384,
		'HS512' : hashlib.sha512,
	}
}

class ParamError(Exception):
	def __init__(self, value):
		self.value = value
	def __str__(self):
		return repr(self.value)


class OIDCClient(object):
	
	def __init__(self, opid):
		self.opId = opid

	def getAuthorizationURL(self, authorizationEndpoint=None, clientId=None, redirectUrl=None, responseType=None, scope=None, state=None, options={}, codeChallenge=None, challengeMethod=None):
		if not authorizationEndpoint or authorizationEndpoint is None:
			raise ParamError('authorizationEndpoint')
		if not clientId or clientId is None:
			raise ParamError('clientId')
		if not redirectUrl or redirectUrl is None:
			raise ParamError('redirectUrl')
		if not responseType or responseType is None:
			raise ParamError('responseType')
		if not scope or scope is None:
			raise ParamError('scope')
		if not state or state is None:
			raise ParamError('state')
		
		nonce = self.__randstr(16)
		
		params = {
			'client_id' : clientId,
			'response_type' : responseType,
			'scope' : scope,
			'redirect_uri' : redirectUrl,
			'nonce' : nonce,
			'state' : state,
		}
		if len(options) > 0:
			for lineitem in options.splitlines():
				item = [x.strip() for x in lineitem.split('=')]
				if len(item) == 2:
					params[item[0]] = item[1]
		if codeChallenge is not None and challengeMethod is not None:
			params['code_challenge'] = codeChallenge
			params['code_challenge_method'] = challengeMethod
		f = furl(authorizationEndpoint)
		f.add(args=params)

		return f.url

	def getAccessToken(self, tokenEndpoint=None, clientId=None, clientSecret=None, redirectUrl=None, code=None, codeVerifier=None, grantType='authorization_code'):
		if not tokenEndpoint or tokenEndpoint is None:
			raise ParamError('tokenEndpoint')
		if not clientId or clientId is None:
			raise ParamError('clientId')
		if not clientSecret or clientSecret is None:
			raise ParamError('clientSecret')
		if not code or code is None:
			raise ParamError('code')
		logger.debug('code='+code)
		if codeVerifier is not None:
			logger.debug('codeVerifier='+codeVerifier)
		params = {
			'grant_type' : grantType,
			'code' : code,
			'redirect_uri' : redirectUrl,
		}
		if codeVerifier is not None:
			params['code_verifier'] = codeVerifier
		
		try:
			r = requests.post(tokenEndpoint, data=params, auth=HTTPBasicAuth(clientId, clientSecret), allow_redirects=False)
			ret = self.__getRequestResponseDetail(r)
		except Exception as exp:
			raise

		return ret
	
	def getRefreshTokenParams(self, tokenEndpoint=None, refreshToken=None, **args):
		if not tokenEndpoint or tokenEndpoint is None:
			raise ParamError('tokenEndpoint')
		if not refreshToken or refreshToken is None:
			raise ParamError('refreshToken')
		
		params = {
			'grant_type' : "refresh_token",
			'refresh_token' : refreshToken,
		}
		
		params.update(args['args'])
		f = furl(tokenEndpoint)
		f.add(args=params)

		return unquote(f.url), unquote(str(f.query))
	
	def getRevocationParams(self, revocationEndpoint=None, accessToken=None, refreshToken=None, **args):
		if not revocationEndpoint or revocationEndpoint is None:
			raise ParamError('revocationEndpoint')
		if (not accessToken or accessToken is None) and (not refreshToken or refreshToken is None):
			raise ParamError('accessToken or refreshToken')
		
		if accessToken is not None:
			token = accessToken
			hint = 'access_token'
		elif refreshToken is not None:
			token = refreshToken
			hint = 'refresh_token'
		else:
			raise ParamError('accessToken or refreshToken')
		
		params = {
			'token' : token,
			'token_type_hint' : hint,
		}
		
		params.update(args['args'])
		f = furl(revocationEndpoint)
		f.add(args=params)

		return unquote(f.url), unquote(str(f.query))
	
	def getIntrospectionParams(self, introspectionEndpoint=None, accessToken=None, refreshToken=None, **args):
		if not introspectionEndpoint or introspectionEndpoint is None:
			raise ParamError('introspectionEndpoint')
		if (not accessToken or accessToken is None) and (not refreshToken or refreshToken is None):
			raise ParamError('accessToken or refreshToken')
		
		if accessToken is not None:
			token = accessToken
			hint = 'access_token'
		elif refreshToken is not None:
			token = refreshToken
			hint = 'refresh_token'
		else:
			raise ParamError('accessToken or refreshToken')
		
		params = {
			'token' : token,
			'token_type_hint' : hint,
		}
		
		params.update(args['args'])
		f = furl(introspectionEndpoint)
		f.add(args=params)

		return unquote(f.url), unquote(str(f.query))

	def commonApi(self, method='GET', apiUrl=None, clientId=None, clientSecret=None, accessToken=None, contentType=None, authorizationType=None, payload=None):
		if not apiUrl or apiUrl is None:
			raise ParamError('apiUrl')
		if authorizationType == "bearer" and (not accessToken or accessToken is None):
			raise ParamError('clientSecret')
		if authorizationType == "basic" and (not clientId or clientId is None):
			raise ParamError('clientId')
		if authorizationType == "basic" and (not clientSecret or clientSecret is None):
			raise ParamError('clientSecret')
		if method.upper() in keyMap['methods'].keys():
			method = keyMap['methods'][method.upper()]
		else:
			raise ParamError('method=' + method)
		
		headers = {}
		
		if contentType == 'json':
			headers['Content-Type'] = 'application/json'
		else:
			headers['Content-Type'] = 'application/x-www-form-urlencoded'
			
		if authorizationType == "basic":
			headers['Authorization'] = 'Basic ' + base64.b64encode((clientId+':'+clientSecret).encode()).decode('utf-8')
			logger.debug(headers['Authorization'])
		elif authorizationType == "bearer":
			headers['Authorization'] =  "Bearer " + accessToken
		else:
			pass

		try:
			r = requests.request(method, apiUrl, headers=headers, data=payload, allow_redirects=False)
			ret = self.__getRequestResponseDetail(r)
		except Exception as exp:
			logger.error('[OIDCClient.commonApi] ' + str(exp))
			raise

		return ret

	def decodeIdToken(self, idToken=None):
		try:
			if not idToken or idToken is None:
				raise ParamError('idToken')
			messages = idToken.split('.')
			message = messages[1] + ('=' * (len(messages[1]) % 4))
			ret = json.dumps(json.loads(base64url_decode(message.encode())), indent=2).encode().decode('unicode-escape')
			
			return ret
		except Exception as exp:
			logger.error('[decodeIdToken] ' + str(exp))
			raise
		
	def __randstr(self, n=32):
		try: # Python3
			return str(''.join(random.choice(string.ascii_letters + string.digits + '_-') for i in range(n)))
		except: # Python2
			return str(''.join(random.choice(string.ascii_letters + string.digits + '_-') for i in xrange(n)))
	
	def __getRequestResponseDetail(self, req):
		if "application/json" in req.request.headers['Content-Type'] or "text/json" in req.request.headers['Content-Type']:
			requestBody = json.dumps(json.loads(req.request.body), indent=2).encode().decode('unicode-escape') if req.request.body is not None else {}
		else:
			requestBody = req.request.body.encode().decode('unicode-escape') if req.request.body is not None else ''
		if "application/json" in req.headers['Content-Type'] or "text/json" in req.headers['Content-Type']:
			responseBody = json.dumps(json.loads(req.text), indent=2).encode().decode('unicode-escape') if req.text is not None else {}
		else:
			responseBody = req.text.encode().decode('unicode-escape') if req.text is not None else ''
		return {
				'requestMethod' : str(req.request.method) if req.request.method is not None else '',
				'requestURI' : str(req.request.url) if req.request.url is not None else '',
				'requestHeaders' : self.__formatHeaders(dict(req.request.headers)) if req.request.headers is not None else '',
				'requestBody' : requestBody,
				'statusCode' : str(req.status_code) if req.status_code is not None else '',
				'responseHeaders' : self.__formatHeaders(dict(req.headers)) if req.headers is not None else '',
				'responseBody' : responseBody
			}

	def __formatHeaders(self, headers):
		return '\r\n'.join([k + ': ' + headers[k] for k in headers.keys()])


class OIDCPreference(object):
	
	def __init__(self, opid):
		self.opId = opid
		try:
			self.o = OPSettings.objects.get(opId=opid)
		except Exception as exp:
			logger.error('[OIDCPrefarence.__init__] ' + str(exp))
			raise

	def getIssuer(self):
		return self.o.issuer
	def getClientId(self):
		return self.o.clientId
	def getClientSecret(self):
		return self.o.clientSecret
	def getClientIdAndSercret(self):
		return self.o.clientId, o.clientSecret
	def getResponseType(self):
		return self.o.responseType
	def getScope(self):
		return self.o.scope
	def getOptions(self):
		return self.o.options
	def getRedirectUrl(self):
		return self.o.redirect_url
	def getSupportPkce(self):
		return self.o.supportPkce
	def getIdTokenSigningAlgValuesSupported(self):
		try:
			c, _ = self.__getOPConfigurations()
			if c is None:
				return []
			config = json.loads(c)
			if 'id_token_signing_alg_values_supported' in config:
				return config['id_token_signing_alg_values_supported']
			else:
				return []
		except Exception as exp:
			logger.error('[OIDCPreference.getIdTokenSigningAlgValuesSupported] ' + str(exp))
			raise
	def getConfigration(self):
		try:
			c, _ = self.__getOPConfigurations()
			if c is None:
				return []
			config = json.loads(c)
			return config
		except Exception as exp:
			logger.error('[OIDCPreference.getConfigration] ' + str(exp))
			raise
	def getJWKSet(self):
		try:
			_, j = self.__getOPConfigurations()
			if j is None or j == "":
				return []
			JWKSet = json.loads(j)
			if 'keys' in JWKSet:
				return JWKSet['keys']
			else:
				return []
		except Exception as exp:
			logger.error('[OIDCPreference.getJWKSet] ' + str(exp))
			raise
	
	def getPreference(self):
		c = {}
		
		try:
			c['opId'] = self.o.opId
			c['displayName'] = self.o.displayName
			c['issuer'] = self.o.issuer
			c['clientId'] = self.o.clientId
			c['clientSecret'] = "*" * len(self.o.clientSecret) if not(not self.o.clientSecret or self.o.clientSecret is None) else ""
			c['redirect_url'] = settings.OIDC_REDIRECT_URL + self.opId
			c['authorizationEndpoint'] = self.o.authorizationEndpoint
			c['tokenizationEndpoint'] = self.o.tokenizationEndpoint
			c['userinfoEndpoint'] = self.o.userinfoEndpoint
			c['revocationEndpoint'] = self.o.revocationEndpoint
			c['introspectionEndpoint'] = self.o.introspectionEndpoint
			c['responseType'] = self.o.responseType
			c['scope'] = self.o.scope
			c['options'] = self.o.options
			c['supportPkce'] = self.o.supportPkce
			
			config, JWKSet = self.__getOPConfigurations()
			if config is not None:
				logger.debug(config)
				c['configurations'] = json.dumps(json.loads(config), indent=2)
				logger.debug(c['configurations'])
			else:
				c['configurations'] = None
			if JWKSet is not None and JWKSet != "":
				c['JWKSet'] = json.dumps(json.loads(JWKSet), indent=2)
			else:
				c['JWKSet'] = None
		except Exception as exp:
			logger.error('[OIDCPreference.getPreference] ' + str(exp))
			raise
		
		return c

	def setPreference(self, c):
		try:
			if 'clientId' in c.keys():
				self.o.clientId = c['clientId']
			if 'clientSecret' in c.keys():
				self.o.clientSecret = c['clientSecret'] if len(c['clientSecret'].replace('*', '')) > 0 else self.o.clientSecret
			self.o.redirect_url = settings.OIDC_REDIRECT_URL + self.opId
			if 'authorizationEndpoint' in c.keys():
				self.o.authorizationEndpoint = c['authorizationEndpoint']
			if 'tokenizationEndpoint' in c.keys():
				self.o.tokenizationEndpoint = c['tokenizationEndpoint']
			if 'userinfoEndpoint' in c.keys():
				self.o.userinfoEndpoint = c['userinfoEndpoint']
			if 'revocationEndpoint' in c.keys():
				self.o.revocationEndpoint = c['revocationEndpoint']
			if 'introspectionEndpoint' in c.keys():
				self.o.introspectionEndpoint = c['introspectionEndpoint']
			if 'responseType' in c.keys():
				if c['responseType'] != '' and c['responseType'] is not None:
					self.o.responseType = c['responseType']
				else:
					self.o.responseType = "code id_token"
			else:
				self.o.responseType = "code id_token"
			if 'scope' in c.keys():
				if c['scope'] != '' and c['scope'] is not None:
					self.o.scope = c['scope']
				else:
					self.o.scope = "openid"
			else:
				self.o.scope = "openid"
			if 'options' in c.keys():
				self.o.options = c['options']
			if 'supportPkce' in c.keys():
				if c['supportPkce'] == 'true':
					self.o.supportPkce = True
				elif c['supportPkce'] == 'false':
					self.o.supportPkce = False

			self.o.save()
		except Exception as exp:
			logger.error('[OIDCPreference.setPreference] ' + str(exp))
			raise

	def checkRequired(self):
		return not(self.o.clientId is None or self.o.clientId == "") and not(self.o.clientSecret is None or self.o.clientSecret == "") and not(self.o.responseType is None or self.o.responseType == "") and not(self.o.scope is None or self.o.scope == "")

	def __getOPConfigurations(self):
		try:
			g = None
			config = None
			JWKSet = None
			try:
				g = OPConfigurations.objects.get(opId=self.opId)
				if g.updateDate > (datetime.now(tz=pytz.timezone('UTC')) - timedelta(days=1)):
					config = g.configurations
			except OPConfigurations.DoesNotExist:
				pass
			
			if config is None:
				config_url = self.o.issuer + '/.well-known/openid-configuration' if self.o.issuer[-1 * len('.well-known/openid-configuration'):] != '.well-known/openid-configuration' else self.o.issuer
				cdoc = requests.get(config_url)
				if cdoc.status_code == 200:
					config = json.dumps(json.loads(cdoc.text))
					if g is None:
						g = OPConfigurations(opId=self.opId)
					g.configurations = config
					g.save()
					
					j = json.loads(cdoc.text)
					if 'jwks_uri' in j.keys():
						if j['jwks_uri'] is not None and j['jwks_uri'] != '':
							jdoc = requests.get(j['jwks_uri'])
							if jdoc.status_code == 200:
								JWKSet = json.dumps(json.loads(jdoc.text))
								g.jwkSet = JWKSet
								g.save()
			else:
				JWKSet = g.jwkSet
		except Exception as exp:
			logger.error('[OIDCPrefarence.__getOPConfigurations] ' + str(exp))
			raise
		
		return config, JWKSet

	def __getConfigurationValByKey(self, keyname):
		try:
			config, _ = self.__getOPConfigurations()
			if config is None:
				return None
			config = json.loads(config)
		except Exception as exp:
			raise
			
		if keyname in config.keys():
			return json.dumps(config[keyname])
		else:
			return None
	
	def __getSpecificationAPIEndPoint(self, apiname):
		try:
			settingsEndPoint = self.o.__dict__[keyMap['specAPIs'][apiname]['settingsName']]
		except Exception as exp:
			return None
		
		try:
			configEndPoint = self.__getConfigurationValByKey(keyMap['specAPIs'][apiname]['configName'])
		except Exception as exp:
			raise
		
		apiEndpoint = settingsEndPoint if settingsEndPoint != "" and settingsEndPoint is not None and configEndPoint != "" and configEndPoint is not None \
			else ( configEndPoint if (settingsEndPoint == "" or settingsEndPoint is None) and configEndPoint != "" and configEndPoint is not None \
			else ( settingsEndPoint if settingsEndPoint != "" and settingsEndPoint is not None and (configEndPoint == "" or configEndPoint is None ) else None ) )
		if apiEndpoint is not None:
			apiEndpoint = str(apiEndpoint).replace('"', '')
			
		return apiEndpoint
	
	def getSpecificationAPIBasicConf(self, apiname):
		c = {}
		apiEndPoint = None
		
		if apiname != 'others':
			try:
				apiEndPoint = self.__getSpecificationAPIEndPoint(apiname)
			except Exception as exp:
				raise
			
			if apiEndPoint is not None:
				c['apiEndPoint'] = str(apiEndPoint).replace('"', '')
				c['apiName'] = keyMap['specAPIs'][apiname]['apiName']
				c['method'] = keyMap['specAPIs'][apiname]['method']
				c['contentType'] = keyMap['specAPIs'][apiname]['contentType']
				c['authorizationHeader'] = keyMap['specAPIs'][apiname]['authorizationHeader']
				
		return c


class OIDCTokenStore(object):
	
	def __init__(self, opid, session):
		if opid is None or opid == "":
			raise ParamError('opid')
		if session is None:
			raise ParamError('session')
		
		self.leeway = 60 * 60 * 24 # 1Day
		self.opId = opid
		try:
			if settings.OIDC_TOKENSTORE_COOKIENAME + opid not in session:
				session[settings.OIDC_TOKENSTORE_COOKIENAME + opid] = {}
			self.session = session[settings.OIDC_TOKENSTORE_COOKIENAME + opid]
		except Exception as exp:
			logger.error('[OIDCTokenStore.__init__] ' + str(exp))
			raise

	def getAuthzResponse(self):
		return self.__getCommonResponse('Authz')
	def getTokenResponse(self):
		return self.__getCommonResponse('Token')
	
	def getAccessToken(self):
		if 'access_token' in self.session.keys():
			return self.session['access_token']
		else:
			return None
		
	def getRefreshToken(self):
		if 'refresh_token' in self.session.keys():
			return self.session['refresh_token']
		else:
			return None

	def deleteAccessToken(self):
		if 'access_token' in self.session.keys():
			del self.session['access_token']
		if 'expireDate' in self.session.keys():
			del self.session['expireDate']
	
	def deleteRefreshToken(self):
		if 'refresh_token' in self.session.keys():
			del self.session['refresh_token']

	def setResponse(self, type, response):
		logger.debug('response='+str(response))
		params = {}
		try:
			if type == 'Authz':
				# Delete all exists objects
				#for p in self.session.keys():
				for p in list(self.session):
					if p not in keyMap['blockDeleteKeys']:
						del self.session[p]
				
				self.session[keyMap['response'][type]['sessionName']] = response.encode().decode('unicode-escape')
				parsed = parse_qs(response)
				for p in parsed.keys():
					params[p] = "".join(parsed[p]).encode().decode('unicode-escape')
			elif type == 'Token':
				self.session[keyMap['response'][type]['sessionName']] = response
				params = json.loads(response)
			elif type == 'Refresh':
				self.session[keyMap['response'][type]['sessionName']] = response
				params = json.loads(response)
			else:
				params = json.loads(response)
		except Exception as exp:
			logger.error('[OIDCTokenStore.setResponse] ' + str(exp))
			raise

		try:
			logger.debug('--- Setting session object (' + type + ') START---')
			for p in params.keys():
				if p in keyMap['response'][type]['paramNames']:
					logger.debug(p + ' = ' + str(params[p]))
					self.session[p] = str(params[p])
			logger.debug('--- Setting session object (' + type + ') END  ---')
		except Exception as exp:
			logger.error('[OIDCTokenStore.setResponse] ' + str(exp))
			raise
		
		try:
			# Update Expired For id_token
			if 'id_token' in params.keys():
				oidc = OIDCClient(self.opId)
				self.session['id_token_decoded'] = oidc.decodeIdToken(self.session['id_token'])
				j = json.loads(self.session['id_token_decoded']);
				# Update Expired For id_token
				if 'exp' in j.keys():
					self.session['id_token_expireDate'] = datetime.fromtimestamp(int(j['exp']), pytz.utc).strftime("%Y-%m-%d %H:%M:%S %Z")
					logger.debug('id_token_expireDate='+self.session['id_token_expireDate'])
				elif 'id_token_expireDate' in self.session:
					del self.session['id_token_expireDate']
			# Update Expired For access_token
			if 'expires_in' in params.keys():
				self.session['expireDate'] = datetime.fromtimestamp(int(time.mktime(datetime.now().timetuple())) + int(params['expires_in']), pytz.utc).strftime("%Y-%m-%d %H:%M:%S %Z")
				logger.debug('expireDate='+str(self.session['expireDate']))
		except Exception as exp:
			logger.error('[OIDCTokenStore.setResponse] ' + str(exp))
			raise

	def setState(self, state):
		try:
			self.session['state'] = state
		except Exception as exp:
			logger.error('[OIDCTokenStore.setState] ' + str(exp))
			raise

	def checkState(self, state):
		try:
			if 'state' in self.session:
				return self.session['state'] == state
			else:
				return False
		except Exception as exp:
			logger.error('[OIDCTokenStore.checkState] ' + str(exp))
			raise
	
	def verifySig(self,issuer=None, clientId=None, clientSecret=None, accessToken=None, sigAlgSupported=[], JWKSet=[]):
		if not issuer or issuer is None:
			raise ParamError('issuer')
		if not clientId or clientId is None:
			raise ParamError('clientId')
		if not clientSecret or clientSecret is None:
			raise ParamError('clientSecret')
		if not sigAlgSupported or sigAlgSupported is None:
			raise ParamError('sigAlgSupported')
		
		c = {}
		
		try:
			if 'id_token' not in self.session.keys() or 'id_token_decoded' not in self.session.keys():
				return c
			if 'id_token_decoded' in self.session.keys():
				id_token_decoded = json.loads(self.session['id_token_decoded'])
			if 'id_token' in self.session.keys():
				id_token = self.session['id_token']
		except Exception as exp:
			logger.error('[OIDCTokenStore.verifySig] id_token Load Error : ' + str(exp))
			raise
		
		try:
			c['issMatching'] = None
			if 'iss' in id_token_decoded.keys():
				if id_token_decoded['iss'] == issuer:
					c['issMatching'] = True
				else:
					c['issMatching'] = False
		except Exception as exp:
			logger.error('[OIDCTokenStore.verifySig] iss Matching Error : ' + str(exp))
			raise
		try:
			c['audMatching'] = None
			if 'aud' in id_token_decoded.keys():
				if clientId in id_token_decoded['aud']:
					c['audMatching'] = True
				else:
					c['audMatching'] = False
		except Exception as exp:
			logger.error('[OIDCTokenStore.verifySig] aud Matching Error : ' + str(exp))
			raise
		try:
			c['azpMatching'] = None
			if 'azp' in id_token_decoded.keys():
				if clientId in id_token_decoded['azp']:
					c['azpMatching'] = True
				else:
					c['azpMatching'] = False
		except Exception as exp:
			logger.error('[OIDCTokenStore.verifySig] azp Matching Error : ' + str(exp))
			raise
		try:
			c['expIntegrity'] = None
			if 'exp' in id_token_decoded.keys():
				if int(time.mktime(datetime.now().timetuple())) < int(id_token_decoded['exp']):
					c['expIntegrity'] = True
				else:
					c['expIntegrity'] = False
		except Exception as exp:
			logger.error('[OIDCTokenStore.verifySig] exp Integrity Error : ' + str(exp))
			raise
		try:
			c['nbfIntegrity'] = None
			if 'nbf' in id_token_decoded.keys():
				if int(time.mktime(datetime.now().timetuple())) >= int(id_token_decoded['nbf']):
					c['nbfIntegrity'] = True
				else:
					c['nbfIntegrity'] = False
		except Exception as exp:
			logger.error('[OIDCTokenStore.verifySig] nbf Integrity Error : ' + str(exp))
			raise
		try:
			c['iatIntegrity'] = None
			if 'iat' in id_token_decoded.keys():
				if (int(time.mktime(datetime.now().timetuple())) - self.leeway) < int(id_token_decoded['iat']):
					c['iatIntegrity'] = True
				else:
					c['iatIntegrity'] = False
		except Exception as exp:
			logger.error('[OIDCTokenStore.verifySig] iat Integrity Error : ' + str(exp))
			raise
		
		try:
			c['sigAlg'] = None
			c['sigType'] = None
			c['sigVerify'] = None
			idTokenHeaders, idTokenBody, idTokenSig = id_token.split('.')
			idTokenHeaders_padding = idTokenHeaders.replace('-','+').replace('_','/') + ('=' * (len(idTokenHeaders) % 4))
			idTokenHeaders_decoded = json.loads(base64.b64decode(idTokenHeaders_padding))
			idTokenBody_padding = idTokenBody.replace('-','+').replace('_','/') + ('=' * (len(idTokenBody) % 4))
			idTokenBody_b64decoded = base64.b64decode(idTokenBody_padding)
			if 'alg' in idTokenHeaders_decoded.keys():
				if (idTokenHeaders_decoded['alg'] in keyMap['hmacType'].keys() and idTokenHeaders_decoded['alg'] in sigAlgSupported) or JWKSet == "":
					c['sigType'] = 'Symmetric'
					c['sigAlg'] = idTokenHeaders_decoded['alg']
					dmod = keyMap['hmacType'][idTokenHeaders_decoded['alg']]
					sig_digest = hmac.new(clientSecret.encode(), '.'.join([idTokenHeaders, idTokenBody]).encode(), digestmod=dmod).digest()
					sig = base64.b64encode(sig_digest).decode('utf-8').replace('+','-').replace('/','_').replace('=','')
					logger.debug('sig       ='+sig)
					logger.debug('idTokenSig='+idTokenSig)
					c['sigVerify'] = (sig == idTokenSig)
					
				elif idTokenHeaders_decoded['alg'] in ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512'] and idTokenHeaders_decoded['alg'] in sigAlgSupported:
					c['sigType'] = 'Asymmetric'
					c['sigAlg'] = idTokenHeaders_decoded['alg']
					try: # Python3
						jwkstr = json.dumps(JWKSet).encode()
					except: # Python2
						jwkstr = json.dumps(JWKSet).decode('utf-8')
					logger.debug('type(jwkstr)=' + str(type(jwkstr)))
					result = jws.verify(id_token, jwkstr, algorithms=idTokenHeaders_decoded['alg'])
					logger.debug('verify result=' + str(result))
					if json.dumps(json.loads(result)) == json.dumps(json.loads(idTokenBody_b64decoded)):
						c['sigVerify'] = True
						logger.debug('verify is True')
					else:
						c['sigVerify'] = False
						logger.debug('verify is False')

				elif idTokenHeaders_decoded['alg'] == 'none':
					c['sigType'] = 'Unsecured'
					c['sigAlg'] = idTokenHeaders_decoded['alg']
				else:
					c['sigType'] = 'Unknown'
					c['sigAlg'] = idTokenHeaders_decoded['alg']
		except Exception as exp:
			logger.error('[OIDCTokenStore.verifySig] sig Validation Error : ' + str(exp))
			raise
		
		try:
			c['sigATHash'] = None
			logger.debug('accessToken=' + str(accessToken))
			logger.debug('type(accessToken)=' + str(type(accessToken)))
			if accessToken is not None:
				logger.debug('1')
				if 'at_hash' in id_token_decoded.keys():
					try: # Python3
						accessToken_bytes = accessToken.encode()
						logger.debug('accessToken_bytes=' + str(accessToken_bytes))
						logger.debug('type(accessToken_bytes)=' + str(type(accessToken_bytes)))
						digest = hashlib.sha256(accessToken_bytes).digest()
						computed_hash = base64url_encode(digest[:len(digest)//2]).decode('utf-8').replace('=','')
						logger.debug('digest=' + str(digest))
						logger.debug('type(digest)=' + str(type(digest)))
						logger.debug('base64url_encode(digest[:len(digest)//2]).decode("utf-8").replace("=","")=' + base64url_encode(digest[:len(digest)//2]).decode('utf-8').replace('=',''))
						logger.debug('type(base64url_encode(digest[:len(digest)//2]).decode("utf-8").replace("=",""))=' + str(type(base64url_encode(digest[:len(digest)//2]).decode('utf-8').replace('=',''))))
						logger.debug('id_token_decoded["at_hash"]=' + id_token_decoded['at_hash'])
					except: # Python2
						digest = hashlib.sha256(accessToken).digest()
						computed_hash = base64url_encode(digest[:len(digest)//2]).replace('=','')

					if id_token_decoded['at_hash'] == computed_hash:
						c['sigATHash'] = True
					else:
						c['sigATHash'] = False
		except Exception as exp:
			logger.error('[OIDCTokenStore.verifySig] at_hash Validation Error : ' + str(exp))
			raise
		
		return c

	def getCodeVerifier(self):
		if 'codeVerifier' in self.session:
			return self.session['codeVerifier']
		else:
			return None
	def getCodeChallenge(self):
		if 'codeChallenge' in self.session:
			return self.session['codeChallenge']
		else:
			return None
	def getChallengeMethod(self):
		if 'challengeMethod' in self.session:
			return self.session['challengeMethod']
		else:
			return None

	def generatePkce(self, challengeMethod):
		if challengeMethod != 'plain' and challengeMethod != 'S256':
			raise ParamError('challengeMethod')
		
		try:
			codeVerifier = self.__generateVerifier(128)
			logger.debug('codeVerifier=' + codeVerifier)
			logger.debug('type(codeVerifier)=' + str(type(codeVerifier)))
			if challengeMethod == 'plain':
				codeChallenge = codeVerifier
			elif challengeMethod == 'S256':
				try: # Python3
					codeVerifier_bytes = codeVerifier.encode()
					logger.debug('type(hashlib.sha256(codeVerifier_bytes)=' + str(type(hashlib.sha256(codeVerifier_bytes))))
					logger.debug('hashlib.sha256(codeVerifier_bytes).digest()=' + str(hashlib.sha256(codeVerifier_bytes).digest()))
					logger.debug('type(hashlib.sha256(codeVerifier_bytes).digest()=' + str(type(hashlib.sha256(codeVerifier_bytes).digest())))
					logger.debug('base64url_encode(hashlib.sha256(codeVerifier_bytes).digest())=' + str(base64url_encode(hashlib.sha256(codeVerifier_bytes).digest())))
					logger.debug('type(base64url_encode(hashlib.sha256(codeVerifier_bytes).digest())=' + str(type(base64url_encode(hashlib.sha256(codeVerifier_bytes).digest()))))
					codeChallenge = base64url_encode(hashlib.sha256(codeVerifier_bytes).digest()).decode('utf-8')
					logger.debug('codeChallenge=' + codeChallenge)
					logger.debug('type(codeChallenge)=' + str(type(codeChallenge)))
				except: # Python2
					codeChallenge = base64url_encode(hashlib.sha256(codeVerifier).digest())
			else:
				raise ParamError('challengeMethod')
			self.session['challengeMethod'] = challengeMethod
			self.session['codeVerifier'] = codeVerifier
			self.session['codeChallenge'] = codeChallenge
		except TypeError as exp:
			logger.error('[OIDCTokenStore.generatePkce] [TypeError] ' + str(exp))
			raise
		except Exception as exp:
			logger.error('[OIDCTokenStore.generatePkce] ' + str(exp))
			raise


	def __getCommonResponse(self, type):
		c = {}
		for k, v in self.session.items():
			logger.debug(k + ' = ' + str(v))
			if k == keyMap['response'][type]['sessionName']:
				c['response'] = v
			else:
				c[k] = v
		return c

	def __generateVerifier(self, n=128):
		try: # Python3
			return str(''.join(random.choice(string.ascii_letters + string.digits + '_-.~') for i in range(n)))
		except: # Python2
			return str(''.join(random.choice(string.ascii_letters + string.digits + '_-.~') for i in xrange(n)))

