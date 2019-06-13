# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from __future__ import print_function
from __future__ import division
from __future__ import absolute_import


import os
import string
import logging
import json
from django.shortcuts import render, redirect
from django.template import Template, Context, loader, RequestContext
from django.http import HttpResponse, HttpResponseForbidden, Http404
from django.views.decorators.csrf import csrf_exempt
#from django.views.decorators import csrf
from django.conf import settings
from rp.models import *


logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

#
# Pages
#

def test(request):
	c = {}
	return render(request, 'test.html', c)

def top(request):
	if(request.method == 'GET'):
		c = {"app_version": _get_app_version()}
		logger.debug(c)
		
		for op_init_data in settings.OP_INIT_DATA:
			try:
				if not OPSettings.objects.filter(opId=op_init_data['opId']).exists():
					opSettings = OPSettings(opId=op_init_data['opId'], displayName=op_init_data['displayName'],issuer=op_init_data['issuer'], scope="openid")
					opSettings.save()
				else:
					opSettings = OPSettings.objects.get(opId=op_init_data['opId'])
					if opSettings.displayName != op_init_data['displayName']:
						opSettings.displayName = op_init_data['displayName']
					if opSettings.issuer != op_init_data['issuer']:
						opSettings.issuer = op_init_data['issuer']
					opSettings.save()
			except Exception as exp:
				return render(request, 'error.html', {'error_message' : 'DB Save Error.'}, status=500)
		
		ops = []
		try:
			for opsetting in OPSettings.objects.all():
				loginlogo = settings.STATIC_URL + 'images/unknown-op.png'
				for op_init_data in settings.OP_INIT_DATA:
					if opsetting.opId == op_init_data['opId']:
						loginlogo = settings.STATIC_URL + 'images/' + op_init_data['loginLogo']
						break
				ops.append({'opid': opsetting.opId, 'displayname': opsetting.displayName, 'loginlogo': loginlogo})
			c['ops'] = ops
			
			return render(request, 'top.html', c)
		except OPSettings.DoesNotExist:
			c['error_message'] = 'OPSettings NotFound.'
			return render(request, 'error.html', c, status=404)
		except Exception as exp:
			c['error_message'] = 'DB Load Error.'
			return render(request, 'error.html', c, status=500)
	else:
		c['error_message'] = 'Other Error.'
		return render(request, 'error.html', c, status=500)

def oidc_redirect(request, opid):
	c = {"app_version": _get_app_version()}
	c['opId'] = opid
	
	return render(request, 'redirect.html', c)


#
# APIs
#
@csrf_exempt
def oidc_authz_req(request, opid):
	
	if not opid or opid is None:
		return HttpResponse('{"status": "PARAMERR", "message" : "Parameters(opid) Error."}', content_type="application/json", status=400)
	
	if(request.method == 'GET'):
		try:
			pref = OIDCPreference(opid)
			if not pref.checkRequired():
				return HttpResponse('{"status": "REQUIEDERR", "message" : "Required Values Error."}', content_type="application/json", status=400)
		except Exception as exp:
			logger.error('[oidc_authz_req] ' + str(exp))
			return HttpResponse('{"status": "PREFERR", "message" : "OPPrefarence Error: ' + str(exp) + ' "}', content_type="application/json", status=500)
		
		try:
			c = pref.getSpecificationAPIBasicConf('Authz')
		except Exception as exp:
			logger.error('[oidc_authz_req] ' + str(exp))
			return HttpResponse('{"status": "OTHERERR", "message" : "[oidc_authz_req] Error: ' + str(exp) + ' "}', content_type="application/json", status=500)
		
		redirectUrl = pref.getRedirectUrl()
		
		if (pref.getOptions() is None or pref.getOptions() == ""):
			options = {}
		else:
			options = pref.getOptions()
		
		state = __randstr(32)
		try:
			tokenstore = OIDCTokenStore(opid, request.session)
			tokenstore.setState(state)
			if pref.getSupportPkce():
				tokenstore.generatePkce('S256')
				codeChallenge = tokenstore.getCodeChallenge()
				challengeMethod = tokenstore.getChallengeMethod()
			else:
				codeChallenge = None
				challengeMethod = None
		except Exception as exp:
			logger.error('[oidc_authz_res] ' + str(exp))
			return HttpResponse('{"status": "TOKENERR", "message" : "PKCE Generate Error."}', content_type="application/json", status=500)
		
		oidc = OIDCClient(opid)

		url = oidc.getAuthorizationURL(authorizationEndpoint=c['apiEndPoint'], clientId=pref.getClientId(), redirectUrl=redirectUrl, responseType=pref.getResponseType(), scope=pref.getScope(), state=state, options=options, codeChallenge=codeChallenge, challengeMethod=challengeMethod)
		logger.debug('authz URL='+url)
		c = {}
		c['authorizationURL'] = url
		c['flowType'] = __getFlowType(opid)
		
		request.session.modified = True
		logger.debug('json='+json.dumps(c))
		return HttpResponse(json.dumps(c), content_type="application/json", status=200)
	else:
		return HttpResponse('{"status": "METHODERR", "message" : "Other Error."}', content_type="application/json", status=500)

@csrf_exempt
def oidc_authz_res(request, opid):
	
	if not opid or opid is None:
		return HttpResponse('{"status": "PARAMERR", "message" : "Parameters(opid) Error."}', content_type="application/json", status=400)
	
	if(request.method == 'GET'):
		c = {}
		
		try:
			tokenstore = OIDCTokenStore(opid, request.session)
			c = tokenstore.getAuthzResponse()
		except Exception as exp:
			logger.error('[oidc_authz_res] ' + str(exp))
			return HttpResponse('{"status"return: "TOKENERR", "message" : "Response Load Error."}', content_type="application/json", status=500)
		
		return HttpResponse(json.dumps(c), content_type="application/json", status=200)
	
	elif(request.method == 'POST'):
		try:
			p = json.loads(request.body)
			
			if (not 'params' in p.keys()):
				return HttpResponse('{"status": "PARAMERR", "message" : "Parameters Error."}', content_type="application/json", status=400)
		except Exception as exp:
			logger.error('[oidc_authz_res] ' + str(exp))
			return HttpResponse('{"status": "PARAMERR", "message" : "Parameters Error."}', content_type="application/json", status=500)
		
		c = {}
		
		try:
			tokenstore = OIDCTokenStore(opid, request.session)
			tokenstore.setResponse('Authz', p['params'])
		except Exception as exp:
			logger.error('[oidc_authz_res] ' + str(exp))
			return HttpResponse('{"status": "TOKENERR", "message" : "Response Set Error."}', content_type="application/json", status=500)

		request.session.modified = True
		return HttpResponse('{"status": "OK", "message" : "Saved Response."}', content_type="application/json", status=200)
		
	else:
		request.session.modified = True
		return HttpResponse('{"status": "METHODERR", "message" : "Other Error."}', content_type="application/json", status=500)

@csrf_exempt
def oidc_token(request, opid):
	
	if not opid or opid is None:
		return HttpResponse('{"status": "PARAMERR", "message" : "Parameters(opid) Error."}', content_type="application/json", status=400)
	
	if(request.method == 'GET'):
		c = {}
		
		try:
			tokenstore = OIDCTokenStore(opid, request.session)
			c = tokenstore.getTokenResponse()
		except Exception as exp:
			logger.error('[oidc_token] ' + str(exp))
			return HttpResponse('{"status": "TOKENERR", "message" : "Response Load Error."}', content_type="application/json", status=500)
		
		return HttpResponse(json.dumps(c), content_type="application/json", status=200)
	
	elif(request.method == 'POST'):
		c = {}

		try:
			p = json.loads(request.body)
			
			if('error' in p.keys()):
				return HttpResponse('{"status": "OTHERERR", "message" : "Error:' + p["error"] + '"}', content_type="application/json", status=500)
			if('code' not in p.keys()):
				return HttpResponse('{"status": "PARAMERR", "message" : "code is missing."}', content_type="application/json", status=400)
			if('state' not in p.keys()):
				return HttpResponse('{"status": "PARAMERR", "message" : "state is missing."}', content_type="application/json", status=400)
			if('doCheckState' not in p.keys()):
				return HttpResponse('{"status": "PARAMERR", "message" : "doCheckState is missing."}', content_type="application/json", status=400)
		except Exception as exp:
			logger.error('[oidc_token] ' + str(exp))
			return HttpResponse('{"status": "PARAMERR", "message" : "Parameters Error."}', content_type="application/json", status=500)
		

		try:
			tokenstore = OIDCTokenStore(opid, request.session)
			
			if p['doCheckState'] == 'true':
				if not tokenstore.checkState(p['state']):
					return HttpResponse('{"status": "STATEERR", "message" : "State not match."}', content_type="application/json", status=400)
			else:
				logger.debug('doCheckState is false.')
		except Exception as exp:
			logger.error('[oidc_token] ' + str(exp))
			return HttpResponse('{"status": "TOKENERR", "message" : "Token Load Error."}', content_type="application/json", status=500)
		
		try:
			pref = OIDCPreference(opid)
			if not pref.checkRequired():
				return HttpResponse('{"status": "REQUIEDERR", "message" : "Required Values Error."}', content_type="application/json", status=400)
		except Exception as exp:
			logger.error('[oidc_token] ' + str(exp))
			return HttpResponse('{"status": "PREFERR", "message" : "OPPreference Error: ' + str(exp) + ' "}', content_type="application/json", status=500)
		
		try:
			m = pref.getSpecificationAPIBasicConf('Token')
		except Exception as exp:
			logger.error('[oidc_token] ' + str(exp))
			return HttpResponse('{"status": "OTHERERR", "message" : "[getSpecificationAPIBasicConf] Error: ' + str(exp) + ' "}', content_type="application/json", status=500)
		
		try:
			logger.debug('getSupportPkce()='+str(pref.getSupportPkce()))
			if pref.getSupportPkce() == True:
				codeVerifier = tokenstore.getCodeVerifier()
				logger.debug('codeVerifier='+codeVerifier)
			else:
				codeVerifier = None
		except Exception as exp:
			logger.error('[oidc_token] ' + str(exp))
			return HttpResponse('{"status": "TOKENERR", "message" : "PKCE Get Error."}', content_type="application/json", status=500)
		
		oidc = OIDCClient(opid)
		
		try:
			c = oidc.getAccessToken(tokenEndpoint=m['apiEndPoint'], clientId=pref.getClientId(), clientSecret=pref.getClientSecret(), redirectUrl=pref.getRedirectUrl(), code=p['code'], codeVerifier=codeVerifier)
			logger.debug( c['responseBody'] )
		except Exception as exp:
			logger.error('[oidc_token] ' + str(exp))
			return HttpResponse('{"status": "GETTOKENERR", "message" : "Access Token Exchange Error: ' + str(exp) + ' "}', content_type="application/json", status=500)
		
		if c['statusCode'] == '200':
			try:
				tokenstore.setResponse('Token', c['responseBody'])
				t = tokenstore.getTokenResponse()
				c.update(t)
			except Exception as exp:
				logger.error('[oidc_token] ' + str(exp))
				return HttpResponse('{"status": "TOKENERR", "message" : "Token Save/Load Error."}', content_type="application/json", status=500)
		
		request.session.modified = True
		return HttpResponse(json.dumps(c), content_type="application/json", status=200)
	else:
		return HttpResponse('{"status": "METHODERR", "message" : "Other Error."}', content_type="application/json", status=500)

@csrf_exempt
def oidc_refresh(request, opid):
	
	if not opid or opid is None:
		return HttpResponse('{"status": "PARAMERR", "message" : "Parameters(opid) Error."}', content_type="application/json", status=400)
	
	if(request.method == 'GET'):
		c = {}

		try:
			pref = OIDCPreference(opid)
			if not pref.checkRequired():
				return HttpResponse('{"status": "REQUIEDERR", "message" : "Required Values Error."}', content_type="application/json", status=400)
		except Exception as exp:
			logger.error('[oidc_refresh] ' + str(exp))
			return HttpResponse('{"status": "PREFERR", "message" : "OPPreference Error: ' + str(exp) + ' "}', content_type="application/json", status=500)
		
		try:
			c = pref.getSpecificationAPIBasicConf('Refresh')
		except Exception as exp:
			logger.error('[oidc_refresh] ' + str(exp))
			return HttpResponse('{"status": "OTHERERR", "message" : "[oidc_refresh] Error: ' + str(exp) + ' "}', content_type="application/json", status=500)
		
		try:
			tokenstore = OIDCTokenStore(opid, request.session)
			refreshToken = tokenstore.getRefreshToken()
			logger.debug('refreshToken=' + refreshToken)
			logger.debug('type(refreshToken)=' + str(type(refreshToken)))
		except Exception as exp:
			logger.error('[oidc_refresh] ' + str(exp))
			return HttpResponse('{"status": "TOKENERR", "message" : "Token Get Error."}', content_type="application/json", status=500)
		
		if refreshToken is None:
			return HttpResponse('{"status": "TOKENERR", "message" : "Refresh Token Not Found."}', content_type="application/json", status=400)
		
		oidc = OIDCClient(opid)
		try:
			url, query = oidc.getRefreshTokenParams(tokenEndpoint=c['apiEndPoint'], refreshToken=refreshToken, args={})
			logger.debug('url=' + str(url))
			logger.debug('type(url)=' + str(type(url)))
			logger.debug('query=' + str(query))
			logger.debug('type(query)=' + str(type(query)))
		except Exception as exp:
			logger.error('[oidc_refresh] ' + str(exp))
			return HttpResponse('{"status": "OTHERERR", "message" : "[oidc_refresh] Error: ' + str(exp) + ' "}', content_type="application/json", status=500)
		
		c['params'] = str(query)

		return HttpResponse(json.dumps(c), content_type="application/json", status=200)
	
	elif(request.method == 'POST'):
		c = {}

		try:
			p = json.loads(request.body)
			if('apiEndPoint' not in p.keys()):
				return HttpResponse('{"status": "PARAMERR", "message" : "apiEndPoint is missing."}', content_type="application/json", status=400)
			if('authorizationHeader' not in p.keys()):
				return HttpResponse('{"status": "PARAMERR", "message" : "authorizationHeader is missing."}', content_type="application/json", status=400)
			if('method' not in p.keys()):
				return HttpResponse('{"status": "PARAMERR", "message" : "method is missing."}', content_type="application/json", status=400)
			if('contentType' not in p.keys()):
				return HttpResponse('{"status": "PARAMERR", "message" : "contentType is missing."}', content_type="application/json", status=400)
			if('params' not in p.keys()):
				return HttpResponse('{"status": "PARAMERR", "message" : "params is missing."}', content_type="application/json", status=400)
		except Exception as exp:
			logger.error('[oidc_refresh] ' + str(exp))
			return HttpResponse('{"status": "PARAMERR", "message" : "Parameters Error."}', content_type="application/json", status=500)

		try:
			pref = OIDCPreference(opid)
			if not pref.checkRequired():
				return HttpResponse('{"status": "REQUIEDERR", "message" : "Required Values Error."}', content_type="application/json", status=400)
		except Exception as exp:
			logger.error('[oidc_refresh] ' + str(exp))
			return HttpResponse('{"status": "PREFERR", "message" : "OPPreference Error: ' + str(exp) + ' "}', content_type="application/json", status=500)
		
		oidc = OIDCClient(opid)
		
		try:
			c = oidc.commonApi(method=p['method'], apiUrl=p['apiEndPoint'], clientId=pref.getClientId(), clientSecret=pref.getClientSecret(), contentType=p['contentType'], authorizationType=p['authorizationHeader'], payload=p['params'])
		except Exception as exp:
			logger.error('[oidc_refresh] ' + str(exp))
			return HttpResponse('{"status": "CALLAPIERR", "message" : "Refresh Token Calling Error: ' + str(exp) + ' "}', content_type="application/json", status=500)
		
		if c['statusCode'] == '200':
			try:
				tokenstore = OIDCTokenStore(opid, request.session)
				tokenstore.setResponse('Refresh', c['responseBody'])
			except Exception as exp:
				logger.error('[oidc_refresh] ' + str(exp))
				return HttpResponse('{"status": "TOKENERR", "message" : "Token Save Error."}', content_type="application/json", status=500)
		
		request.session.modified = True
		return HttpResponse(json.dumps(c), content_type="application/json", status=200)
		
	else:
		return HttpResponse('{"status": "METHODERR", "message" : "Other Error."}', content_type="application/json", status=500)
	
@csrf_exempt
def oidc_userinfo(request, opid):
	
	if not opid or opid is None:
		return HttpResponse('{"status": "PARAMERR", "message" : "Parameters(opid) Error."}', content_type="application/json", status=400)
	
	if(request.method == 'GET'):
		c = {}

		try:
			pref = OIDCPreference(opid)
			if not pref.checkRequired():
				return HttpResponse('{"status": "REQUIEDERR", "message" : "Required Values Error."}', content_type="application/json", status=400)
		except Exception as exp:
			logger.error('[oidc_userinfo] ' + str(exp))
			return HttpResponse('{"status": "PREFERR", "message" : "OPPreference Error: ' + str(exp) + ' "}', content_type="application/json", status=500)
		
		try:
			c = pref.getSpecificationAPIBasicConf('UserInfo')
		except Exception as exp:
			logger.error('[oidc_userinfo] ' + str(exp))
			return HttpResponse('{"status": "OTHERERR", "message" : "[oidc_userinfo] Error: ' + str(exp) + ' "}', content_type="application/json", status=500)

		return HttpResponse(json.dumps(c), content_type="application/json", status=200)
	
	elif(request.method == 'POST'):
		c = {}

		try:
			p = json.loads(request.body)
			if('apiEndPoint' not in p.keys()):
				return HttpResponse('{"status": "PARAMERR", "message" : "apiEndPoint is missing."}', content_type="application/json", status=400)
			if('authorizationHeader' not in p.keys()):
				return HttpResponse('{"status": "PARAMERR", "message" : "authorizationHeader is missing."}', content_type="application/json", status=400)
			if('method' not in p.keys()):
				return HttpResponse('{"status": "PARAMERR", "message" : "method is missing."}', content_type="application/json", status=400)
			if('contentType' not in p.keys()):
				return HttpResponse('{"status": "PARAMERR", "message" : "contentType is missing."}', content_type="application/json", status=400)
			if('params' not in p.keys()):
				return HttpResponse('{"status": "PARAMERR", "message" : "params is missing."}', content_type="application/json", status=400)
		except Exception as exp:
			logger.error('[oidc_userinfo] ' + str(exp))
			return HttpResponse('{"status": "PARAMERR", "message" : "Parameters Error."}', content_type="application/json", status=500)
		
		try:
			tokenstore = OIDCTokenStore(opid, request.session)
			accessToken = tokenstore.getAccessToken()
		except Exception as exp:
			logger.error('[oidc_userinfo] ' + str(exp))
			return HttpResponse('{"status": "TOKENERR", "message" : "Token Get Error."}', content_type="application/json", status=500)
		
		if accessToken is None:
			return HttpResponse('{"status": "TOKENERR", "message" : "Refresh Token Not Found."}', content_type="application/json", status=400)
		
		oidc = OIDCClient(opid)
		
		try:
			c = oidc.commonApi(method=p['method'], apiUrl=p['apiEndPoint'], accessToken=accessToken, contentType=p['contentType'], authorizationType=p['authorizationHeader'], payload=p['params'])
		except Exception as exp:
			logger.error('[oidc.commonApi] ' + str(exp))
			return HttpResponse('{"status": "CALLAPIERR", "message" : "UserInfo Calling Error: ' + str(exp) + ' "}', content_type="application/json", status=500)

		return HttpResponse(json.dumps(c), content_type="application/json", status=200)
	else:
		return HttpResponse('{"status": "METHODERR", "message" : "Other Error."}', content_type="application/json", status=500)

@csrf_exempt
def oidc_revocation(request, opid):
	
	if not opid or opid is None:
		return HttpResponse('{"status": "PARAMERR", "message" : "Parameters(opid) Error."}', content_type="application/json", status=400)
	
	if(request.method == 'GET'):
		c = {}

		try:
			pref = OIDCPreference(opid)
			if not pref.checkRequired():
				return HttpResponse('{"status": "REQUIEDERR", "message" : "Required Values Error."}', content_type="application/json", status=400)
		except Exception as exp:
			logger.error('[oidc_revocation] ' + str(exp))
			return HttpResponse('{"status": "PREFERR", "message" : "OPPreference Error: ' + str(exp) + ' "}', content_type="application/json", status=500)
		
		try:
			c = pref.getSpecificationAPIBasicConf('Revocation')
		except Exception as exp:
			logger.error('[oidc_revocation] ' + str(exp))
			return HttpResponse('{"status": "OTHERERR", "message" : "[oidc_refresh] Error: ' + str(exp) + ' "}', content_type="application/json", status=500)
		
		if (len(c) == 0):
			return HttpResponse('{"status": "APPERR", "message" : "The OP seems to not provide Revocation API."}', content_type="application/json", status=400)
		
		try:
			tokenstore = OIDCTokenStore(opid, request.session)
			accessToken = tokenstore.getAccessToken()
			refreshToken = tokenstore.getRefreshToken()
		except Exception as exp:
			logger.error('[oidc_revocation] ' + str(exp))
			return HttpResponse('{"status": "TOKENERR", "message" : "Token Get Error."}', content_type="application/json", status=500)
		
		if accessToken is None:
			return HttpResponse('{"status": "TOKENERR", "message" : "AccessToken Not Found."}', content_type="application/json", status=400)
		
		tokenParams = {}
		oidc = OIDCClient(opid)
		try:
			_, query = oidc.getRevocationParams(revocationEndpoint=c['apiEndPoint'], accessToken=accessToken, args={})
			tokenParams['access_token'] = str(query)

			if refreshToken is not None:
				url, query = oidc.getRevocationParams(revocationEndpoint=c['apiEndPoint'], refreshToken=refreshToken, args={})
				tokenParams['refresh_token'] = str(query)
		except Exception as exp:
			logger.error('[oidc.getRevocationParams] ' + str(exp))
			return HttpResponse('{"status": "OTHERERR", "message" : "[oidc.getRevocationParams] Error: ' + str(exp) + ' "}', content_type="application/json", status=500)
		
		c['tokenParams'] = tokenParams

		return HttpResponse(json.dumps(c), content_type="application/json", status=200)
	
	elif(request.method == 'POST'):
		c = {}

		try:
			p = json.loads(request.body)
			if('apiEndPoint' not in p.keys()):
				return HttpResponse('{"status": "PARAMERR", "message" : "apiEndPoint is missing."}', content_type="application/json", status=400)
			if('authorizationHeader' not in p.keys()):
				return HttpResponse('{"status": "PARAMERR", "message" : "authorizationHeader is missing."}', content_type="application/json", status=400)
			if('method' not in p.keys()):
				return HttpResponse('{"status": "PARAMERR", "message" : "method is missing."}', content_type="application/json", status=400)
			if('contentType' not in p.keys()):
				return HttpResponse('{"status": "PARAMERR", "message" : "contentType is missing."}', content_type="application/json", status=400)
			if('tokenType' not in p.keys()):
				return HttpResponse('{"status": "PARAMERR", "message" : "tokenType is missing."}', content_type="application/json", status=400)
			if('params' not in p.keys()):
				return HttpResponse('{"status": "PARAMERR", "message" : "params is missing."}', content_type="application/json", status=400)
		except Exception as exp:
			logger.error('[oidc_revocation] ' + str(exp))
			return HttpResponse('{"status": "PARAMERR", "message" : "Parameters Error."}', content_type="application/json", status=500)
		
		try:
			pref = OIDCPreference(opid)
			if not pref.checkRequired():
				return HttpResponse('{"status": "REQUIEDERR", "message" : "Required Values Error."}', content_type="application/json", status=400)
		except Exception as exp:
			logger.error('[oidc_revocation] ' + str(exp))
			return HttpResponse('{"status": "PREFERR", "message" : "OPPreference Error: ' + str(exp) + ' "}', content_type="application/json", status=500)

		oidc = OIDCClient(opid)
		
		try:
			c = oidc.commonApi(method=p['method'], apiUrl=p['apiEndPoint'], clientId=pref.getClientId(), clientSecret=pref.getClientSecret(), contentType=p['contentType'], authorizationType=p['authorizationHeader'], payload=p['params'])
		except Exception as exp:
			logger.error('[oidc_revocation] ' + str(exp))
			return HttpResponse('{"status": "CALLAPIERR", "message" : "Revocation Calling Error: ' + str(exp) + ' "}', content_type="application/json", status=500)

		if c['statusCode'] == '200':
			try:
				tokenstore = OIDCTokenStore(opid, request.session)
				if p['tokenType'] == 'access_token':
					tokenstore.deleteAccessToken()
				elif p['tokenType'] == 'refresh_token':
					tokenstore.deleteRefreshToken()
			except Exception as exp:
				logger.error('[oidc_revocation] ' + str(exp))
				return HttpResponse('{"status": "TOKENERR", "message" : "Token Save Error."}', content_type="application/json", status=500)

		request.session.modified = True
		return HttpResponse(json.dumps(c), content_type="application/json", status=200)
	else:
		return HttpResponse('{"status": "METHODERR", "message" : "Other Error."}', content_type="application/json", status=500)

@csrf_exempt
def oidc_introspection(request, opid):
	return HttpResponse('{"status": "OTHERERR", "message" : "Not Implement Yet."}', content_type="application/json", status=400)

@csrf_exempt
def oidc_custom(request, opid):
	
	if not opid or opid is None:
		return HttpResponse('{"status": "PARAMERR", "message" : "Parameters(opid) Error."}', content_type="application/json", status=400)
	
	if(request.method == 'GET'):
		c = {}
		c['apiEndPoint'] = ''
		c['apiName'] = 'Custom'
		c['method'] = 'GET'
		c['contentType'] = 'none'
		c['authorizationHeader'] = 'none'
		c['params'] = ''
		
		return HttpResponse(json.dumps(c), content_type="application/json", status=200)
	
	elif(request.method == 'POST'):
		c = {}

		try:
			p = json.loads(request.body)
			if('apiEndPoint' not in p.keys()):
				return HttpResponse('{"status": "PARAMERR", "message" : "apiEndPoint is missing."}', content_type="application/json", status=400)
			if('authorizationHeader' not in p.keys()):
				return HttpResponse('{"status": "PARAMERR", "message" : "authorizationHeader is missing."}', content_type="application/json", status=400)
			if('method' not in p.keys()):
				return HttpResponse('{"status": "PARAMERR", "message" : "method is missing."}', content_type="application/json", status=400)
			if('contentType' not in p.keys()):
				return HttpResponse('{"status": "PARAMERR", "message" : "contentType is missing."}', content_type="application/json", status=400)
			if('params' not in p.keys()):
				return HttpResponse('{"status": "PARAMERR", "message" : "params is missing."}', content_type="application/json", status=400)
		except Exception as exp:
			logger.error('[oidc_custom] ' + str(exp))
			return HttpResponse('{"status": "PARAMERR", "message" : "Parameters Error."}', content_type="application/json", status=500)

		try:
			pref = OIDCPreference(opid)
			if not pref.checkRequired():
				return HttpResponse('{"status": "REQUIEDERR", "message" : "Required Values Error."}', content_type="application/json", status=400)
		except Exception as exp:
			logger.error('[oidc_custom] ' + str(exp))
			return HttpResponse('{"status": "PREFERR", "message" : "OPPreference Error: ' + str(exp) + ' "}', content_type="application/json", status=500)
		
		try:
			tokenstore = OIDCTokenStore(opid, request.session)
			accessToken = tokenstore.getAccessToken()
		except Exception as exp:
			logger.error('[oidc_custom] ' + str(exp))
			return HttpResponse('{"status": "TOKENERR", "message" : "Token Get Error."}', content_type="application/json", status=500)
		
		if accessToken is None:
			return HttpResponse('{"status": "TOKENERR", "message" : "AccessToken Not Found."}', content_type="application/json", status=400)
		
		oidc = OIDCClient(opid)
		
		try:
			c = oidc.commonApi(method=p['method'], apiUrl=p['apiEndPoint'], clientId=pref.getClientId(), clientSecret=pref.getClientSecret(), accessToken=accessToken, contentType=p['contentType'], authorizationType=p['authorizationHeader'], payload=p['params'])
		except Exception as exp:
			logger.error('[oidc.commonApi] ' + str(exp))
			return HttpResponse('{"status": "CALLAPIERR", "message" : "Custom Calling Error: ' + str(exp) + ' "}', content_type="application/json", status=500)

		if c['statusCode'] == '200':
			try:
				tokenstore = OIDCTokenStore(opid, request.session)
				tokenstore.setResponse('Custom', c['responseBody'])
			except Exception as exp:
				logger.error('[oidc_custom] ' + str(exp))
				return HttpResponse('{"status": "TOKENERR", "message" : "Token Save Error."}', content_type="application/json", status=500)

		request.session.modified = True
		return HttpResponse(json.dumps(c), content_type="application/json", status=200)
	else:
		return HttpResponse('{"status": "METHODERR", "message" : "Other Error."}', content_type="application/json", status=500)
		
@csrf_exempt
def oidc_verify(request, opid):
	
	if not opid or opid is None:
		return HttpResponse('{"status": "PARAMERR", "message" : "Parameters(opid) Error."}', content_type="application/json", status=400)
	
	if(request.method == 'GET'):
		try:
			pref = OIDCPreference(opid)
			if not pref.checkRequired():
				return HttpResponse('{"status": "REQUIEDERR", "message" : "Required Values Error."}', content_type="application/json", status=400)
		except Exception as exp:
			logger.error('[oidc_verify] ' + str(exp))
			return HttpResponse('{"status": "PREFERR", "message" : "OPPreference Error: ' + str(exp) + ' "}', content_type="application/json", status=500)
		
		accessToken = None
		try:
			tokenstore = OIDCTokenStore(opid, request.session)
			accessToken = tokenstore.getAccessToken()
		except Exception as exp:
			logger.error('[oidc_verify] ' + str(exp))
			return HttpResponse('{"status": "TOKENERR", "message" : "Token Get Error."}', content_type="application/json", status=500)
		
		c = {}
		try:
			c = tokenstore.verifySig(pref.getIssuer(), pref.getClientId(), pref.getClientSecret(), accessToken, pref.getIdTokenSigningAlgValuesSupported(), pref.getJWKSet())
		except Exception as exp:
			logger.error('[oidc_verify] ' + str(exp))
			return HttpResponse('{"status": "TOKENERR", "message" : "Token Verify Error."}', content_type="application/json", status=500)
		
		return HttpResponse(json.dumps(c), content_type="application/json", status=200)
	else:
		return HttpResponse('{"status": "METHODERR", "message" : "Other Error."}', content_type="application/json", status=500)

@csrf_exempt
def opSettings(request, opid):

	if not opid or opid is None:
		return HttpResponse('{"status": "PARAMERR", "message" : "Parameters(opid) Error."}', content_type="application/json", status=400)
	
	if(request.method == 'GET'):
		try:
			pref = OIDCPreference(opid)
			c = pref.getPreference()
		except Exception as exp:
			logger.error('[opSettings] ' + str(exp))
			return HttpResponse('{"status": "PREFERR", "message" : "OPPrefarence Load Error: ' + str(exp) + ' "}', content_type="application/json", status=500)

		return HttpResponse(json.dumps(c), content_type="application/json", status=200)
		
	elif(request.method == 'POST'):

		try:
			c = json.loads(request.body)

			if (not 'clientId' in c.keys()) or (not 'clientSecret' in c.keys()) or (not 'redirect_url' in c.keys()) or (not 'scope' in c.keys()):
				return HttpResponse('{"status": "PARAMERR", "message" : "Parameters Error."}', content_type="application/json", status=400)
			if (not c['clientId'] or c['clientId'] is None) or (not c['clientSecret'] or c['clientSecret'] is None) or (not c['redirect_url'] or c['redirect_url'] is None):
				return HttpResponse('{"status": "PARAMERR", "message" : "Parameters Error."}', content_type="application/json", status=400)
			if c['scope'] is None or c['scope'] == "":
				c['scope'] = "openid"
		except Exception as exp:
			logger.error('[opSettings] ' + str(exp))
			return HttpResponse('{"status": "PARAMERR", "message" : "Parameters Error."}', content_type="application/json", status=500)
		
		try:
			pref = OIDCPreference(opid)
			pref.setPreference(c)
		except Exception as exp:
			logger.error('[opSettings] ' + str(exp))
			return HttpResponse('{"status": "PREFERR", "message" : "OPPrefarence Save Error: ' + str(exp) + ' "}', content_type="application/json", status=500)
		
		return HttpResponse('{"status": "OK", "message" : "Saved OPSettungs."}', content_type="application/json", status=200)

	else:
		return HttpResponse('{"status": "METHODERR", "message" : "Other Error."}', content_type="application/json", status=500)




#
# Common Functions
#

def __randstr(n=32):
	return str(''.join(random.choice(string.ascii_letters + string.digits + '_-') for i in range(n)))

def __getFlowType(opid):
	ftype = None
	
	try:
		o = OPSettings.objects.get(opId=opid)
	except Exception as exp:
		raise
	
	rt = o.responseType.split(' ')
	if len(rt) == 1 and rt[0] == 'code':
		ftype = 'authorization_code'
	elif (len(rt) == 1 and rt[0] == 'id_token') or (len(rt) == 1 and rt[0] == 'token') or (len(rt) == 2 and 'id_token' in rt and 'token' in rt):
		ftype = 'implicit'
	elif (len(rt) == 2 and 'code' in rt and 'token' in rt) or (len(rt) == 2 and 'code' in rt and 'id_token' in rt) or (len(rt) == 3 and 'code' in rt and 'token' in rt and 'id_token' in rt):
		ftype = 'hybrid'
	else:
		ftype = 'unknown'
	
	return ftype
	
def _get_app_version():
    ret_ver = '(?)'
    try:
        version_file = None

        if os.path.exists(os.path.join(os.path.dirname(os.path.abspath(__name__)), './VERSION')):
            version_file = os.path.join(os.path.dirname(os.path.abspath(__name__)), './VERSION')
        elif os.path.exists(os.path.join(os.path.dirname(os.path.abspath(__name__)), '../VERSION')):
            version_file = os.path.join(os.path.dirname(os.path.abspath(__name__)), '../VERSION')
        elif os.path.exists(os.path.join(os.path.dirname(os.path.abspath(__name__)), '../../VERSION')):
            version_file = os.path.join(os.path.dirname(os.path.abspath(__name__)), '../../VERSION')
        if version_file is not None:
            with open(version_file) as f:
                ret_ver = f.read()
    except IOError:
        pass
    return ret_ver