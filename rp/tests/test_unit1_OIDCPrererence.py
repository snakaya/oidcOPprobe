# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import logging
import datetime
import json
from django.conf import settings
from django.test import TestCase, Client
from requests.exceptions import *
from rp.models import *


class OIDCPreferenceTestCase(TestCase):
	
	# Variables
	
	opId = 'pseudoOP'
	displayName = 'pseudoOP Name'
	issuer = 'https://accounts.google.com'
	redirect_url = settings.OIDC_REDIRECT_URL + opId
	scope = 'openid'
	
	fake_issuer1 = 'https://xxx.google.com'
	fake_issuer2 = 'https://accounts.google.com/xxx'
	
	# Initialize / Finalize
	
	@classmethod
	def setUpTestData(cls):
		pass

	def setUp(self):
		#pass
		settings = OPSettings(opId=self.opId, displayName=self.displayName, issuer=self.issuer, redirect_url=self.redirect_url, scope=self.scope)
		settings.save()
	
	def tearDown(self):
		#pass
		OPSettings.objects.all().delete()
		OPConfigurations.objects.all().delete()
	
	# Normal Case
	
	def test_1_1_Construct_initial_normal(self):
		"Initial Construct OIDCPreference Model."
		pref = OIDCPreference('pseudoOP')
		self.assertEquals(pref.getIssuer(), self.issuer)
		self.assertEquals(pref.getScope(), self.scope)
		self.assertEquals(pref.getClientId(), '')
		self.assertEquals(pref.getResponseType(), '')
		self.assertEquals(pref.getResponseType(), '')
		self.assertEquals(pref.getOptions(), '')
		self.assertEquals(pref.getRedirectUrl(), self.redirect_url)
		
	def test_1_2_getPreference_initial_normal(self):
		"Getting Preference from OIDCPreference Model."
		pref = OIDCPreference('pseudoOP')
		c = pref.getPreference()
		self.assertEquals(c['opId'], self.opId)
		self.assertEquals(c['displayName'], self.displayName)
		self.assertEquals(c['issuer'], self.issuer)
		self.assertEquals(c['clientId'], '')
		self.assertEquals(c['clientSecret'], '')
		self.assertEquals(c['redirect_url'], settings.OIDC_REDIRECT_URL + self.opId)
		self.assertEquals(c['authorizationEndpoint'], '')
		self.assertEquals(c['tokenizationEndpoint'], '')
		self.assertEquals(c['userinfoEndpoint'], '')
		self.assertEquals(c['revocationEndpoint'], '')
		self.assertEquals(c['introspectionEndpoint'], '')
		self.assertEquals(c['responseType'], '')
		self.assertEquals(c['scope'], self.scope)
		self.assertEquals(c['options'], '')
		self.assertEquals(c['supportPkce'], False)
		config = OPConfigurations.objects.get(opId=self.opId)
		self.assertNotEquals(config.configurations, '')
		self.assertNotEquals(config.jwkSet, '')

	def test_1_3_getAlgSupported_normal(self):
		"Getting IdTokenSigningAlgValuesSupported from OIDCPreference Model."
		pref = OIDCPreference('pseudoOP')
		self.assertEquals(len(pref.getIdTokenSigningAlgValuesSupported()) > 0, True)
	
	def test_1_4_1_getConfigration_normal(self):
		"Getting Configration from OIDCPreference Model."
		pref = OIDCPreference('pseudoOP')
		self.assertEquals(len(pref.getConfigration()) > 0, True)
	
	def test_1_4_2_getJWKSet_normal(self):
		"Getting JWKSet from OIDCPreference Model."
		pref = OIDCPreference('pseudoOP')
		self.assertEquals(len(pref.getJWKSet()) > 0, True)
		
	def test_1_5_1_checkRequired_normal(self):
		"Testing checkRequired Function in OIDCPreference Model."
		o = OPSettings.objects.get(opId=self.opId)
		o.clientId = '_clientId_'
		o.clientSecret = '_clientSecret_'
		o.responseType = 'code id_token'
		o.scope = 'openid'
		o.save()
		pref = OIDCPreference('pseudoOP')
		self.assertEquals(pref.checkRequired(), True)
	def test_1_5_2_checkRequired_normal(self):
		"Testing checkRequired Function in OIDCPreference Model."
		o = OPSettings.objects.get(opId=self.opId)
		o.clientId = ''
		o.clientSecret = ''
		o.responseType = 'code id_token'
		o.scope = 'openid'
		o.save()
		pref = OIDCPreference('pseudoOP')
		self.assertEquals(pref.checkRequired(), False)
	def test_1_5_3_checkRequired_normal(self):
		"Testing checkRequired Function in OIDCPreference Model."
		o = OPSettings.objects.get(opId=self.opId)
		o.clientId = '_clientId_'
		o.clientSecret = ''
		o.responseType = 'code id_token'
		o.scope = 'openid'
		o.save()
		pref = OIDCPreference('pseudoOP')
		self.assertEquals(pref.checkRequired(), False)
	def test_1_5_4_checkRequired_normal(self):
		"Testing checkRequired Function in OIDCPreference Model."
		o = OPSettings.objects.get(opId=self.opId)
		o.clientId = ''
		o.clientSecret = '_clientSecret_'
		o.responseType = 'code id_token'
		o.scope = 'openid'
		o.save()
		pref = OIDCPreference('pseudoOP')
		self.assertEquals(pref.checkRequired(), False)
	def test_1_5_5_checkRequired_normal(self):
		"Testing checkRequired Function in OIDCPreference Model."
		o = OPSettings.objects.get(opId=self.opId)
		o.clientId = ''
		o.clientSecret = ''
		o.responseType = 'code id_token'
		o.scope = ''
		o.save()
		pref = OIDCPreference('pseudoOP')
		self.assertEquals(pref.checkRequired(), False)
	def test_1_5_6_checkRequired_normal(self):
		"Testing checkRequired Function in OIDCPreference Model."
		o = OPSettings.objects.get(opId=self.opId)
		o.clientId = ''
		o.clientSecret = ''
		o.responseType = ''
		o.scope = 'openid'
		o.save()
		pref = OIDCPreference('pseudoOP')
		self.assertEquals(pref.checkRequired(), False)
	
	def test_1_6_1_settPreference_normal(self):
		"Setting Preference from OIDCPreference Model."
		pref = OIDCPreference('pseudoOP')
		c = {}
		c['opId'] = 'FakaOP'
		c['displayName'] = 'FakeOP Name'
		c['issuer'] = 'https://fakeop/'
		c['clientId'] = '_clientId_'
		c['clientSecret'] = '_clientSecret_'
		c['redirect_url'] = '_redirect_url_'
		c['authorizationEndpoint'] = '_authorizationEndpoint_'
		c['tokenizationEndpoint'] = '_tokenizationEndpoint_'
		c['userinfoEndpoint'] = '_userinfoEndpoint_'
		c['revocationEndpoint'] = '_revocationEndpoint_'
		c['introspectionEndpoint'] = '_introspectionEndpoint_'
		c['responseType'] = '_responseType_'
		c['scope'] = '_scope_'
		c['options'] = '_options_'
		c['supportPkce'] = 'true'
		pref.setPreference(c)
		
		o = OPSettings.objects.get(opId=self.opId)
		self.assertEquals(o.displayName, self.displayName)
		self.assertEquals(o.issuer, self.issuer)
		self.assertEquals(o.clientId, '_clientId_')
		self.assertEquals(o.clientSecret, '_clientSecret_')
		self.assertEquals(o.redirect_url, self.redirect_url)
		self.assertEquals(o.authorizationEndpoint, '_authorizationEndpoint_')
		self.assertEquals(o.tokenizationEndpoint, '_tokenizationEndpoint_')
		self.assertEquals(o.userinfoEndpoint, '_userinfoEndpoint_')
		self.assertEquals(o.revocationEndpoint, '_revocationEndpoint_')
		self.assertEquals(o.introspectionEndpoint, '_introspectionEndpoint_')
		self.assertEquals(o.responseType, '_responseType_')
		self.assertEquals(o.scope, '_scope_')
		self.assertEquals(o.options, '_options_')
		self.assertEquals(o.supportPkce, True)
		
	def test_1_6_2_settPreference_defaultvalues(self):
		"Check Default Values, When Setting Preference from OIDCPreference Model."
		pref = OIDCPreference('pseudoOP')
		c = {}
		c['clientId'] = ''
		c['clientSecret'] = ''
		c['redirect_url'] = ''
		c['authorizationEndpoint'] = ''
		c['tokenizationEndpoint'] = ''
		c['userinfoEndpoint'] = ''
		c['revocationEndpoint'] = ''
		c['introspectionEndpoint'] = ''
		c['responseType'] = ''
		c['scope'] = ''
		c['options'] = ''
		c['supportPkce'] = ''

		pref.setPreference(c)
		o = OPSettings.objects.get(opId=self.opId)
		self.assertEquals(o.displayName, self.displayName)
		self.assertEquals(o.issuer, self.issuer)
		self.assertEquals(o.clientId, '')
		self.assertEquals(o.clientSecret, '')
		self.assertEquals(o.redirect_url, self.redirect_url)
		self.assertEquals(o.authorizationEndpoint, '')
		self.assertEquals(o.tokenizationEndpoint, '')
		self.assertEquals(o.userinfoEndpoint, '')
		self.assertEquals(o.revocationEndpoint, '')
		self.assertEquals(o.introspectionEndpoint, '')
		self.assertEquals(o.responseType, 'code id_token')
		self.assertEquals(o.scope, 'openid')
		self.assertEquals(o.options, '')
		self.assertEquals(o.supportPkce, False)
	
	def test_1_6_3_settPreference_password(self):
		"Setting password on OIDCPreference Model."
		pref = OIDCPreference('pseudoOP')
		c = {}
		c['clientSecret'] = '_clientSecret_'
		pref.setPreference(c)
		c = {}
		c['clientSecret'] = '**********'
		pref.setPreference(c)
		o = OPSettings.objects.get(opId=self.opId)
		self.assertEquals(o.clientSecret, '_clientSecret_')
		
	def test_1_7_getSpecificationAPIBasicConf_configData(self):
		"Getting SpecificationAPI Configuration."
		pref = OIDCPreference('pseudoOP')
		config = pref.getConfigration()
		for k in ['Authz','Token','Refresh','UserInfo','Revocation']:
			c = pref.getSpecificationAPIBasicConf(k)
			self.assertEquals(c['apiEndPoint'], config[keyMap['specAPIs'][k]['configName']])
			self.assertEquals(c['apiName'], keyMap['specAPIs'][k]['apiName'])
			self.assertEquals(c['method'], keyMap['specAPIs'][k]['method'])
			self.assertEquals(c['contentType'], keyMap['specAPIs'][k]['contentType'])
			self.assertEquals(c['authorizationHeader'], keyMap['specAPIs'][k]['authorizationHeader'])
		for k in ['Introspection','Registration']:
			c = pref.getSpecificationAPIBasicConf(k)
			self.assertEquals(c, {})
		
	def test_1_8_getSupportPkce_normal(self):
		"Getting supportPkce from OIDCPreference Model."
		pref = OIDCPreference('pseudoOP')
		self.assertEquals(pref.getSupportPkce(), False)
		

	# Error Case
	
	def test_2_1_Construct_param_error(self):
		"Parameter Error When Constructing OIDCPreference Model."
		with self.assertRaises(Exception):
			pref = OIDCPreference(None)

	def test_3_1_getPreference_invalid_issuer_error(self):
		"Issuer is Invalid (hostname is unknown)."
		o = OPSettings.objects.get(opId=self.opId)
		o.issuer = self.fake_issuer1
		o.save()	
		OPConfigurations.objects.all().delete()
		
		pref = OIDCPreference('pseudoOP')
		with self.assertRaises(ConnectionError):
			c = pref.getPreference()
		
	def test_3_2_getPreference_invalid_issuer_error(self):
		"Issuer is Invalid (URL NotFound)."
		o = OPSettings.objects.get(opId=self.opId)
		o.issuer = self.fake_issuer2
		o.save()	
		OPConfigurations.objects.all().delete()
		
		pref = OIDCPreference('pseudoOP')
		c = pref.getPreference()
		self.assertEquals(c['JWKSet'] , None)
	
	def test_3_3_getAlgSupported_error(self):
		"Issuer is Invalid (URL NotFound), When Getting IdTokenSigningAlgValuesSupported from OIDCPreference Model."
		o = OPSettings.objects.get(opId=self.opId)
		o.issuer = self.fake_issuer2
		o.save()
		OPConfigurations.objects.all().delete()
		pref = OIDCPreference('pseudoOP')
		self.assertEquals(len(pref.getIdTokenSigningAlgValuesSupported()) == 0, True)
	
	def test_3_4_getJWKSet_error(self):
		"Issuer is Invalid (URL NotFound), When Getting JWKSet from OIDCPreference Model."
		o = OPSettings.objects.get(opId=self.opId)
		o.issuer = self.fake_issuer2
		o.save()
		OPConfigurations.objects.all().delete()
		pref = OIDCPreference('pseudoOP')
		self.assertEquals(len(pref.getJWKSet()) == 0, True)
		

		

	
	

	