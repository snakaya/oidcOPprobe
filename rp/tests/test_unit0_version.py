# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import os
from django.test import TestCase


class VersionTestCase(TestCase):
	
	# Variables
	
	# Initialize / Finalize
	
	@classmethod
	def setUpTestData(cls):
		pass

	def setUp(self):
		pass
	
	def tearDown(self):
		pass
	
	# Normal Case
	
	def test_1_version_number(self):
		"Version Number Test."
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
			raise IOError
		self.assertEquals(ret_ver, '1.0')
	

	