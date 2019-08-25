# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import string
import logging
import datetime
import json
import hashlib
from jose.utils import base64url_encode
from django.conf import settings
from django.test import TestCase, Client
from rp.models import *


class OIDCTokenStoreTestCase(TestCase):
	
	# Variables
	
	opId = 'pseudoOP'
	session = Client().session
	
	authzResponseData_Code = {
		# state, code, authuser, hd, session_state, prompt
		'responseData':'state=yJN6RV208fWrr2mb5fD2GDtgD6aCOZBL&code=4/WAB2raDTNqNUaVtHg0V7e8R7hEGpdl8_QsLVYOr0lpP36tdgHGr5hSVN-xeDqglXny2JCgutdjspC8zJfPHyQ-0&authuser=6&hd=loosedays.jp&session_state=48cb2f5fe7a31cb67556b5ecafc150ec20e26dfb..e3e1&prompt=consent',
		'state':'yJN6RV208fWrr2mb5fD2GDtgD6aCOZBL',
		'code':'4/WAB2raDTNqNUaVtHg0V7e8R7hEGpdl8_QsLVYOr0lpP36tdgHGr5hSVN-xeDqglXny2JCgutdjspC8zJfPHyQ-0',
		'authuser':6,
		'hd':'loosedays.jp',
		'session_state':'48cb2f5fe7a31cb67556b5ecafc150ec20e26dfb..e3e1',
		'prompt':'consent',
	}
	authzResponseData_Hybrid = {
		# state, code, access_token, token_type, expires_in, id_token, authuser, hd, session_state, prompt
		'responseData':'state=qm5fWnuPxdrk1L7I-eNj9puTV_0xHnco&code=4/VgC2uVDkD9TaqxJ_BGumxnXIVm_5S7Zf9aKnIHTn4hiKow9nH0jx4rp9iEuJt2pBgXjn_fYul5jdfB5onGBeCDc&access_token=ya29.GlsUBo5zHVnsfjyKOnBksdr6SHFStTbVyZlEDzNs-xwlI_UVe-gJb3EYWaGDufLbRYLl00h1AHGqZbwsfAgCVnjDoUaHi7wIJOAiOtOVGridgO-nvRbpytf1_O67&token_type=Bearer&expires_in=3600&id_token=eyJhbGciOiJSUzI1NiIsImtpZCI6ImQ5NjQ4ZTAzMmNhYzU4NDI0ZTBkMWE3YzAzMGEzMTk4ZDNmNDZhZGIifQ.eyJhenAiOiI2ODczNzIzNzU0OTgtMGtzZGVxcnBiaTZjODVuaXZvOHBib241OG85NTUxaXAuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiI2ODczNzIzNzU0OTgtMGtzZGVxcnBiaTZjODVuaXZvOHBib241OG85NTUxaXAuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMDExODU1MzMyMzU3NzMzNTk5NDUiLCJoZCI6Imxvb3NlZGF5cy5qcCIsImVtYWlsIjoidXNvbWF0c3VAbG9vc2VkYXlzLmpwIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImF0X2hhc2giOiJOVGdteV9NTTNxdmhodDdDN1ZSb2NBIiwiY19oYXNoIjoiV3VyYTlMQ2RwcXpHU1JCU184OE1ZdyIsIm5vbmNlIjoiMGVobUlRQWw1M0o0Yk1ZdSIsImV4cCI6MTUzNjYwMDE1MiwiaXNzIjoiaHR0cHM6Ly9hY2NvdW50cy5nb29nbGUuY29tIiwianRpIjoiN2I5ZjJjNTIxOTk5YjJiOGI5NGEzYmFhZWYzNDE3NzQ0Yjc3OWM5ZSIsImlhdCI6MTUzNjU5NjU1MiwibmFtZSI6IuadvueUsOiqoCIsInBpY3R1cmUiOiJodHRwczovL2xoMy5nb29nbGV1c2VyY29udGVudC5jb20vLXZ5dExnTlBObGprL0FBQUFBQUFBQUFJL0FBQUFBQUFBQUFBL0FQVUlGYU9MUVZiRjB2NGwzRmpQS2lRZUl4TlRDdDQwa0Evczk2LWMvcGhvdG8uanBnIiwiZ2l2ZW5fbmFtZSI6IuiqoCIsImZhbWlseV9uYW1lIjoi5p2-55SwIiwibG9jYWxlIjoiamEifQ.D_atf6cziTYtgx90mQx1LHWa6mj7G8KxllLgcFXstQuNieZ3DKIQTzFvV2zcd2_smzIe9eLtEnjs0Ix2Hlfiw_pRr2JTyEde4zFisO_z_lwFMP1XARagm8ngvRp3kC2cC-ZDNRpDuSrTDwR6PxGg4cKZmcFxw_3XTyGO6Q63jfTeOP6WKsQfbXMlo6DziUla7Lchmux_hPSCVRseXVj2V3UiQYobfsvRPpDh9RODzrsaVRH-RzeesFfRGLmCDCmB4_OxjOD2CY964rhZ0J7bqAOk-t6Enu5ekQRm1ZFELkugUBdvrJdrUMl0JKd9W-sLErnYZ91P9nYnu0BxjM9mfQ&authuser=6&hd=loosedays.jp&session_state=44b0e7970ef0beb8159f4cc190db9b37c89881f0..4b27&prompt=consent',
		'state':'qm5fWnuPxdrk1L7I-eNj9puTV_0xHnco',
		'code':'4/VgC2uVDkD9TaqxJ_BGumxnXIVm_5S7Zf9aKnIHTn4hiKow9nH0jx4rp9iEuJt2pBgXjn_fYul5jdfB5onGBeCDc',
		'access_token':'ya29.GlsUBo5zHVnsfjyKOnBksdr6SHFStTbVyZlEDzNs-xwlI_UVe-gJb3EYWaGDufLbRYLl00h1AHGqZbwsfAgCVnjDoUaHi7wIJOAiOtOVGridgO-nvRbpytf1_O67',
		'token_type':'Bearer',
		'expires_in':3583,
		'id_token':'eyJhbGciOiJSUzI1NiIsImtpZCI6ImQ5NjQ4ZTAzMmNhYzU4NDI0ZTBkMWE3YzAzMGEzMTk4ZDNmNDZhZGIifQ.eyJhenAiOiI2ODczNzIzNzU0OTgtMGtzZGVxcnBiaTZjODVuaXZvOHBib241OG85NTUxaXAuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiI2ODczNzIzNzU0OTgtMGtzZGVxcnBiaTZjODVuaXZvOHBib241OG85NTUxaXAuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMDExODU1MzMyMzU3NzMzNTk5NDUiLCJoZCI6Imxvb3NlZGF5cy5qcCIsImVtYWlsIjoidXNvbWF0c3VAbG9vc2VkYXlzLmpwIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImF0X2hhc2giOiJOVGdteV9NTTNxdmhodDdDN1ZSb2NBIiwiY19oYXNoIjoiV3VyYTlMQ2RwcXpHU1JCU184OE1ZdyIsIm5vbmNlIjoiMGVobUlRQWw1M0o0Yk1ZdSIsImV4cCI6MTUzNjYwMDE1MiwiaXNzIjoiaHR0cHM6Ly9hY2NvdW50cy5nb29nbGUuY29tIiwianRpIjoiN2I5ZjJjNTIxOTk5YjJiOGI5NGEzYmFhZWYzNDE3NzQ0Yjc3OWM5ZSIsImlhdCI6MTUzNjU5NjU1MiwibmFtZSI6IuadvueUsOiqoCIsInBpY3R1cmUiOiJodHRwczovL2xoMy5nb29nbGV1c2VyY29udGVudC5jb20vLXZ5dExnTlBObGprL0FBQUFBQUFBQUFJL0FBQUFBQUFBQUFBL0FQVUlGYU9MUVZiRjB2NGwzRmpQS2lRZUl4TlRDdDQwa0Evczk2LWMvcGhvdG8uanBnIiwiZ2l2ZW5fbmFtZSI6IuiqoCIsImZhbWlseV9uYW1lIjoi5p2-55SwIiwibG9jYWxlIjoiamEifQ.D_atf6cziTYtgx90mQx1LHWa6mj7G8KxllLgcFXstQuNieZ3DKIQTzFvV2zcd2_smzIe9eLtEnjs0Ix2Hlfiw_pRr2JTyEde4zFisO_z_lwFMP1XARagm8ngvRp3kC2cC-ZDNRpDuSrTDwR6PxGg4cKZmcFxw_3XTyGO6Q63jfTeOP6WKsQfbXMlo6DziUla7Lchmux_hPSCVRseXVj2V3UiQYobfsvRPpDh9RODzrsaVRH-RzeesFfRGLmCDCmB4_OxjOD2CY964rhZ0J7bqAOk-t6Enu5ekQRm1ZFELkugUBdvrJdrUMl0JKd9W-sLErnYZ91P9nYnu0BxjM9mfQ',
		'id_token_decoded':'{"nonce":"0ehmIQAl53J4bMYu","picture":"https://lh3.googleusercontent.com/-vytLgNPNljk/AAAAAAAAAAI/AAAAAAAAAAA/APUIFaOLQVbF0v4l3FjPKiQeIxNTCt40kA/s96-c/photo.jpg","sub":"101185533235773359945","c_hash":"Wura9LCdpqzGSRBS_88MYw","aud":"687372375498-0ksdeqrpbi6c85nivo8pbon58o9551ip.apps.googleusercontent.com","family_name":"松田","iss":"https://accounts.google.com","email_verified":true,"at_hash":"NTgmy_MM3qvhht7C7VRocA","jti":"7b9f2c521999b2b8b94a3baaef3417744b779c9e","given_name":"誠","exp":1536600152,"azp":"687372375498-0ksdeqrpbi6c85nivo8pbon58o9551ip.apps.googleusercontent.com","iat":1536596552,"locale":"ja","email":"usomatsu@loosedays.jp","hd":"loosedays.jp","name":"松田誠"}',
		'authuser':6,
		'hd':'loosedays.jp',
		'session_state':'44b0e7970ef0beb8159f4cc190db9b37c89881f0..4b27',
		'prompt':'consent',
	}
	tokenResponseData = {
		# access_token, id_token, expires_in, token_type, scope, refresh_token
		'responseData':'{"access_token":"ya29.GlsWBtL_ahVKn0UFNgsxUrpAUwWfFqy1tsJlWYThasCRg4jKPh4IslWftBZ2jPXhp-ND6hXrXIRM11lpa1R3fMzX4lTCDI2cFDXse-_pbH3uyl2yRdeVtPfMlihy","id_token":"eyJhbGciOiJSUzI1NiIsImtpZCI6ImQ5NjQ4ZTAzMmNhYzU4NDI0ZTBkMWE3YzAzMGEzMTk4ZDNmNDZhZGIifQ.eyJhenAiOiI2ODczNzIzNzU0OTgtMGtzZGVxcnBiaTZjODVuaXZvOHBib241OG85NTUxaXAuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiI2ODczNzIzNzU0OTgtMGtzZGVxcnBiaTZjODVuaXZvOHBib241OG85NTUxaXAuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMDExODU1MzMyMzU3NzMzNTk5NDUiLCJoZCI6Imxvb3NlZGF5cy5qcCIsImVtYWlsIjoidXNvbWF0c3VAbG9vc2VkYXlzLmpwIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImF0X2hhc2giOiJqY2E0NVpaei05dzllMmZkdjNfVE13Iiwibm9uY2UiOiJKZ0FFamZ4SzB0cWdzaUFqIiwiZXhwIjoxNTM2NzE0MzE4LCJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJpYXQiOjE1MzY3MTA3MTgsIm5hbWUiOiLmnb7nlLDoqqAiLCJwaWN0dXJlIjoiaHR0cHM6Ly9saDMuZ29vZ2xldXNlcmNvbnRlbnQuY29tLy12eXRMZ05QTmxqay9BQUFBQUFBQUFBSS9BQUFBQUFBQUFBQS9BUFVJRmFPTFFWYkYwdjRsM0ZqUEtpUWVJeE5UQ3Q0MGtBL3M5Ni1jL3Bob3RvLmpwZyIsImdpdmVuX25hbWUiOiLoqqAiLCJmYW1pbHlfbmFtZSI6IuadvueUsCIsImxvY2FsZSI6ImphIn0.Senub9rvJ5qluxZIgIkLVHOaMiWP8_G8Kn2uwGwaGMjDGlwH4sNXq8jaStGSHzZN0SsGZa3NqfWMUMQi7go91eF-x51ZoTdsBjHHq5QChF3nU2MZaNS8KRi8G26vKTUZVBgfkx1YzFnLafhdPCDzr8pjGBNpjmZhqX3WX8RB42oL9UwaqrlDNGSu0zVNQMOvhYYaiQ0I-HCXil720hn7F64TuvN3CuIuGCT00RbCxBaBHZiiGf26-iq1FUgmiRMjVYck9YSAOfkL_MRCJj4bQxJ511p302v-CG-PTUU62uCc3ZF1Uw5R5TLxoS7ajWkG2nXHzZhLXdBuT1zRkBECQA","expires_in":3586,"token_type":"Bearer","scope":"https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/plus.me https://www.googleapis.com/auth/userinfo.profile","refresh_token":"1/N5U6Y4XVtz9CAedgM68Ib5mNk_mw31oYRm2lhm6pusc"}',
		'access_token':'ya29.GlsWBtL_ahVKn0UFNgsxUrpAUwWfFqy1tsJlWYThasCRg4jKPh4IslWftBZ2jPXhp-ND6hXrXIRM11lpa1R3fMzX4lTCDI2cFDXse-_pbH3uyl2yRdeVtPfMlihy',
		'id_token':'eyJhbGciOiJSUzI1NiIsImtpZCI6ImQ5NjQ4ZTAzMmNhYzU4NDI0ZTBkMWE3YzAzMGEzMTk4ZDNmNDZhZGIifQ.eyJhenAiOiI2ODczNzIzNzU0OTgtMGtzZGVxcnBiaTZjODVuaXZvOHBib241OG85NTUxaXAuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiI2ODczNzIzNzU0OTgtMGtzZGVxcnBiaTZjODVuaXZvOHBib241OG85NTUxaXAuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMDExODU1MzMyMzU3NzMzNTk5NDUiLCJoZCI6Imxvb3NlZGF5cy5qcCIsImVtYWlsIjoidXNvbWF0c3VAbG9vc2VkYXlzLmpwIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImF0X2hhc2giOiJqY2E0NVpaei05dzllMmZkdjNfVE13Iiwibm9uY2UiOiJKZ0FFamZ4SzB0cWdzaUFqIiwiZXhwIjoxNTM2NzE0MzE4LCJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJpYXQiOjE1MzY3MTA3MTgsIm5hbWUiOiLmnb7nlLDoqqAiLCJwaWN0dXJlIjoiaHR0cHM6Ly9saDMuZ29vZ2xldXNlcmNvbnRlbnQuY29tLy12eXRMZ05QTmxqay9BQUFBQUFBQUFBSS9BQUFBQUFBQUFBQS9BUFVJRmFPTFFWYkYwdjRsM0ZqUEtpUWVJeE5UQ3Q0MGtBL3M5Ni1jL3Bob3RvLmpwZyIsImdpdmVuX25hbWUiOiLoqqAiLCJmYW1pbHlfbmFtZSI6IuadvueUsCIsImxvY2FsZSI6ImphIn0.Senub9rvJ5qluxZIgIkLVHOaMiWP8_G8Kn2uwGwaGMjDGlwH4sNXq8jaStGSHzZN0SsGZa3NqfWMUMQi7go91eF-x51ZoTdsBjHHq5QChF3nU2MZaNS8KRi8G26vKTUZVBgfkx1YzFnLafhdPCDzr8pjGBNpjmZhqX3WX8RB42oL9UwaqrlDNGSu0zVNQMOvhYYaiQ0I-HCXil720hn7F64TuvN3CuIuGCT00RbCxBaBHZiiGf26-iq1FUgmiRMjVYck9YSAOfkL_MRCJj4bQxJ511p302v-CG-PTUU62uCc3ZF1Uw5R5TLxoS7ajWkG2nXHzZhLXdBuT1zRkBECQA',
		'id_token_decoded':'{"nonce":"JgAEjfxK0tqgsiAj","picture":"https://lh3.googleusercontent.com/-vytLgNPNljk/AAAAAAAAAAI/AAAAAAAAAAA/APUIFaOLQVbF0v4l3FjPKiQeIxNTCt40kA/s96-c/photo.jpg","aud":"687372375498-0ksdeqrpbi6c85nivo8pbon58o9551ip.apps.googleusercontent.com","family_name":"松田","iss":"https://accounts.google.com","email_verified":true,"name": "松田誠","at_hash":"jca45ZZz-9w9e2fdv3_TMw","given_name":"誠","exp":1536714318,"azp":"687372375498-0ksdeqrpbi6c85nivo8pbon58o9551ip.apps.googleusercontent.com","iat":1536710718,"locale":"ja","email":"usomatsu@loosedays.jp","hd":"loosedays.jp","sub":"101185533235773359945"}',
		'token_type':'Bearer',
		'expires_in':3586,
		'scope':'https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/plus.me https://www.googleapis.com/auth/userinfo.profile',
		'refresh_token':'1/N5U6Y4XVtz9CAedgM68Ib5mNk_mw31oYRm2lhm6pusc',
	}
	refreshResponseData = {
		# access_token, id_token, expires_in, token_type, scope
		'responseData':'{"access_token":"ya29.GlsYBgg4MMo0FSphTq-7geL9Aa28ur32iA_wPJJl9ifG73E68QmJidsGY7rKiSC_SXCilsq3o-OhgzSHp2kqoo7S802K7VOn4Ob3L-PGg5b2GE78OnqbgJ_8Cew9","id_token":"eyJhbGciOiJSUzI1NiIsImtpZCI6ImQ5NjQ4ZTAzMmNhYzU4NDI0ZTBkMWE3YzAzMGEzMTk4ZDNmNDZhZGIifQ.eyJhenAiOiI2ODczNzIzNzU0OTgtMGtzZGVxcnBiaTZjODVuaXZvOHBib241OG85NTUxaXAuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiI2ODczNzIzNzU0OTgtMGtzZGVxcnBiaTZjODVuaXZvOHBib241OG85NTUxaXAuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMDExODU1MzMyMzU3NzMzNTk5NDUiLCJoZCI6Imxvb3NlZGF5cy5qcCIsImVtYWlsIjoidXNvbWF0c3VAbG9vc2VkYXlzLmpwIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImF0X2hhc2giOiIwMGh4SElaUDZiVGpkQTdNYVVwV1F3IiwiZXhwIjoxNTM2OTA4MDI1LCJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJpYXQiOjE1MzY5MDQ0MjV9.rl1W45E8W5JhBqpKAyQ5crz21yn4NuEr4Ll7hddNLHh8paqC3q-NPbf9KBfa3p_83azcacCAjP8i6bXcVTh_pYB8VdBHJAn-2u0ndQCeheuhQ6KMYGPcawybGBBn5CEuOlXiK_TbcryFkMIsQCqJgFK5LvQHuuRMFaRFaDCMsfKyGsVdrXQoUQq582wKrkTyrG0GGPT02ltZDy37eu-8xXqxbHQwH3_b66-DQALXsum6IZJu2gAoH9zLy4H4uCXMLJqe5G-aBSi6uuOIBS-PxaTojyLq8Nd3ip9NV6DXKIZTwhwCuy0FGJ5tmCRsW7pfM-uRKzdwmt0yWpUZ5ykCNw","expires_in":3586,"token_type":"Bearer","scope":"https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/plus.me https://www.googleapis.com/auth/userinfo.profile","refresh_token":"1/N5U6Y4XVtz9CAedgM68Ib5mNk_mw31oYRm2lhm6pusc"}',
		'access_token':'ya29.GlsYBgg4MMo0FSphTq-7geL9Aa28ur32iA_wPJJl9ifG73E68QmJidsGY7rKiSC_SXCilsq3o-OhgzSHp2kqoo7S802K7VOn4Ob3L-PGg5b2GE78OnqbgJ_8Cew9',
		'id_token':'eyJhbGciOiJSUzI1NiIsImtpZCI6ImQ5NjQ4ZTAzMmNhYzU4NDI0ZTBkMWE3YzAzMGEzMTk4ZDNmNDZhZGIifQ.eyJhenAiOiI2ODczNzIzNzU0OTgtMGtzZGVxcnBiaTZjODVuaXZvOHBib241OG85NTUxaXAuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiI2ODczNzIzNzU0OTgtMGtzZGVxcnBiaTZjODVuaXZvOHBib241OG85NTUxaXAuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMDExODU1MzMyMzU3NzMzNTk5NDUiLCJoZCI6Imxvb3NlZGF5cy5qcCIsImVtYWlsIjoidXNvbWF0c3VAbG9vc2VkYXlzLmpwIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImF0X2hhc2giOiIwMGh4SElaUDZiVGpkQTdNYVVwV1F3IiwiZXhwIjoxNTM2OTA4MDI1LCJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJpYXQiOjE1MzY5MDQ0MjV9.rl1W45E8W5JhBqpKAyQ5crz21yn4NuEr4Ll7hddNLHh8paqC3q-NPbf9KBfa3p_83azcacCAjP8i6bXcVTh_pYB8VdBHJAn-2u0ndQCeheuhQ6KMYGPcawybGBBn5CEuOlXiK_TbcryFkMIsQCqJgFK5LvQHuuRMFaRFaDCMsfKyGsVdrXQoUQq582wKrkTyrG0GGPT02ltZDy37eu-8xXqxbHQwH3_b66-DQALXsum6IZJu2gAoH9zLy4H4uCXMLJqe5G-aBSi6uuOIBS-PxaTojyLq8Nd3ip9NV6DXKIZTwhwCuy0FGJ5tmCRsW7pfM-uRKzdwmt0yWpUZ5ykCNw',
		'id_token_decoded':'{"aud":"687372375498-0ksdeqrpbi6c85nivo8pbon58o9551ip.apps.googleusercontent.com","iss":"https://accounts.google.com","email_verified":true,"at_hash":"00hxHIZP6bTjdA7MaUpWQw","exp":1536908025,"azp":"687372375498-0ksdeqrpbi6c85nivo8pbon58o9551ip.apps.googleusercontent.com","iat":1536904425,"email":"usomatsu@loosedays.jp","hd":"loosedays.jp","sub":"101185533235773359945"}',
		'token_type':'Bearer',
		'expires_in':3600,
		'scope':'https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/plus.me https://www.googleapis.com/auth/userinfo.profile',
	}
	
	
	test_code_verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
	test_code_challenge = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'
	
	# Initialize / Finalize
	
	def setUp(self):
		if settings.OIDC_TOKENSTORE_COOKIENAME + self.opId in self.session:
			del self.session[settings.OIDC_TOKENSTORE_COOKIENAME + self.opId]
		self.session[settings.OIDC_TOKENSTORE_COOKIENAME + self.opId] = {}
		for k,v in self.authzResponseData_Hybrid.items():
			self.session[settings.OIDC_TOKENSTORE_COOKIENAME + self.opId][k] = v
	
	def tearDown(self):
		if settings.OIDC_TOKENSTORE_COOKIENAME + self.opId in self.session:
			del self.session[settings.OIDC_TOKENSTORE_COOKIENAME + self.opId]
	
	# Normal Case
	
	def test_1_1_Construct_initial_normal(self):
		"Initial Construct OIDCTokenStore Model."
		tokenstore = OIDCTokenStore(self.opId, self.session)
		self.assertEquals(settings.OIDC_TOKENSTORE_COOKIENAME + self.opId in self.session, True)
		del self.session[settings.OIDC_TOKENSTORE_COOKIENAME + self.opId]
		tokenstore = OIDCTokenStore(self.opId, self.session)
		self.assertEquals(settings.OIDC_TOKENSTORE_COOKIENAME + self.opId in self.session, True)
		
	def test_1_2_getAuthzResponse_normal(self):
		"Getting AuthzResponse from OIDCTokenStore Model."
		tokenstore = OIDCTokenStore(self.opId, self.session)
		c = tokenstore.getAuthzResponse()
		#self.assertEquals(len(c.keys()), len(self.responseData.keys()))
		for k, v in c.items():
			if k == 'response':
				self.assertEquals('responseData' in self.authzResponseData_Hybrid.keys(), True)
				self.assertEquals(v, self.authzResponseData_Hybrid['responseData'])
			else:
				self.assertEquals(k in self.authzResponseData_Hybrid.keys(), True)
				self.assertEquals(v, self.authzResponseData_Hybrid[k])

	def test_1_3_getTokenResponse_normal(self):
		"Getting TokenResponse from OIDCTokenStore Model."
		for k,v in self.tokenResponseData.items():
			self.session[settings.OIDC_TOKENSTORE_COOKIENAME + self.opId][k] = v
		tokenstore = OIDCTokenStore(self.opId, self.session)
		c = tokenstore.getTokenResponse()
		#self.assertEquals(len(c.keys()), len(self.responseData.keys()))
		for k, v in c.items():
			if k in self.tokenResponseData.keys() and k == 'responseData':
				self.assertEquals(v, self.tokenResponseData['responseData'])
			elif k in self.tokenResponseData.keys() and k != 'responseData':
				self.assertEquals(v, self.tokenResponseData[k])

	def test_1_4_getAccessToken_normal(self):
		"Getting AccessToken from OIDCTokenStore Model."
		tokenstore = OIDCTokenStore(self.opId, self.session)
		at = tokenstore.getAccessToken()
		self.assertEquals(at, self.authzResponseData_Hybrid['access_token'])
		del self.session[settings.OIDC_TOKENSTORE_COOKIENAME + self.opId]['access_token']
		at = tokenstore.getAccessToken()
		self.assertEquals(at, None)
	
	def test_1_5_getRefreshToken_normal(self):
		"Getting RefreshToken from OIDCTokenStore Model."
		for k,v in self.tokenResponseData.items():
			self.session[settings.OIDC_TOKENSTORE_COOKIENAME + self.opId][k] = v
		tokenstore = OIDCTokenStore(self.opId, self.session)
		rt = tokenstore.getRefreshToken()
		self.assertEquals(rt, self.tokenResponseData['refresh_token'])
		del self.session[settings.OIDC_TOKENSTORE_COOKIENAME + self.opId]['refresh_token']
		rt = tokenstore.getRefreshToken()
		self.assertEquals(rt, None)
		
	def test_1_6_state_normal(self):
		"Setting and Verifying state from OIDCTokenStore Model."
		tokenstore = OIDCTokenStore(self.opId, self.session)
		tokenstore.setState('_state_')
		self.assertEquals(self.session[settings.OIDC_TOKENSTORE_COOKIENAME + self.opId]['state'], '_state_')
		self.assertEquals(tokenstore.checkState('_state_'), True)
		
	def test_1_7_1_getCodeVerifier_normal(self):
		"Getting CodeVerifier from OIDCTokenStore Model."
		tokenstore = OIDCTokenStore(self.opId, self.session)
		self.session[settings.OIDC_TOKENSTORE_COOKIENAME + self.opId]['codeVerifier'] = '_codeverifier_'
		self.assertEquals(tokenstore.getCodeVerifier(),'_codeverifier_')
		
	def test_1_7_2_getCodeChallenge_normal(self):
		"Getting CodeChallenge from OIDCTokenStore Model."
		tokenstore = OIDCTokenStore(self.opId, self.session)
		self.session[settings.OIDC_TOKENSTORE_COOKIENAME + self.opId]['codeChallenge'] = '_codechallenge_'
		self.assertEquals(tokenstore.getCodeChallenge(),'_codechallenge_')

	def test_1_7_3_getChallengeMethod_normal(self):
		"Getting ChallengeMethod from OIDCTokenStore Model."
		tokenstore = OIDCTokenStore(self.opId, self.session)
		self.session[settings.OIDC_TOKENSTORE_COOKIENAME + self.opId]['challengeMethod'] = '_challengemethod_'
		self.assertEquals(tokenstore.getChallengeMethod(),'_challengemethod_')
		
	def test_1_7_4_generatePkce_plain_normal(self):
		"Generating Plain CodeChallenge from OIDCTokenStore Model."
		tokenstore = OIDCTokenStore(self.opId, self.session)
		cc = tokenstore.generatePkce('plain')
		self.assertEquals(self.session[settings.OIDC_TOKENSTORE_COOKIENAME + self.opId]['challengeMethod'], 'plain')
		self.assertEquals(self.session[settings.OIDC_TOKENSTORE_COOKIENAME + self.opId]['codeVerifier'], self.session[settings.OIDC_TOKENSTORE_COOKIENAME + self.opId]['codeChallenge'])
		
	def test_1_7_4_generatePkce_s256_normal(self):
		"Generating Plain CodeChallenge from OIDCTokenStore Model."
		tokenstore = OIDCTokenStore(self.opId, self.session)
		cc = tokenstore.generatePkce('S256')
		self.assertEquals(self.session[settings.OIDC_TOKENSTORE_COOKIENAME + self.opId]['challengeMethod'], 'S256')
		try:
			codeChallenge = base64url_encode(hashlib.sha256(self.session[settings.OIDC_TOKENSTORE_COOKIENAME + self.opId]['codeVerifier'].encode()).digest()).decode('utf-8')
			self.assertEquals(self.session[settings.OIDC_TOKENSTORE_COOKIENAME + self.opId]['codeChallenge'], codeChallenge)
		except:
			self.assertEquals(self.session[settings.OIDC_TOKENSTORE_COOKIENAME + self.opId]['codeChallenge'], base64url_encode(hashlib.sha256(self.session[settings.OIDC_TOKENSTORE_COOKIENAME + self.opId]['codeVerifier']).digest()))
		
	def test_1_8_1_setResponse_authzhybrid_normal(self):
		"Setting Response of Authz(Hybrid) on OIDCTokenStore Model."
		del self.session[settings.OIDC_TOKENSTORE_COOKIENAME + self.opId]
		tokenstore = OIDCTokenStore(self.opId, self.session)
		tokenstore.setResponse('Authz', self.authzResponseData_Hybrid['responseData'])
		self.assertEquals(self.session[settings.OIDC_TOKENSTORE_COOKIENAME + self.opId][keyMap['response']['Authz']['sessionName']], self.authzResponseData_Hybrid['responseData'])
		self.assertEquals(self.session[settings.OIDC_TOKENSTORE_COOKIENAME + self.opId]['state'], self.authzResponseData_Hybrid['state'])
		self.assertEquals(self.session[settings.OIDC_TOKENSTORE_COOKIENAME + self.opId]['code'], self.authzResponseData_Hybrid['code'])
		self.assertEquals(self.session[settings.OIDC_TOKENSTORE_COOKIENAME + self.opId]['id_token'], self.authzResponseData_Hybrid['id_token'])
		self.assertEquals(json.loads(self.session[settings.OIDC_TOKENSTORE_COOKIENAME + self.opId]['id_token_decoded']) == json.loads(self.authzResponseData_Hybrid['id_token_decoded']), True)
		self.assertEquals(self.session[settings.OIDC_TOKENSTORE_COOKIENAME + self.opId]['access_token'], self.authzResponseData_Hybrid['access_token'])
		# TODO: How test now()?
		#self.assertEquals(self.session[settings.OIDC_TOKENSTORE_COOKIENAME + self.opId]['expireDate'], '2018-09-10 16:02:29 UTC')
		self.assertEquals('expireDate' in self.session[settings.OIDC_TOKENSTORE_COOKIENAME + self.opId], True)
		self.assertEquals(self.session[settings.OIDC_TOKENSTORE_COOKIENAME + self.opId]['id_token_expireDate'], '2018-09-10 17:22:32 UTC')
		self.assertEquals('authuser' not in self.session[settings.OIDC_TOKENSTORE_COOKIENAME + self.opId], True)
		self.assertEquals('hd' not in self.session[settings.OIDC_TOKENSTORE_COOKIENAME + self.opId], True)
		self.assertEquals('session_state' not in self.session[settings.OIDC_TOKENSTORE_COOKIENAME + self.opId], True)
		self.assertEquals('prompt' not in self.session[settings.OIDC_TOKENSTORE_COOKIENAME + self.opId], True)
		
	def test_1_8_2_setResponse_authzhybrid_authzcode_normal(self):
		"Setting Response of Authz(Hybrid) and Authz(Code) on OIDCTokenStore Model."
		del self.session[settings.OIDC_TOKENSTORE_COOKIENAME + self.opId]
		tokenstore = OIDCTokenStore(self.opId, self.session)
		tokenstore.setResponse('Authz', self.authzResponseData_Hybrid['responseData'])
		tokenstore.setResponse('Authz', self.authzResponseData_Code['responseData'])
		self.assertEquals(self.session[settings.OIDC_TOKENSTORE_COOKIENAME + self.opId][keyMap['response']['Authz']['sessionName']], self.authzResponseData_Code['responseData'])
		self.assertEquals(self.session[settings.OIDC_TOKENSTORE_COOKIENAME + self.opId]['state'], self.authzResponseData_Code['state'])
		self.assertEquals(self.session[settings.OIDC_TOKENSTORE_COOKIENAME + self.opId]['code'], self.authzResponseData_Code['code'])
		self.assertEquals('id_token' not in self.session[settings.OIDC_TOKENSTORE_COOKIENAME + self.opId], True)
		self.assertEquals('id_token_decoded' not in self.session[settings.OIDC_TOKENSTORE_COOKIENAME + self.opId], True)
		self.assertEquals('access_token' not in self.session[settings.OIDC_TOKENSTORE_COOKIENAME + self.opId], True)
		self.assertEquals('expireDate' not in self.session[settings.OIDC_TOKENSTORE_COOKIENAME + self.opId], True)
		self.assertEquals('authuser' not in self.session[settings.OIDC_TOKENSTORE_COOKIENAME + self.opId], True)
		self.assertEquals('hd' not in self.session[settings.OIDC_TOKENSTORE_COOKIENAME + self.opId], True)
		self.assertEquals('session_state' not in self.session[settings.OIDC_TOKENSTORE_COOKIENAME + self.opId], True)
		self.assertEquals('prompt' not in self.session[settings.OIDC_TOKENSTORE_COOKIENAME + self.opId], True)
	
	def test_1_8_3_setResponse_authzhybrid_token_normal(self):
		"Setting Response of Authz(Hybrid) and Token on OIDCTokenStore Model."
		del self.session[settings.OIDC_TOKENSTORE_COOKIENAME + self.opId]
		tokenstore = OIDCTokenStore(self.opId, self.session)
		tokenstore.setResponse('Authz', self.authzResponseData_Hybrid['responseData'])
		tokenstore.setResponse('Token', self.tokenResponseData['responseData'])
		self.assertEquals(self.session[settings.OIDC_TOKENSTORE_COOKIENAME + self.opId][keyMap['response']['Authz']['sessionName']], self.authzResponseData_Hybrid['responseData'])
		self.assertEquals(self.session[settings.OIDC_TOKENSTORE_COOKIENAME + self.opId][keyMap['response']['Token']['sessionName']], self.tokenResponseData['responseData'])
		self.assertEquals(self.session[settings.OIDC_TOKENSTORE_COOKIENAME + self.opId]['state'], self.authzResponseData_Hybrid['state'])
		self.assertEquals(self.session[settings.OIDC_TOKENSTORE_COOKIENAME + self.opId]['code'], self.authzResponseData_Hybrid['code'])
		self.assertEquals(self.session[settings.OIDC_TOKENSTORE_COOKIENAME + self.opId]['id_token'], self.tokenResponseData['id_token'])
		self.assertEquals(json.loads(self.session[settings.OIDC_TOKENSTORE_COOKIENAME + self.opId]['id_token_decoded']) == json.loads(self.tokenResponseData['id_token_decoded']), True)
		self.assertEquals(self.session[settings.OIDC_TOKENSTORE_COOKIENAME + self.opId]['access_token'], self.tokenResponseData['access_token'])
		self.assertEquals(self.session[settings.OIDC_TOKENSTORE_COOKIENAME + self.opId]['refresh_token'], self.tokenResponseData['refresh_token'])
		# TODO: How test now()?
		#self.assertEquals(self.session[settings.OIDC_TOKENSTORE_COOKIENAME + self.opId]['expireDate'], '2018-09-12 01:22:40 UTC')
		self.assertEquals('expireDate' in self.session[settings.OIDC_TOKENSTORE_COOKIENAME + self.opId], True)
		self.assertEquals(self.session[settings.OIDC_TOKENSTORE_COOKIENAME + self.opId]['id_token_expireDate'], '2018-09-12 01:05:18 UTC')
		self.assertEquals('authuser' not in self.session[settings.OIDC_TOKENSTORE_COOKIENAME + self.opId], True)
		self.assertEquals('hd' not in self.session[settings.OIDC_TOKENSTORE_COOKIENAME + self.opId], True)
		self.assertEquals('session_state' not in self.session[settings.OIDC_TOKENSTORE_COOKIENAME + self.opId], True)
		self.assertEquals('prompt' not in self.session[settings.OIDC_TOKENSTORE_COOKIENAME + self.opId], True)
		
	def test_1_8_4_setResponse_authzhybrid_token_refresh_normal(self):
		"Setting Response of Authz(Hybrid) and Token and Refresh on OIDCTokenStore Model."
		del self.session[settings.OIDC_TOKENSTORE_COOKIENAME + self.opId]
		tokenstore = OIDCTokenStore(self.opId, self.session)
		tokenstore.setResponse('Authz', self.authzResponseData_Hybrid['responseData'])
		tokenstore.setResponse('Token', self.tokenResponseData['responseData'])
		tokenstore.setResponse('Refresh', self.refreshResponseData['responseData'])
		self.assertEquals(self.session[settings.OIDC_TOKENSTORE_COOKIENAME + self.opId][keyMap['response']['Authz']['sessionName']], self.authzResponseData_Hybrid['responseData'])
		self.assertEquals(self.session[settings.OIDC_TOKENSTORE_COOKIENAME + self.opId][keyMap['response']['Token']['sessionName']], self.tokenResponseData['responseData'])
		self.assertEquals(self.session[settings.OIDC_TOKENSTORE_COOKIENAME + self.opId][keyMap['response']['Refresh']['sessionName']], self.refreshResponseData['responseData'])
		self.assertEquals(self.session[settings.OIDC_TOKENSTORE_COOKIENAME + self.opId]['state'], self.authzResponseData_Hybrid['state'])
		self.assertEquals(self.session[settings.OIDC_TOKENSTORE_COOKIENAME + self.opId]['code'], self.authzResponseData_Hybrid['code'])
		self.assertEquals(self.session[settings.OIDC_TOKENSTORE_COOKIENAME + self.opId]['id_token'], self.refreshResponseData['id_token'])
		self.assertEquals(json.loads(self.session[settings.OIDC_TOKENSTORE_COOKIENAME + self.opId]['id_token_decoded']) == json.loads(self.refreshResponseData['id_token_decoded']), True)
		self.assertEquals(self.session[settings.OIDC_TOKENSTORE_COOKIENAME + self.opId]['access_token'], self.refreshResponseData['access_token'])
		self.assertEquals(self.session[settings.OIDC_TOKENSTORE_COOKIENAME + self.opId]['refresh_token'], self.tokenResponseData['refresh_token'])
		# TODO: How test now()?
		#self.assertEquals(self.session[settings.OIDC_TOKENSTORE_COOKIENAME + self.opId]['expireDate'], '2018-09-14 06:53:45 UTC')
		self.assertEquals('expireDate' in self.session[settings.OIDC_TOKENSTORE_COOKIENAME + self.opId], True)
		self.assertEquals(self.session[settings.OIDC_TOKENSTORE_COOKIENAME + self.opId]['id_token_expireDate'], '2018-09-14 06:53:45 UTC')
		self.assertEquals('authuser' not in self.session[settings.OIDC_TOKENSTORE_COOKIENAME + self.opId], True)
		self.assertEquals('hd' not in self.session[settings.OIDC_TOKENSTORE_COOKIENAME + self.opId], True)
		self.assertEquals('session_state' not in self.session[settings.OIDC_TOKENSTORE_COOKIENAME + self.opId], True)
		self.assertEquals('prompt' not in self.session[settings.OIDC_TOKENSTORE_COOKIENAME + self.opId], True)
	
	
	
	
		

	# Error Case
	
	def test_2_1_Construct_param_error(self):
		"Parameter Error When Constructing OIDCTokenStore Model."
		with self.assertRaises(ParamError):
			tokenstore = OIDCTokenStore(None, self.session)
		with self.assertRaises(ParamError):
			tokenstore = OIDCTokenStore(self.opId, None)
		with self.assertRaises(TypeError):
			tokenstore = OIDCTokenStore(self.opId)

	def test_2_2_state_error(self):
		"Verifying Error of state."
		tokenstore = OIDCTokenStore(self.opId, self.session)
		tokenstore.setState('_state_')
		self.assertEquals(tokenstore.checkState('_XXXXX_'), False)
		del self.session[settings.OIDC_TOKENSTORE_COOKIENAME + self.opId]['state']
		self.assertEquals(tokenstore.checkState('_state_'), False)

	def test_2_3_1_getCodeVerifier_error(self):
		"Getting Error CodeVerifier."
		tokenstore = OIDCTokenStore(self.opId, self.session)
		self.assertEquals(tokenstore.getCodeVerifier() is None, True)
		
	def test_2_3_2_getCodeChallenge_error(self):
		"Getting Error CodeChallenge."
		tokenstore = OIDCTokenStore(self.opId, self.session)
		self.assertEquals(tokenstore.getCodeChallenge() is None, True)

	def test_2_3_3_getChallengeMethod_error(self):
		"Getting Error ChallengeMethod."
		tokenstore = OIDCTokenStore(self.opId, self.session)
		self.assertEquals(tokenstore.getChallengeMethod() is None, True)

	def test_2_4_1_generatePkce_error(self):
		"Param Error on generatePkce."
		tokenstore = OIDCTokenStore(self.opId, self.session)
		with self.assertRaises(ParamError):
			cc = tokenstore.generatePkce('XXX')







