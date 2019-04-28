#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
@date: 2019-04-28
@author: Shell.Xu
@copyright: 2019, Shell.Xu <shell909090@gmail.com>
@license: MIT
'''
from __future__ import absolute_import, division,\
    print_function, unicode_literals
import os
import re
import logging
from os import path

import acme


class Validator(object):

    re_token = re.compile(r'[^A-Za-z0-9_\-]')

    def __init__(self, path, nocheck=True):
        self.acme_path = path
        self.nocheck = nocheck

    def check(self, domain, wkpath, token, keyauth):
        logging.info('check wellknown url')
        try:
            wkurl = 'http://{0}/.well-known/acme-challenge/{1}'.format(domain, token)
            data, _, _ = acme.httpget(wkurl)
            if data != keyauth:
                raise acme.WellKnownCheckError()
        except (AssertionError, ValueError) as e:
            raise acme.WellKnownCheckError(
                "couldn't download wellknown file: {}".format(e))
        logging.info('wellknown check passed')

    def auth_domain(self, od, auth_url):
        logging.info('get challenge')
        auth, _, _ = acme.httpget(auth_url, err_msg='get challenges error')
        domain = auth['identifier']['value']
        logging.warning('verify %s', domain)

        challenge = [c for c in auth['challenges'] if c['type'] == 'http-01'][0]
        token = self.re_token.sub('_', challenge['token'])
        keyauth = '%s.%s' %(token, od.acct.get_thumbprint())
        wkpath = path.join(self.acme_path, token)
        logging.info('write token to %s', wkpath)
        with open(wkpath, 'w') as fo:
            fo.write(keyauth)

        try:
            if not self.nocheck:
                self.check(domain, wkpath, token, keyauth)

            logging.info('submit challenge')
            od.acct.signed_get(challenge['url'], {},
                               'submit challenge error: %s' % domain)
            auth = od.acct.wait(
                auth_url, {'pending',},
                'check challenge status error for %s' % domain)
            if auth['status'] != 'valid':
                raise acme.ChallengeError(
                    'challenge did not pass for {0}: {1}'.format(domain, auth))
            logging.warning('%s verified!', domain)
        finally:
            logging.info('remove wellknown file %s', wkpath)
            os.remove(wkpath)

    def __call__(self, od):
        for auth_url in od.order['authorizations']:
            self.auth_domain(od, auth_url)
