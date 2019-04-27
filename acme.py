#!/usr/bin/python3
# -*- coding: utf-8 -*-
'''
@date: 2019-04-27
@author: Shell.Xu
@copyright: 2019, Shell.Xu <shell909090@gmail.com>
@license: MIT
'''
import os
import re
import sys
import json
import time
import base64
import pprint
import hashlib
import logging
import argparse
import binascii
from os import path
try:
    from urllib.request import urlopen, Request  # Python 3
except ImportError:
    from urllib2 import urlopen, Request  # Python 2

from cryptography import x509
from cryptography.x509.extensions import _key_identifier_from_public_key
from cryptography.x509.oid import NameOID, ExtensionOID, ExtendedKeyUsageOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives.serialization import \
    Encoding, PrivateFormat, PublicFormat


RETRY_LIMIT = 100
DEFAULT_INTERVAL = 2
DEFAULT_DIRECTORY_URL = 'https://acme-staging-v02.api.letsencrypt.org/directory'
HEADERS = {
    'Content-Type': 'application/jose+json',
    'User-Agent': 'acme-tiny'}
BACKEND = default_backend()
PADALGO = padding.PKCS1v15()
DGSTALGO = hashes.SHA256()


def _b64(b):
    s = base64.urlsafe_b64encode(b)
    return s.decode('utf8').replace('=', '')


def _d64(s):
    s += '=' * (4 - len(s)%4)
    return base64.urlsafe_b64decode(s)


def int2b64(i):
    s = hex(i)[2:]
    if len(s) % 2:
        s = '0' + s
    return _b64(binascii.unhexlify(s))


def b642int(s):
    return int(binascii.hexlify(_d64(s)), 16)


def read_privatekey(pemfile, password=None):
    with open(pemfile, 'rb') as fi:
        bkey = fi.read()
    return serialization.load_pem_private_key(
        bkey, password=password, backend=BACKEND)


class BadNonceError(Exception):
    pass


class WellKnownCheckError(Exception):
    pass


class ChallengeError(Exception):
    pass


class OrderError(Exception):
    pass


def httpget(url, data=None, err_msg='error'):
    logging.info('req: %s', url)
    try:
        req = Request(url, data=data, headers=HEADERS)
        resp = urlopen(req)
        code, headers = resp.getcode(), resp.headers
        logging.debug('resp: %d, headers:\n%s',
                      code, pprint.pformat(dict(headers)))
        respdata = resp.read().decode('utf8')
    except IOError as e:
        respdata = e.read().decode('utf8') if hasattr(e, 'read') else str(e)
        code, headers = getattr(e, 'code', None), {}
    try:
        respdata = json.loads(respdata)  # try to parse json results
        logging.debug('data:\n%s', pprint.pformat(respdata))
    except ValueError:
        pass  # ignore json parsing errors
    if code == 400 and respdata['type'] == 'urn:ietf:params:acme:error:badNonce':
        raise BadNonceError(url)
    if code not in [200, 201, 204]:
        raise ValueError(err_msg)
    return respdata, code, headers


class Account(object):

    alg = 'RS256'

    def __init__(self, directory_url, contact=None):
        logging.info('get directory')
        self.directory, _, _ = httpget(directory_url,
                                       err_msg='get directory error')
        self.contact = contact
        self.kid = None
        self.nonce = None

    def read_pem(self, pemfile, password=None):
        logging.info('load account key from pemfile: %s', pemfile)
        self.pkey = read_privatekey(pemfile, password)
        assert isinstance(self.pkey, rsa.RSAPrivateKey)
        pn = self.pkey.public_key().public_numbers()
        self.jwk = {
            'kty': 'RSA',
            'n': int2b64(pn.n),
            'e': int2b64(pn.e)}
        logging.debug('jwk:\n%s', pprint.pformat(self.jwk))

    def read_json(self, jsonfile):
        logging.info('load account key from jsonfile: %s', jsonfile)
        with open(jsonfile, 'r') as fi:
            jkey = json.loads(fi.read())
        pubkey = rsa.RSAPublicNumbers(b642int(jkey['e']), b642int(jkey['n']))
        prikey = rsa.RSAPrivateNumbers(
            b642int(jkey['p']), b642int(jkey['q']), b642int(jkey['d']),
            b642int(jkey['dp']), b642int(jkey['dq']), b642int(jkey['qi']),
            pubkey)
        self.pkey = prikey.private_key(BACKEND)
        self.jwk = {k: jkey[k] for k in ['kty', 'n', 'e']}
        logging.debug('jwk: %s', pprint.pformat(self.jwk))

    def sign(self, data):
        return self.pkey.sign(data, PADALGO, DGSTALGO)

    def get_nonce(self):  # CAUTION: not thread safe
        if self.nonce is None:
            logging.info('get nonce')
            _, _, headers = httpget(self.directory['newNonce'])
            return headers['Replay-Nonce']
        nonce, self.nonce = self.nonce, None
        return nonce

    def signed_get(self, url, payload, err_msg):
        payload64 = _b64(json.dumps(payload).encode('utf8'))
        protected = {'url': url, 'alg': self.alg}
        if self.kid:
            protected['kid'] = self.kid
        else:
            protected['jwk'] = self.jwk
        for _ in range(RETRY_LIMIT):
            protected['nonce'] = self.get_nonce()
            protected64 = _b64(json.dumps(protected).encode('utf8'))
            protected_input = '{0}.{1}'.format(protected64, payload64).encode('utf8')
            data = json.dumps({
                'protected': protected64,
                'payload': payload64,
                'signature': _b64(self.sign(protected_input)),
            }).encode('utf8')
            try:
                data, code, headers = httpget(url, data=data, err_msg=err_msg)
            except BadNonceError:
                continue
            if 'Replay-Nonce' in headers:
                self.nonce = headers['Replay-Nonce']
            return data, code, headers

    def wait(self, url, statuses, err_msg, interval=DEFAULT_INTERVAL):
        logging.info('waiting for statuses: %s', statuses)
        while True:
            rslt, _, _ = httpget(url, err_msg=err_msg)
            if rslt['status'] not in statuses:
                return rslt
            time.sleep(interval)

    def register(self):
        logging.info('register account')
        reg_payload = {'termsOfServiceAgreed': True}
        account, code, acct_headers = self.signed_get(
            self.directory['newAccount'], reg_payload, 'register error')
        logging.info('registered!' if code == 201 else 'already registered!')
        self.kid = acct_headers['Location']
        if self.contact is not None:
            logging.info('update contact')
            account, _, _ = self.signed_get(
                self.kid, {'contact': self.contact}, 'update contact error')

    def get_thumbprint(self):
        accountkey_json = json.dumps(
            self.jwk, sort_keys=True, separators=(',', ':'))
        return _b64(hashlib.sha256(accountkey_json.encode('utf8')).digest())

    def make_order(self, od):
        logging.info('make order')
        payload = od.gen_order()
        od.order, _, od.headers = self.signed_get(
            self.directory['newOrder'], payload, 'make order error')

    def finalize(self, od):
        logging.debug('pem csr:\n' + od.gen_csr(Encoding.PEM).decode('utf-8'))
        logging.warning('sign cert')
        payload = {'csr': _b64(od.gen_csr())}
        od.order, _, _= self.signed_get(
            od.order['finalize'], payload, 'finalize order error')

        od.order = self.wait(
            od.headers['Location'], {'pending', 'processing'},
            'check order status error')
        if od.order['status'] != 'valid':
            raise OrderError('order failed: %s' % order)
        logging.warning('cert signed.')

    def download_cert(self, od):
        logging.info('download cert.')
        pem, _, _ = httpget(od.order['certificate'],
                            err_msg='certificate download failed')
        return pem


class Order(object):

    def __init__(self, domains, pem_prikey, password=None):
        logging.info('domains: %s', domains)
        self.domains = domains
        logging.info('load domain key from pemfile: %s', pem_prikey)
        self.pkey = read_privatekey(pem_prikey, password)
        self.order = None

    def gen_csr(self, fmt=Encoding.DER):
        name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, self.domains[0]),
            ])
        csr = x509.CertificateSigningRequestBuilder().subject_name(name)
        if len(self.domains) > 1:
            alternative = [x509.DNSName(d.strip()) for d in domains[1:]]
            csr = csr.add_extension(
                x509.SubjectAlternativeName(alternative), critical=False)
        csr = csr.sign(self.pkey, hashes.SHA256(), BACKEND)
        return csr.public_bytes(fmt)

    def gen_order(self):
        return {'identifiers': [{'type': 'dns', 'value': d} for d in self.domains]}


class FileValidator(object):

    re_token = re.compile(r'[^A-Za-z0-9_\-]')

    def __init__(self, acme_path, disable_check):
        self.acme_path = acme_path
        self.disable_check = disable_check

    def check(self, domain, wkpath, token, keyauth):
        logging.info('check wellknown url')
        try:
            wkurl = 'http://{0}/.well-known/acme-challenge/{1}'.format(domain, token)
            data, _, _ = httpget(wkurl)
            if data != keyauth:
                raise WellKnownCheckError()
        except (AssertionError, ValueError) as e:
            raise WellKnownCheckError(
                "couldn't download wellknown file: {}".format(e))
        logging.info('wellknown check passed')

    def auth_domain(self, acct, auth_url):
        logging.info('get challenge')
        auth, _, _ = httpget(auth_url, err_msg='get challenges error')
        domain = auth['identifier']['value']
        logging.warning('verify %s', domain)

        challenge = [c for c in auth['challenges'] if c['type'] == 'http-01'][0]
        token = self.re_token.sub('_', challenge['token'])
        keyauth = '%s.%s' %(token, acct.get_thumbprint())
        wkpath = path.join(self.acme_path, token)
        logging.info('write token to %s', wkpath)
        with open(wkpath, 'w') as fo:
            fo.write(keyauth)

        try:
            if not self.disable_check:
                self.check(domain, wkpath, token, keyauth)

            logging.info('submit challenge')
            acct.signed_get(challenge['url'], {},
                            'submit challenge error: %s' % domain)
            auth = acct.wait(
                auth_url, {'pending',},
                'check challenge status error for %s' % domain)
            if auth['status'] != 'valid':
                raise ChallengeError(
                    'challenge did not pass for {0}: {1}'.format(domain, auth))
            logging.warning('%s verified!', domain)
        finally:
            logging.info('remove wellknown file %s', wkpath)
            os.remove(wkpath)

    def __call__(self, acct, od):
        for auth_url in od.order['authorizations']:
            self.auth_domain(acct, auth_url)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--account-key', '-a',
                        help='path to your account pem key')
    parser.add_argument('--account-json', '-j',
                        help='path to your account json key')
    parser.add_argument('--domain', '-d', action='append',
                        help='domains')
    parser.add_argument('--domain-key', '-k', required=True,
                        help='path to your csr pem key')
    parser.add_argument('--acme-path', '-p', required=True,
                        help='path to the .well-known/acme-challenge/ directory')
    parser.add_argument('--loglevel', '-l', default='WARNING',
                        help='log level (e.g. DEBUG/INFO/WARNING/ERROR)')
    parser.add_argument('--disable-check', default=False, action='store_true',
                        help='disable checking of the challenge file')
    parser.add_argument('--directory-url', '-u', default=DEFAULT_DIRECTORY_URL,
                        help='certificate authority directory url')
    parser.add_argument('--contact', metavar="CONTACT", default=None, nargs="*",
                        help='contact details (e.g. mailto:aaa@bbb.com) for your account-key')

    args = parser.parse_args()
    logging.basicConfig(level=args.loglevel)

    acct = Account(args.directory_url, args.contact)
    od = Order(args.domain, args.domain_key)
    validator = FileValidator(args.acme_path, args.disable_check)

    if args.account_key:
        acct.read_pem(args.account_key)
    elif args.account_json:
        acct.read_json(args.account_json)
    else:
        logging.error('no pem or json file of account')
        return
    acct.register()
    acct.make_order(od)
    validator(acct, od)
    acct.finalize(od)
    pem = acct.download_cert(od)
    sys.stdout.write(pem)


if __name__ == '__main__':
    main()
