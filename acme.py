#!/usr/bin/python3
# -*- coding: utf-8 -*-
'''
@date: 2019-04-27
@author: Shell.Xu
@copyright: 2019, Shell.Xu <shell909090@gmail.com>
@license: MIT
'''
import os
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


class ValidateError(Exception):
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
    except (ValueError, TypeError):
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
        try:
            pkey = read_privatekey(pemfile, password)
        except ValueError:
            return
        logging.info('load account key from pemfile: %s', pemfile)
        if not isinstance(pkey, rsa.RSAPrivateKey):
            raise ValueError('only support rsa key')
        pn = pkey.public_key().public_numbers()
        return pkey, {'kty': 'RSA', 'n': int2b64(pn.n), 'e': int2b64(pn.e)}

    def read_json(self, jsonfile):
        with open(jsonfile, 'r') as fi:
            data = fi.read()
        try:
            jkey = json.loads(data)
        except ValueError:
            return
        logging.info('load account key from jsonfile: %s', jsonfile)
        return self.load_json(jkey)

    def load_json(self, jkey):
        pubkey = rsa.RSAPublicNumbers(b642int(jkey['e']), b642int(jkey['n']))
        prikey = rsa.RSAPrivateNumbers(
            b642int(jkey['p']), b642int(jkey['q']), b642int(jkey['d']),
            b642int(jkey['dp']), b642int(jkey['dq']), b642int(jkey['qi']),
            pubkey)
        pkey = prikey.private_key(BACKEND)
        return pkey, {k: jkey[k] for k in ['kty', 'n', 'e']}

    def load_key(self, key):
        self.pkey, self.jwk = self.load_json(key)
        logging.debug('jwk: %s', pprint.pformat(self.jwk))

    def read_key(self, keyfile):
        if not path.isfile(keyfile):
            raise ValueError('%s not exist or not a file' % keyfile)
        for f in [self.read_pem, self.read_json]:
            r = f(keyfile)
            if r:
                self.pkey, self.jwk = r
                break
        else:
            raise ValueError("can't identity key file format")
        logging.debug('jwk: %s', pprint.pformat(self.jwk))

    def sign(self, data):
        return self.pkey.sign(data, PADALGO, DGSTALGO)

    def get_thumbprint(self):
        accountkey_json = json.dumps(
            self.jwk, sort_keys=True, separators=(',', ':'))
        return _b64(hashlib.sha256(accountkey_json.encode('utf8')).digest())

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
        if self.contact:
            logging.info('update contact')
            account, _, _ = self.signed_get(
                self.kid, {'contact': self.contact}, 'update contact error')

    def make_order(self, domain, pem_prikey, password=None):
        logging.info('make order')
        od = Order(self, domain, pem_prikey, password)
        payload = od.gen_order()
        od.order, _, od.headers = self.signed_get(
            self.directory['newOrder'], payload, 'make order error')
        return od


class Order(object):

    def __init__(self, acct, domains, pem_prikey, password=None):
        self.acct = acct
        logging.info('domains: %s', domains)
        self.domains = domains
        logging.info('load domain key from pemfile: %s', pem_prikey)
        self.pkey = read_privatekey(pem_prikey, password)
        self.order, self.header = None, None

    def gen_order(self):
        return {'identifiers': [{'type': 'dns', 'value': d} for d in self.domains]}

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

    def finalize(self):
        logging.debug('pem csr:\n' + self.gen_csr(Encoding.PEM).decode('utf-8'))
        logging.warning('sign cert')
        payload = {'csr': _b64(self.gen_csr())}
        self.order, _, _= self.acct.signed_get(
            self.order['finalize'], payload, 'finalize order error')
        self.order = self.acct.wait(
            self.headers['Location'], {'pending', 'processing'},
            'check order status error')
        if self.order['status'] != 'valid':
            raise OrderError('order failed: %s' % order)
        logging.warning('cert signed.')

    def download_cert(self):
        logging.info('download cert.')
        pem, _, _ = httpget(self.order['certificate'],
                            err_msg='certificate download failed')
        return pem
        

def read_config_ini(configpath):
    try:
        import configparser
        cp = configparser.ConfigParser()
    except ImportError:
        import ConfigParser as configparser
        cp = configparser.SafeConfigParser()
    try:
        cp.read(configpath)
    except configparser.MissingSectionHeaderError:
        return
    cfg = dict(cp['main'])
    if 'domains' in cfg:
        cfg['domain'] = cfg.pop('domains').split(',')
    if 'contacts' in cfg:
        cfg['contact'] = cfg.pop('contacts').split(',')
    for n in cp.sections():
        if n == 'main':
            continue
        v = dict(cp[n])
        v['name'] = n
        cfg.setdefault('validator', []).append(v)
    return cfg


def read_config_jsonyaml(configpath):
    with open(configpath, 'rb') as fi:
        data = fi.read()
    try:
        return json.loads(data)
    except (ValueError, TypeError):
        pass
    try:
        import yaml
        return yaml.safe_load(data)
    except ValueError:
        pass


def read_config():
    parser = argparse.ArgumentParser()
    parser.add_argument('--account-key', '-a',
                        help='path to your account pem key')
    parser.add_argument('--config', '-c',
                        help='path to config file')
    parser.add_argument('--domain', '-d', action='append',
                        help='domains')
    parser.add_argument('--domain-key', '-k',
                        help='path to your csr pem key')
    parser.add_argument('--acme-path', '-p',
                        help='path to the .well-known/acme-challenge/ directory')
    parser.add_argument('--loglevel', '-l',
                        help='log level (e.g. DEBUG/INFO/WARNING/ERROR)')
    parser.add_argument('--logfile', '-f',
                        help='log file')
    parser.add_argument('--nocheck', default=False, action='store_true',
                        help='disable checking of the challenge file')
    parser.add_argument('--directory-url', '-u',
                        help='certificate authority directory url')
    parser.add_argument('--contact', action='append',
                        help='contact details (e.g. mailto:aaa@bbb.com)')
    args = parser.parse_args()

    if args.config:
        cfg = read_config_ini(args.config)
        if not cfg:
            cfg = read_config_jsonyaml(args.config)
    else:
        cfg = {}

    for n in ['account_key', 'domain', 'domain_key',
              'loglevel', 'logfile', 'directory_url']:
        if getattr(args, n):
            cfg[n.replace('_', '-')] = getattr(args, n)
    if args.acme_path:
        v = {
            'name': 'file',
            'path': args.acme_path,
            'nocheck': args.nocheck}
        cfg.setdefault('validator', []).append(v)

    cfg.setdefault('loglevel', 'WARNING')
    cfg.setdefault('directory-url', DEFAULT_DIRECTORY_URL)

    for n in ['account-key', 'domain', 'domain-key', 'validator']:
        if not cfg.get(n):
            raise ValueError('no %s' % n)
    return cfg


def main():
    cfg = read_config()

    logging.basicConfig(level=cfg['loglevel'], filename=cfg.get('logfile', None))
    logging.debug('config:\n%s', pprint.pformat(cfg))

    acct = Account(cfg['directory-url'], cfg['contact'])
    if isinstance(cfg['account-key'], str):
        acct.read_key(cfg['account-key'])
    else:
        acct.load_key(cfg['account-key'])
    
    validators = []
    for v in cfg['validator']:
        mod = __import__(v.pop('name'))
        validators.append(mod.Validator(**v))

    acct.register()
    od = acct.make_order(cfg['domain'], cfg['domain-key'])
    for validator in validators:
        try:
            validator(od)
            break
        except Exception as e:
            logging.error(e)
    else:
        raise ValidateError('no validator works')
    od.finalize()
    sys.stdout.write(od.download_cert())


if __name__ == '__main__':
    main()
