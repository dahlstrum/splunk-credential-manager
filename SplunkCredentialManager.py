import PAMManager
import requests
import logging
import yaml
import sys
import os
import argparse
import subprocess
from enum import Enum
from xml.dom.minidom import parse, parseString
import xml.etree.ElementTree as ET

from typing import TextIO

# default splunk settings
splunk_port = 8089

# create logging objects
logging.getLogger('PAMManager').setLevel(logging.INFO)
logger = logging.getLogger(__name__)
handler = logging.FileHandler('SplunkCredentialManager.log')
stream_handler = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')

# set default logging levels for handlers
logger.setLevel(logging.INFO)
handler.setLevel(logging.INFO)
stream_handler.setLevel(logging.INFO)

# set handler formatting
handler.setFormatter(formatter)
stream_handler.setFormatter(formatter)

# add handlers to logger
logger.addHandler(handler)
logger.addHandler(stream_handler)


class SplunkCredentialManager:
    class SplunkCredentialType(Enum):
        PASSWORDS_CONF = 1
        LOCAL          = 2
        CUSTOM_API     = 3
        DIRECT         = 4

    def authenticate(self, hostname: str, username: str, password: str, verify: str=False) -> str:
        """ authenticate to hostname usering username:password, cache it and return a session key

        Positional Arguments:
        hostname -- the hostname of the destination server you're connecting to
        username -- the username to be used for authentication
        password -- the password of the authenticating account

        Keyword Arguments:
        verify   -- either the file location of root cert used to validate the connection, or false
        """

        # splunk api settings
        splunk_service = 'services'
        splunk_endpoint = '/auth/login'

        # check cache first
        if self._session_keys.get(hostname, None):
            return self._session_keys[hostname]

        logger.debug(f"Generating session token from {hostname} using {username}")

        # get session token from Splunk
        auth_url = f"https://{hostname}:{splunk_port}/{splunk_service}{splunk_endpoint}"
        auth_response = requests.get(auth_url,
                                     data={'username':username, 'password':password},
                                     verify=verify)

        session_key = parseString(auth_response.text).getElementsByTagName('sessionKey')[0].firstChild.nodeValue
        self._session_keys[hostname] = session_key

        return session_key

    def _get_session(self, hostname: str) -> str:
        """ retrieve session key stored in cache by using hostname as a key """
        return self._session_keys.get(hostname, None)

    def __init__(self, cert=None, key=None, keypass=None, rootca=None):
        """ constructor for SplunkCredentialManager object. cert settings can be specified using keyword arguments. """
        self._session_keys = {}
        self._cert_conf = {}
        self._cert_conf['cert'] = cert
        self._cert_conf['key'] = key
        self._cert_conf['keypass'] = keypass
        self._cert_conf['rootca'] = rootca

    def update_credential_passwordsconf(self, hostname: str, username: str, new_password: str, app: str, realm: str ='', extra=None):
        """ Update Splunk credential stored in a passwords.conf file by leveraging Splunks API
        Positional Arguments:
        hostname     -- the host where the credential is stored
        username     -- the username of the stored credential
        new_password -- the new password for the stored credential
        app          -- the Splunk app where the credential is stored

        Keyword Arguments:
        realm        -- the Splunk realm to set the credential under (it's a passwords.conf thing)
        """
        logger.debug(f"Update u:{username} passwordsconf via api on h:{hostname} in {app}")
        headers = {}
        data = {}
        splunk_endpoint = '/storage/passwords'
        request_url = f'https://{hostname}:{splunk_port}/servicesNS/nobody/{app}{splunk_endpoint}'
        full_url = f'{request_url}/{realm}:{username}:'
        #full_url = f'{request_url}/'

        session_key = self._get_session(hostname)
        if not session_key:
            logger.error("Session key for h:{hostname} not found in cache. Please authenticate to h:{hostname} to generate session key first")
        else:
            headers['Authorization'] = f'Splunk {session_key}'

        data['password'] = new_password
        #data['name'] = username
        #data['realm'] = realm

        pw_object = None
        get_pass = requests.request("GET", full_url, headers=headers, verify=self._cert_conf.get('rootca',False))
        if get_pass.status_code != 200:
            if get_pass.status_code == 404:
                # if the account doesnt exist, the endpoint and body requirements change
                logger.info(f"Account {username} not found on h:{hostname}")
                full_url = f'{request_url}'
                data['name'] = username
                data['realm'] = realm

            logger.debug(f"Request to h:{full_url} resulted in {get_pass.status_code} response")
        else:
            # fetch password field in XML response using XPath expression
            get_pass_xml = ET.fromstring(get_pass.content)
            pw_object = get_pass_xml.find(".//*[@name='clear_password']")

        if pw_object == None:
            logger.warning(f'No password found in XML response. Assuming account doesn\'t exist on h:{hostname}')

            # creates anonymous object with 1 attribute named text
            pw_object = type('',(object,),{"text":""})()

        response = None
        current_api_pw = pw_object.text
        if current_api_pw == new_password:
            logger.debug(f"Password update for u:{username} on h:{hostname} not needed. Skipping.")
        else:
            logger.info(f"Updating password for u:{username} on h:{hostname} via api (passwords.conf)")
            response = requests.request("POST", full_url, headers=headers, data=data, verify=self._cert_conf.get('rootca',False))

        return response

    def update_credential_localaccount(self, hostname:str , username: str, password:str, app: str, realm: str='', extra=None):
        """ TODO: write way to update local user account on remote Splunk host"""
        raise NotImplementedError()

    def update_credential_direct(self, hostname:str , username: str, password:str, app: str, realm: str='', extra=None):
        """ TODO: write way to update passwords directly in conf files """
        raise NotImplementedError()

    def update_credential_customapi(self, hostname, username, password, app, realm='', extra=None):
        logger.debug(f"Update u:{username} passwordsconf via api on h:{hostname} in {app} using custom_api integration")

        headers = {}
        data = {}
        api = extra.get('api', {})
        if not api:
            logger.error("missing api definition in configuration files")
            raise KeyError
        elif not (api.get('endpoint',None) and  api.get('field',None) and api.get('encrypt',None) and api.get('stanza',None)):
            logger.error("missing one or more settings in api configuration: endpoint, field, encrypt, stanza")
            raise KeyError

        # get session key for splunk api calls
        session_key = self._get_session(hostname)
        if not session_key:
            logger.error(f"Session key for h:{hostname} not found in cache. Please authenticate to h:{hostname} to generate session key first")
        else:
            headers['Authorization'] = f'Splunk {session_key}'
        splunk_endpoint = api.get('endpoint')

        # build urls for splunk api calls
        request_url = f'https://{hostname}:{splunk_port}/{splunk_endpoint}'
        full_url = f'{request_url}/{api.get("stanza")}'

        # run commands to fetch and compare current pw
        curr_pw_response = requests.request("GET",full_url,headers=headers,verify=self._cert_conf.get('rootca',False))
        get_pass_xml = ET.fromstring(curr_pw_response.content)
        xpath_exp = ".//*[@name='{}']".format(api.get('field'))
        pw_object = get_pass_xml.find(xpath_exp)
        curr_enc_password = None
        if pw_object == None:
            logger.error(f"custom api config item {api.get('field')} cannot be found in xml response")
            raise RuntimeError(f"custom api config item {api.get('field')} cannot be found in xml response")
        elif not pw_object.text:
            logger.error(f"Retrieved {api.get('field')} field value was empty in xml response. Exiting.")
            raise RuntimeError(f"Retrieved {api.get('field')} field value was empty in xml response. Exiting.")
        else:
            curr_enc_password = pw_object.text

        # decrypt current field from api
        # This command is exposed in process table and can be read by other views. Be aware of what you run in subprocess.
        splunk_proc = subprocess.run(["/opt/splunk/bin/splunk", "show-decrypted", "--value", curr_enc_password], stderr=subprocess.DEVNULL, stdout=subprocess.PIPE)
        curr_dec_password = splunk_proc.stdout.decode('utf-8').replace('\n','')

        if ((curr_dec_password == password) and (extra.get('force', False) != True)):
            logger.debug(f"Password update for u:{username} on h:{hostname} at {full_url} not needed. Skipping.")
            return None

        new_password = password
        if api.get('encrypt'):
            pw_create_url = f'https://{hostname}:{splunk_port}/servicesNS/nobody/search/storage/passwords'
            enc_cred_data = {}
            enc_cred_data['name'] = api.get('field')
            enc_cred_data['password'] = password
            enc_cred_data['realm'] = 'encdec'
            pw_response = requests.request("POST",
                                           pw_create_url,
                                           headers=headers,
                                           data=enc_cred_data,
                                           verify=self._cert_conf.get('rootca',False))
            get_pass_xml = ET.fromstring(pw_response.content)
            pw_object = get_pass_xml.find(".//*[@name='encr_password']")
            pw_response = requests.request("DELETE",
                                           f'{pw_create_url}/{enc_cred_data["realm"]}:{enc_cred_data["name"]}:',
                                           headers=headers,
                                           verify=self._cert_conf.get('rootca',False))
            if pw_object == None:
                logger.error("No password found in XML response")
                raise RuntimeError("No password found in XML response")
            elif not pw_object.text:
                logger.error("Empty password field returned from splunk api call")
                raise RuntimeError("Empty password field returned from splunk api call")
            elif not pw_object.text.startswith('$'):
                logger.error("Password string retrieved from the api is in clear text. Stopping script to avoid unintentional exposure.")
                raise RuntimeError("Empty password field returned from splunk api call")
            else:
                new_password = pw_object.text

        data[api.get('field')] = new_password

        response = None
        # update api / field endpoint with new password
        logger.info(f"Updating password for u:{username} on h:{hostname} at {full_url} in field {api.get('field')} (custom_api)")
        response = requests.request("POST", full_url, headers=headers, data=data, verify=self._cert_conf.get('rootca',False))

        # attempt to reload the config of the api
        reload_url = f"https://{hostname}:{splunk_port}{api.get('reload',None)}" or f'{request_url}/_reload'
        logger.debug(f"Attempting to reload configuration at this endpoint: {reload_url}")
        response = requests.request("GET", reload_url, headers=headers, verify=self._cert_conf.get('rootca',False))

        return response

    def update_credential(self,splunk_credential_type: SplunkCredentialType, hostname: str, username: str, password: str, app: str, realm: str='', extra=None):
        """ Method used to route to proper credential updating functionality based on type
        Positional Arguments:
        splunk_credential_type -- The type of Splunk credential to update:
                               -- choices are:
                               --    SplunkCredentialManager.SplunkCredentialType.PASSWORDS_CONF
                               --    SplunkCredentialManager.SplunkCredentialType.LOCAL
                               --    SplunkCredentialManager.SplunkCredentialType.CUSTOM_API
                               --    SplunkCredentialManager.SplunkCredentialType.DIRECT
        hostname               -- the host where the credential is stored
        username               -- the username of the stored credential
        password               -- the new password for the stored credential
        app                    -- the Splunk app where the credential is stored

        Keyword Arguments:
        realm                  -- the Splunk realm to set the credential under (it's a passwords.conf thing).
        """
        cred_function = {
            SplunkCredentialManager.SplunkCredentialType.PASSWORDS_CONF : self.update_credential_passwordsconf,
            SplunkCredentialManager.SplunkCredentialType.LOCAL          : self.update_credential_localaccount,
            SplunkCredentialManager.SplunkCredentialType.CUSTOM_API     : self.update_credential_customapi,
            SplunkCredentialManager.SplunkCredentialType.DIRECT         : self.update_credential_direct,
        }

        response = cred_function[SplunkCredentialManager.SplunkCredentialType[splunk_credential_type]](hostname, username, password, app, realm, extra)

        if response != None:
            logger.debug(f'Credential update call: rc:{response.status_code}|{response.content}')
            if (int(response.status_code) < 200 or int(response.status_code) > 299):
                logger.error(f'Credential update failed. Host h:{hostname} returned status code {response.status_code}')

        return response
        exit(1)

    def bulk_update_credential(bulk_file: TextIO) -> None:
        """ static method to bulk update remote credentials for Splunk using settings defined in file
        Positional Arguments:
        bulk_file -- TextIO file handle storing configurations/accounts to update
        """
        logger.info(f"starting bulk processing using file {bulk_file.name}")
        try:
            bulk_creds = yaml.safe_load(bulk_file)
        except yaml.YAMLError as yexc:
            print(yexc)

        if bulk_creds['privileged-account']['provider']['type'] == "PAM":
            priv_cred_safe = PAMManager.PAMManager(bulk_creds['privileged-account']['provider']['url'], bulk_creds['privileged-account']['provider']['config'])
            extra_params = bulk_creds['privileged-account'].get('extra-params',{})
            priv_cred = priv_cred_safe.getCredential(username=bulk_creds['privileged-account']['name'],
                                                     safe=bulk_creds['privileged-account']['safe'],
                                                     appid=bulk_creds['privileged-account']['appid'],
                                                     **extra_params)
            splunk_cred_manager = SplunkCredentialManager(rootca=bulk_creds['ssl']['rootca'])

            for account in bulk_creds['sync-accounts']['accounts']:
                try:
                    splunk_cred_manager.authenticate(account['hostname'], priv_cred[0], priv_cred[1], verify=bulk_creds['ssl']['rootca'])
                except requests.ConnectionError as rce:
                    logger.error(f"encountered error while attempting to authenticate to {account.get('hostname',None)}")

                new_splunk_cred_safe = PAMManager.PAMManager(bulk_creds['sync-accounts']['provider']['url'], bulk_creds['sync-accounts']['provider']['config'])

                lookup_name = account['pamUsername'] or account['username']
                extra_params = account.get('extra-params',{})
                new_splunk_cred = new_splunk_cred_safe.getCredential(username=lookup_name,
                                                                     safe=bulk_creds['sync-accounts']['safe'],
                                                                     appid=bulk_creds['sync-accounts']['appid'],
                                                                     **extra_params)
                logger.info(f"syncing credential u:{account['username']} on h:{account['hostname']}...")
                force = bulk_creds['sync-accounts'].get('force',False)
                extra = account.get('extra',{})
                if extra.get('force') == None:
                    extra['force'] = force

                try:
                    response = splunk_cred_manager.update_credential(account.get('type',None),
                                                                     account.get('hostname',None),
                                                                     account.get('username',None),
                                                                     new_splunk_cred[1],
                                                                     account.get('app',None),
                                                                     realm=account.get('realm',None),
                                                                     extra=extra)
                except requests.ConnectionError as rce:
                    logger.error(f"encountered error while attempting to update credential for {account.get('hostname',None)}")

        if bulk_creds['privileged-account']['provider']['type'] == "local":
            priv_cred = (bulk_creds['privileged-account']['name'], bulk_creds['privileged-account']['password'])
            splunk_cred_manager = SplunkCredentialManager(rootca=bulk_creds['ssl']['rootca'])

            for account in bulk_creds['sync-accounts']['accounts']:
                if account.get('username') == None:
                    raise KeyError("bulk sync configuration file sync-accounts.accounts[X].username field is missing or empty for provider.type set as local")
                if account.get('password') == None:
                    raise KeyError("bulk sync configuration file sync-accounts.accounts[X].password field is missing or empty for provider.type set as local")

                try:
                    splunk_cred_manager.authenticate(account['hostname'], priv_cred[0], priv_cred[1], verify=bulk_creds['ssl']['rootca'])
                except requests.ConnectionError as rce:
                    logger.error(f"encountered error while attempting to authenticate to {account.get('hostname',None)}")

                logger.info(f"syncing credential u:{account['username']} on h:{account['hostname']}...")
                force = bulk_creds['sync-accounts'].get('force',False)
                extra = account.get('extra',{})
                if extra.get('force') == None:
                    extra['force'] = force

                try:
                    response = splunk_cred_manager.update_credential(account.get('type',None),
                                                                     account.get('hostname',None),
                                                                     account.get('username',None),
                                                                     account.get('password',None),
                                                                     account.get('app',None),
                                                                     realm=account.get('realm',None),
                                                                     extra=extra)
                except requests.ConnectionError as rce:
                    logger.error(f"encountered error while attempting to update credential for {account.get('hostname',None)}")


        #print(f'pw update response: {response}')

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Manage credentials within Splunk easier.')
    parser.add_argument('bulk_filename', nargs='?', type=argparse.FileType('r'), default=sys.stdin, help='file containing a bulk list of credentials to update in yaml')
    args = parser.parse_args()
    logger.info(f'Starting script: {__file__}')
    try:
        SplunkCredentialManager.bulk_update_credential(args.bulk_filename)
    except Exception as e:
        logger.error(e)

    logger.info(f'Ending script: {__file__}')
