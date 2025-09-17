# load libraries
try:
    from urllib.request import urlopen, Request
    from urllib.parse import urlencode
    from urllib.error import HTTPError
    from CredentialRetriever import CredentialRetriever
    import configparser
    import logging
    from typing import Tuple
    import json
    import ssl
    import sys
except NameError as lib_load_exc:
    print(lib_load_exc)
    exit(1)

# create logging objects
logger = logging.getLogger(__name__)
handler = logging.FileHandler('PAMManager.log')
stream_handler = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')

# set default logging levels for handlers
logger.setLevel(logging.DEBUG)
handler.setLevel(logging.DEBUG)
stream_handler.setLevel(logging.DEBUG)

# set handler formatting
handler.setFormatter(formatter)
stream_handler.setFormatter(formatter)

# add handlers to logger
logger.addHandler(handler)
logger.addHandler(stream_handler)

class PAMManager(CredentialRetriever):
    """ Manages the connection to PAM and ability to retrieve credentials

    getCredential(self, username: str, **kwargs: dict) -> (username: str, password: str)

    getConfig(self) -> ConfigParser
    """
    _config = {}
    _cert_context = None

    # default headers
    headers = {
        'content-type': 'application/json'
    }

    def __configure_certs(self):
        """ configure certificates using config file set and loaded during instantiation """
        self._cert_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        passfile = self._config['ssl'].get('passfile',None)
        if passfile:
            with open(passfile, 'r') as passfile_handle:
                pw = passfile_handle.read().replace('\n','')
            self._cert_context.load_cert_chain(certfile=self._config['ssl']['cert'], keyfile=self._config['ssl']['key'], password=pw)
        else:
            self._cert_context.load_cert_chain(certfile=self._config['ssl']['cert'], keyfile=self._config['ssl']['key'])
        self._cert_context.load_verify_locations(cafile=self._config['ssl']['rootca'])

    def __init__(self, address: str, config: str='./pam_config.ini'):
        """ constructor for PAMManager
        Positional Arguments:
        address -- address of the password management system

        Keyword Arguments:
        config  -- config holding connection configurations
        """
        with open(config,'r') as config_file:
            self._config = configparser.ConfigParser()
            self._config.read(config)
        self.address = address
        self.__configure_certs()

    def getCredential(self, username: str=None, **kwargs: dict) -> Tuple[str, str]:
        """ fetch password for username under settings set during initialization """
        required = ['appid', 'safe', 'username']

        headers = self.headers
        kwargs['username'] = username
        safe = kwargs.get('safe',None)
        appid = kwargs.get('appid',None)

        if not all(name in kwargs for name in required):
            logger.error("safe, appid and username are all required in order to retrieve credentials from PAM")
            exit(1)
        else:
            pam_params = {
                'username': username,
            }
            pam_params.update(kwargs)
            url_params = urlencode(pam_params)


        request_url=f'{self.address}?{url_params}'
        request = Request(request_url)

        # add headers to request object
        for header_key in headers:
            request.add_header(header_key, headers[header_key])

        logger.debug(f"fetch credential from: {request_url}")

        cred = ()
        if self._cert_context:
            try:
                with urlopen(request, context=self._cert_context) as response:
                    pam_response = response.read()

                    if not pam_response:
                        logger.error("pam response empty")
                    else:
                        pam_json = json.loads(pam_response.decode('utf-8'))
                        cred = (pam_json['UserName'], pam_json['Content'])
            except HTTPError as htpe:
                logger.error(htpe)
                exit(1)

        return cred

    def getConfig(self) -> configparser:
        """ return internal config object containing connection settings """
        return self._config
