import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import json
import urllib3
import requests
import traceback
from typing import Any, Dict, Tuple, List, Optional, Union, cast
from requests.auth import HTTPBasicAuth
import time

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''

BASE_URL = demisto.params().get('url')
USERNAME = demisto.params().get('credentials').get('identifier')
PASSWORD = demisto.params().get('credentials').get('password')
SITES = demisto.params().get('sites')

USE_SSL = not demisto.params().get('insecure', False)

DEFAULT_HEADERS = {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    'Connection': 'keep_alive'
}

# Authentication
AUTH_URL = '/dna/system/api/v1/auth/token'

# URLs
CLIENT_DETAIL = '/dna/intent/api/v1/client-detail'
CLIENT_ENRICHMENT_DETAILS = '/dna/intent/api/v1/client-enrichment-details'
#CLIENT_HEALTH = '/dna/intent/api/v1/client-health'
CLIENT_HOST = '/api/assurance/v1/host'
NETWORK_DEVICE = '/dna/intent/api/v1/network-device'
#NETWORK_HEALTH = '/dna/intent/api/v1/network-health'
#SITE_HEALTH = '/dna/intent/api/v1/site-health'

dnac_token = None

def http_request(method, url_suffix, params={}, auth=None, data=None, headers=DEFAULT_HEADERS)  -> Dict[str, Any]:
    try:
        url = BASE_URL + url_suffix
        LOG(f'running {method} request with url={url}')

        response = requests.request(
            method,
            url,
            headers=headers,
            auth=auth,
            verify=USE_SSL,
            params=params,
            data=data
        )
    except requests.exceptions.SSLError:
        err_msg = 'Could not connect to Cisco DNA Center: Could not verify certificate.'
        LOG(f'Error: {err_msg}')
        return_error(err_msg)
    except requests.exceptions.ConnectionError:
        err_msg = 'Connection Error. Verify that the Server URL and port are correct, and that the port is open.'
        LOG(f'Error: {err_msg}')
        return_error(err_msg)

    # handle request failure
    if response.status_code not in {200, 201, 202, 204}:
        message = parse_error_response(response)
        err_msg = f'Error in API call to Cisco DNA Center Integration [{response.status_code}] - {response.reason}, {message}'
        LOG(f'Error: {err_msg}')
        return_error(err_msg)

    try:
        response = response.json()
    except ValueError:
        return_error(f'error: {response}')

    return response

def parse_error_response(response):
    try:
        res = response.json()
        msg = res.get('ERSResponse').get('messages')
        err = msg[0].get('title', '')
    except Exception:
        return response.text
    return err

# Get Authentication token
def get_dnac_jwt_token():
    response = http_request('POST', AUTH_URL, auth=HTTPBasicAuth(USERNAME, PASSWORD))
    try:
        token = response['Token']
    except Exception:
        return response
    return token

# Get network health
def get_network_device(headers):
    response = http_request('GET', NETWORK_DEVICE, headers=headers)
    try:
        devices = response['response']
    except Exception:
        return response
    return CommandResults(
        outputs_prefix='cisco-dnac-IoT.network_device',
        outputs=devices
    )


# Get clients
def get_clients(headers):
    data={}
    response = http_request('POST', CLIENT_HOST, headers=headers, data=json.dumps(data))
    try:
        hosts = response['response']
    except Exception:
        return response
    return CommandResults(
        outputs_prefix='cisco-dnac-IoT.clients',
        outputs=hosts
    )

# Get client detail
def get_client_detail(headers):
    mac_address = demisto.args().get('client')
    timestamp = int(time.time() * 1000)
    params = {
        'timestamp': timestamp,
        'macAddress': mac_address
    }
    response = http_request('GET', CLIENT_DETAIL, headers=headers, params=params)
    return CommandResults(
        outputs_prefix='cisco-dnac-IoT.client_detail',
        outputs=response
    )

# Get client enrichment detail
def get_client_enrichment_detail(headers):
    mac_address = demisto.args().get('client')
    headers["entity_type"] = 'mac_address'
    headers["entity_value"] = mac_address
    response = http_request('GET', CLIENT_ENRICHMENT_DETAILS, headers=headers)
    return CommandResults(
        outputs_prefix='cisco-dnac-IoT.client_enrichment_detail',
        outputs=response[0]
    )


''' COMMAND FUNCTIONS '''

def test_module() -> str:
    """
    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """
    try:
        token = get_dnac_jwt_token()
    except DemistoException as e:
        raise e
    return 'ok'


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """
    global BASE_URL
    global dnac_token

    # get the service API url
    BASE_URL = demisto.params()['url']

    verify_certificate = not demisto.params().get('insecure', False)

    handle_proxy()

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        if dnac_token is None:
            dnac_token = get_dnac_jwt_token()

        headers = {
            'X-Auth-Token': dnac_token,
            'Content-Type': 'application/json'
        }

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module()
            return_results(result)

        elif demisto.command() == 'dnac-network-device':
            return_results(get_network_device(headers))

        elif demisto.command() == 'dnac-clients':
            return_results(get_clients(headers))

        elif demisto.command() == 'dnac-client-detail':
            return_results(get_client_detail(headers))

        elif demisto.command() == 'dnac-client-enrichment-detail':
            return_results(get_client_enrichment_detail(headers))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
