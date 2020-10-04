import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import requests
import json
import urllib3
import dateparser
import traceback
from typing import Any, Dict, Tuple, List, Optional, Union, cast
from datetime import datetime
from datetime import timedelta

# Disable insecure warnings
urllib3.disable_warnings()

KEY_ID = demisto.params().get("Key ID")
ACCESS_KEY = demisto.params().get("Access Key")
CUSTOMER_ID = demisto.params().get("Customer ID")
BASE_URL = demisto.params().get("url")
DEFAULT_PAGE_SIZE = 1000

api_type_map = {
    "Devices": {
        "url": "pub/v4.0/device/list",
        "output_path": "PaloAltoIoTIntegrationBase.Devices",
        "status_path": "PaloAltoIoTIntegrationBase.DeviceInventoryStatus"
    },
    "Alerts": {
        "url": "pub/v4.0/alert/list",
        "output_path": "PaloAltoIoTIntegrationBase.Alerts",
        "status_path": "PaloAltoIoTIntegrationBase.AlertStatus"
    },
    "Vulnerabilities": {
        "url": "pub/v4.0/vulnerability/list",
        "output_path": "PaloAltoIoTIntegrationBase.Vulnerabilities",
        "status_path": "PaloAltoIoTIntegrationBase.VulnerabilityStatus"
    }
}

device_fields_map = [
    ("ip_address", "dvc="),
    ("mac_address", "dvcmac="),
    ("hostname", "dvchost="),
    ("profile", "cs1Label=Profile cs1="),
    ("category", "cs2Label=Category cs2="),
    ("profile_type", "cs1Labe3=Profile cs3="),
    ("vendor", "cs4Label=Vendor cs4="),
    ("model", "cs5Label=Model cs5="),
    ("vlan", "cs6Label=Vlan cs6="),
    ("site_name", "cs7Label=Site cs7="),
    ("risk_score", "cs8Label=RiskScore cs8="),
    ("risk_level", "cs9Label=RiskLevel cs9="),
    ("subnet", "cs10Label=Subnet cs10="),
    ("number_of_critical_alerts", "cs11Label=NumCriticalAlerts cs11="),
    ("number_of_warning_alerts", "cs12Label=NumWarningAlerts cs12="),
    ("number_of_caution_alerts", "cs13Label=NumCautionAlerts cs13="),
    ("number_of_info_alerts", "cs14Label=NumInfoAlerts cs14="),
    ("first_seen_date", "cs15Label=FirstSeenDate cs15="),
    ("confidence_score", "cs16Label=ConfidenceScore cs16="),
    ("os_group", "cs17Label=OsGroup cs17="),
    ("os/firmware_version", "cs18Label=OsFirmwareVersion cs18="),
    ("OS_Support", "cs19Label=OsSupport cs19="),
    ("OS_End_of_Support", "cs20Label=OsEndOfSupport cs20="),
    ("Serial_Number", "cs21Label=SerialNumber cs21="),
    ("endpoint_protection", "cs22Label=EndpointProtection cs22="),
    ("NetworkLocation", "cs23Label=NetworkLocation cs23="),
    ("AET", "cs24Label=AET cs24="),
    ("DHCP", "cs25Label=DHCP cs25="),
    ("wire_or_wireless", "cs26Label=WireOrWireless cs26="),
    ("SMB", "cs27Label=SMB cs27="),
    ("Switch_Port", "cs28Label=SwitchPort cs28="),
    ("Switch_Name", "cs29Label=SwitchName cs29="),
    ("Switch_IP", "cs30Label=SwitchIp cs30="),
    ("services", "cs31Label=Services cs31="),
    ("is_server", "cs32Label=IsServer cs32="),
    ("NAC_profile", "cs33Label=NAC_Profile cs33="),
    ("NAC_profile_source", "cs34Label=NAC_ProfileSource cs34="),
    ("Access_Point_IP", "cs35Label=AccessPointIp cs35="),
    ("Access_Point_Name", "cs36Label=AccessPointName cs36="),
    ("SSID", "cs37Label=SSID cs37="),
    ("Authentication_Method", "cs38Label=AuthMethod cs38="),
    ("Encryption_Cipher", "cs39Label=EncryptionCipher cs39="),
    ("AD_Username", "cs40Label=AD_Username cs40="),
    ("AD_Domain", "cs41Label=AD_Domain cs41="),
    ("Applications", "cs42Label=Applications cs42="),
    ("Tags", "cs43Label=Tags cs43=")]

vulnerabilities_fields_map = [
    ("ip", "dvc="),
    ("deviceid", "dvcmac="),
    ("name", "dvchost="),
    ("profile", "cs1Label=Profile cs1="),
    ("display_profile_category", "cs2Label=Category cs2="),
    ("profile_vertical", "cs1Labe3=Profile cs3="),
    ("vendor", "cs4Label=Vendor cs4="),
    ("model", "cs5Label=Model cs5="),
    ("vlan", "cs6Label=Vlan cs6="),
    ("site_name", "cs7Label=Site cs7="),
    ("risk_score", "cs8Label=RiskScore cs8="),
    ("risk_level", "cs9Label=RiskLevel cs9="),
    ("subnet", "cs10Label=Subnet cs10="),
    ("vulnerability_name", "cs11Label=vulnerabilityName cs11="),
    ("detected_date", "cs12Label=DetectionDate cs12="),
    ("remediate_instruction", "cs13Label=RemediateInstructions cs13="),
    ("remediate_checkbox", "cs14Label=RemediateCheckbox cs14="),
    ("first_seen_date", "cs15Label=FirstSeenDate cs15="),
    ("confidence_score", "cs16Label=ConfidenceScore cs16="),
    ("os", "cs17Label=OsGroup cs17="),
    ("os/firmware_version", "cs18Label=OsFirmwareVersion cs18="),
    ("osCombined", "cs19Label=OsSupport cs19="),
    ("OS_End_of_Support", "cs20Label=OsEndOfSupport cs20="),
    ("Serial_Number", "cs21Label=SerialNumber cs21="),
    ("endpoint_protection", "cs22Label=EndpointProtection cs22="),
    ("NetworkLocation", "cs23Label=NetworkLocation cs23="),
    ("AET", "cs24Label=AET cs24="),
    ("DHCP", "cs25Label=DHCP cs25="),
    ("wire_or_wireless", "cs26Label=WireOrWireless cs26="),
    ("SMB", "cs27Label=SMB cs27="),
    ("Switch_Port", "cs28Label=SwitchPort cs28="),
    ("Switch_Name", "cs29Label=SwitchName cs29="),
    ("Switch_IP", "cs30Label=SwitchIp cs30="),
    ("services", "cs31Label=Services cs31="),
    ("is_server", "cs32Label=IsServer cs32="),
    ("NAC_profile", "cs33Label=NAC_Profile cs33="),
    ("NAC_profile_source", "cs34Label=NAC_ProfileSource cs34="),
    ("Access_Point_IP", "cs35Label=AccessPointIp cs35="),
    ("Access_Point_Name", "cs36Label=AccessPointName cs36="),
    ("SSID", "cs37Label=SSID cs37="),
    ("Authentication_Method", "cs38Label=AuthMethod cs38="),
    ("Encryption_Cipher", "cs39Label=EncryptionCipher cs39="),
    ("AD_Username", "cs40Label=AD_Username cs40="),
    ("AD_Domain", "cs41Label=AD_Domain cs41="),
    ("Applications", "cs42Label=Applications cs42="),
    ("Tags", "cs43Label=Tags cs43=")]


def convert_device_map_to_cef():
    device_details = demisto.args().get('deviceList')
    opList = []
    if 'mac_address' in device_details:
        line = "INFO:siem-syslog:CEF:0|PaloAltoNetworks|PANWIOT|1.0|asset|Asset Identification|1|"
        for t in device_fields_map:
            input_field = t[0]
            output_field = t[1]
            # print input_field, output_field
            if input_field in device_details:
                val = device_details[input_field]
            else:
                val = ""
            if output_field and val:
                line += str(output_field) + str(val) + " "
        opList.append(line)

    return CommandResults(
        readable_output="Device inventory CEF Syslog",
        outputs_prefix='PaloAltoIoTIntegrationBase.DeviceSyslogs',
        outputs=opList
    )


def convert_alert_map_to_cef():
    alert = demisto.args().get('alertList')
    opList = []
    if alert != None and "msg" in alert and "status" in alert["msg"] and alert["msg"]["status"] == "publish":
        msg = alert['msg']
        line = "CEF:0|PaloAltoNetworks|PANWIOT|1.0|PaloAltoNetworks Alert:policy_alert|"

        if "name" in alert:
            line += alert["name"] + "|"
        if "severityNumber" in alert:
            line += str(alert["severityNumber"]) + "|"
        if "deviceid" in alert:
            line += "dvcmac=%s " % alert["deviceid"]
        if "fromip" in msg:
            line += "src=%s " % msg["fromip"]
        if "toip" in msg:
            line += "dst=%s " % msg["toip"]
        if "hostname" in msg:
            line += "shost=%s " % msg["hostname"]
        if "toURL" in msg:
            line += "dhost=%s " % msg["toURL"]
        if "id" in msg:
            line += "fileId=%s " % msg["id"]
            line += "fileType=alert "

        if "date" in alert:
            line += "rt=%s " % str(msg["id"])
        if "generationTimestamp" in msg:
            line += "deviceCustomDate1=%s " % str(msg["generationTimestamp"])

        description = None
        values = []
        if "description" in alert:
            description = alert["description"]
        if "values" in msg:
            values = msg["values"]

        line += "cs1Label=Description cs1=%s " % description
        line += "cs2Label=Values cs2=%s " % str(values)
        opList.append(line)
        return CommandResults(
            readable_output="Alert CEF Syslog",
            outputs_prefix='PaloAltoIoTIntegrationBase.AlertSyslogs',
            outputs=line
        )


def convert_vulnerability_map_to_cef():
    vulnerability = demisto.args().get('VulnerabilityList')
    opList = []

    risk_level_map = {'Critical': '10', 'High': '6', 'Medium': '3', 'Low': '1'}

    line = "INFO:siem-syslog:CEF:0|PaloAltoNetworks|PANWIOT|1.0|vulnerability|"
    if "vulnerability_name" in vulnerability:
        line += vulnerability['vulnerability_name'] + "|"
    if "risk_level" in vulnerability:
        if vulnerability["risk_level"] in risk_level_map:
            line += risk_level_map[vulnerability["risk_level"]] + "|"
        else:
            line += "1|"  # default severity

    for t in vulnerabilities_fields_map:
        input_field = t[0]
        output_field = t[1]
        # print input_field, output_field
        if input_field in vulnerability:
            val = vulnerability[input_field]
        else:
            val = ""
        if output_field and val:
            line += str(output_field) + str(val) + " "
    opList.append(line)

    return CommandResults(
        readable_output="Vulnerability CEF Syslog",
        outputs_prefix='PaloAltoIoTIntegrationBase.VulnerabilitySyslogs',
        outputs=opList
    )


def run_get_request(api_type, api_url, stime=None, offset=0):
    if stime == None:
        stime = '-1'
    url = BASE_URL + api_url
    params = (
        ('customerid', CUSTOMER_ID),
        ('key_id', KEY_ID),
        ('access_key', ACCESS_KEY),
        ('stime', stime),
        ('offset', str(offset)),
        ('pagelength', str(DEFAULT_PAGE_SIZE)),
    )
    if api_type == "Devices":
        params += (('detail', 'true'),)
    elif api_type == "Vulnerabilities":
        params += (('groupby', 'device'),)

    response = None
    try:
        response = requests.get(url, params=params)
        code = response.status_code
        if code < 300:
            status = "Success"
        else:
            status = "HTTP error code = %s, url = %s" % (str(code), url)
    except requests.exceptions.RequestException as e:
        status = "Failed connection to %s\n%s" % (url, e)
    return status, response


def write_status_context_data(status_path, message, status, count):
    existing_data = demisto.getIntegrationContext()
    existing_data[status_path] = {
        "message": message,
        "status": status,
        "count": count,
        "timestamp": str(datetime.now())
    }
    demisto.setIntegrationContext(existing_data)


def run_api_command(api_type, delay=-1):
    if api_type not in api_type_map:
        return_error("Invalid API type")

    api_url = api_type_map[api_type]['url']
    output_path = api_type_map[api_type]['output_path']
    status_path = api_type_map[api_type]['status_path']

    asset_list = []
    offset = 0
    count = 0
    if delay != -1:
        stime = datetime.now() - timedelta(minutes=delay)
    else:
        stime = None
    # Loop to gather all data available, each req
    while True:
        status, response = run_get_request(api_type, api_url, stime, offset)
        # if API failed, write error status to context so we can forward this back to the cloud
        if status != "Success":
            write_status_context_data(status_path, status, "Error", -1)
            return_error(status)
        try:
            data = json.loads(response.text)
            if api_type == "Devices":
                assets = data['devices']
                count = data['total']
            else:
                assets = data['items']
                count = len(data['items'])
            asset_list.extend(assets)
            if count == DEFAULT_PAGE_SIZE:
                offset += DEFAULT_PAGE_SIZE
            else:
                break
        except Exception as e:
            status = "Exception in parsing %s API response %s" % (api_type, str(e))
            write_status_context_data(status_path, status, "Error", -1)
            return_error(status)

    return_message = "Total %s pulled from IoT cloud %d" % (api_type, len(asset_list))
    write_status_context_data(status_path, return_message, status, len(asset_list))

    return CommandResults(
        readable_output=return_message,
        outputs_prefix=output_path,
        outputs=asset_list
    )


def send_return_status():
    arg = demisto.args().get('input_type')
    playook_name = demisto.args().get('playook_name')

    if arg in api_type_map:
        path = api_type_map[arg]['status_path']
        integration_context = demisto.getIntegrationContext()
        if path in integration_context:
            context_data = integration_context[path]
            count = context_data['count']
            if count == 0:
                message = "Nothing to send to SIEM server, %d %s received from IoT Cloud" % (count, arg)

            elif count >= 1:
                message = "Succesfully sent %d %s to SIEM server" % (count, arg)
            else:
                message = context_data['message']
            data = {"playbook_name": playook_name, "message": message,
                    "status": context_data['status'], "type": arg, "timestamp": context_data['timestamp']}
        else:
            count = 0
            message = "Nothing to send to SIEM server, %d %s received from IoT Cloud" % (count, arg)
            data = {"playbook_name": playook_name, "message": message,
                    "status": "Success", "type": arg, "timestamp": str(datetime.now())}

        # handle key errors for context_data
        # find a way to get the playbook name and determine the integration type (SIEM, ISE, etc)
        # Once we are here that means this task is called right at the end so everything went well.
        # we already have hte number of assets pulled, need to the integration/playbook to determine the specific action/stat

    else:
        # if the input type is not Devices,Alerts or Vulnerabilities that means something definitely went wrong
        # Simply use the input type to determine what went wrong and report to cloud
        message = "%s Failed" % arg
        data = {"playbook_name": playook_name, "message": message,
                "status": "Failure", "type": arg, "timestamp":  str(datetime.now())}
        path = "PaloAltoIoTIntegrationBase.Errors"

    # Send data over to iot cloud
    # 1. confirm if the access key, key id and other params are the same as the ones we use
    #   to make the GET requests
    # 2. do a try/except to get errors

    return CommandResults(
        readable_output=data,
        outputs_prefix=path,
        outputs=data
    )


def main() -> None:
    """main function, parses params and runs command functions
    :return:
    :rtype:
    """
    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        if demisto.command() == 'test-module':
            status, response = run_get_request("Alerts", "pub/v4.0/alert/list")
            if(status == "Success"):
                return_results('ok')
            else:
                return_results(response.status_code)
        elif demisto.command() == 'get-bulk-device-inventory':
            results = run_api_command("Devices", -1)
            return_results(results)
        elif demisto.command() == 'get-bulk-vulnerabilities':
            results = run_api_command("Vulnerabilities", -1)
            return_results(results)
        elif demisto.command() == 'get-bulk-alerts':
            results = run_api_command("Alerts", -1)
            return_results(results)
        elif demisto.command() == 'get-incremental-device-inventory':
            results = run_api_command("Devices", 15)
            return_results(results)
        elif demisto.command() == 'get-incremental-alerts':
            results = run_api_command("Alerts", 15)
            return_results(results)
        elif demisto.command() == 'get-incremental-vulnerabilities':
            results = run_api_command("Vulnerabilities", 15)
            return_results(results)
        elif demisto.command() == 'convert-device-inventory-to-cef':
            results = convert_device_map_to_cef()
            return_results(results)
        elif demisto.command() == 'convert-alerts-to-cef':
            results = convert_alert_map_to_cef()
            return_results(results)
        elif demisto.command() == 'convert-vulnerabilities-to-cef':
            results = convert_vulnerability_map_to_cef()
            return_results(results)
        elif demisto.command() == 'report-status-to-iot-cloud':
            results = send_return_status()
            return_results(results)

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''
if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
