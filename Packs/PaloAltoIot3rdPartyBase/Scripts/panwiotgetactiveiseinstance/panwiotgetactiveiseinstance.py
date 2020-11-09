import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
# run get-nodes on all ISE instances (primary and secondary)
response = demisto.executeCommand("cisco-ise-get-nodes", {})
err_msg = []
active_instance = None
demisto.executeCommand("syslog-send", {"message": response})

# go over responses from all configures instances
for resp in response:
    local_instance = resp['ModuleName']
    if isError(resp):
        # node is probably down or misconfigured. Dont do anything here,
        # just collect the error messages so we can report back to cloud if needed
        err = resp['Contents']
        err_msg.append(err.split('-')[0] + ", instance name = %s" % local_instance)
    else:
        # check if the output has any node that matches the local instance
        # and is also a primary or is in standalone mode
        for node_data in resp['Contents']['CiscoISE.NodesData']:
            if node_data['isLocalIstance']:
                if node_data['inDeployment'] == False or (node_data['inDeployment'] == True and node_data['primaryPapNode'] == True):
                    active_instance = local_instance

# if no active instances are found that means we dont have any valid ise nodes
# we can either report to cloud here or better write to the context data
# and do it in the playbook for better visibility
if active_instance == None:
    readable_status = "No Primary/Active Cisco ISE instance found = %s" % err_msg
    demisto.debug(readable_status)
    results = CommandResults(
        readable_output=readable_status,
        outputs_prefix="PaloAltoIoTIntegrationBase.NodeErrorStatus",
        outputs=readable_status
    )
    # write data to context
    return_results(results)
    # also return error, so we can detect it in the playbook
    return_error(err_msg)
else:
    readable_status = "Found active Cisco ISE instance = %s" % active_instance
    demisto.debug(readable_status)
    results = CommandResults(
        readable_output=readable_status,
        outputs_prefix="PaloAltoIoTIntegrationBase.ActiveNodeInstance",
        outputs=active_instance
    )
    return_results(results)
