#!/usr/bin/python
# Web site: https://github.com/BongoEADGC6/icinga-awx-event-handler
# Author: https://github.com/BongoEADGC6
#
# This script has been designed to be run as a
# Nagios/Icinga Service Handler. It will trigger an
# Ansible Tower job template via the API.


import sys
import json
import syslog
import argparse
import requests

# things we pass to the job POST call
job_data = {}
# prevents log_run from breaking
job_number = ""
job_status = ""
# used to find by name
template_number = None
inventory_number = None

parser = argparse.ArgumentParser()
parser.add_argument("-H", "--host", help="Tower host", required=True)
parser.add_argument("-u", "--username", help="Tower username", required=True)
parser.add_argument("-p", "--password", help="Tower password", required=True)
parser.add_argument("--insecure", help="Disable SSL certificate verification.",
                    required=False, action='store_true')
parser.add_argument("--template", help="Job template (number or name)",
                    required=True)
parser.add_argument("--inventory", help="Inventory (number or name)",
                    required=True)
parser.add_argument("--playbook", help="Playbook to run (yaml file inside \
                    template)", required=False)
parser.add_argument("--extra_vars", help="Extra variables (JSON)",
                    required=False)
parser.add_argument("--limit", help="Limit run to these hosts (group name, \
                    or comma separated hosts)", required=False)
parser.add_argument("--state", help="Nagios check state", required=False)
parser.add_argument("--attempt", help="Nagios check attempt", required=False,
                    type=int, default=0)
parser.add_argument("--downtime", help="Nagios service downtime check",
                    required=False, type=int, default=0)
parser.add_argument("--host_downtime", help="Nagios host downtime check",
                    required=False, type=int, default=0)
parser.add_argument("--service", help="Nagios alerting service",
                    required=False)
parser.add_argument("--hostname", help="Nagios alerting hostname",
                    required=False)
parser.add_argument("--warning",
                    help="Trigger on WARNING (otherwise just CRITICAL and \
                      UNKNOWN)",
                    required=False, action='store_true')
parser.add_argument("-v", "--verbose", help="Enable verbosity",
                    required=False, action='store_true')

args = parser.parse_args()


def logger(msg):
    syslog.syslog(msg)


def error(msg):
    sys.stderr.write(msg + "\n")
    exit(3)


def info(msg):
    print(msg)


def log_run(msg):
    # kind of NRPE-style logging
    logger('job_number=%s job_status="%s" service="%s" hostname="%s" service_state="%s" service_attempt=%s service_downtime=%s host_downtime=%s template="%s" inventory="%s" extra_vars="%s" limit="%s" handler_message="%s"' %
           (job_number, job_status, args.service, args.hostname, args.state, args.attempt, args.downtime, args.host_downtime, args.template, args.inventory, args.extra_vars, args.limit, msg))


# don't run handler if either one is true:
# - service state is OK
# - downtime is set
# - this is the first attempt
# - option --warning is not set
if args.state == "OK" or \
    args.downtime > 0 or \
        args.host_downtime > 0 or \
        args.attempt <= 1 or \
        (args.state == "WARNING" and args.warning is False):
            log_run("SKIP: skipped")
            sys.exit(0)

root_url = "https://{}/api/v2".format(args.host)
auth_username = args.username
auth_password = args.password
ssl_verify = args.insecure


def apiPost(api_uri, data):
    called_url = root_url + api_uri
    headers = {'Content-Type': 'application/json'}
    response = requests.post(called_url, auth=(auth_username, auth_password),
                             headers=headers, json=data, verify=ssl_verify)
    if response.status_code == 401:
        log_run("Error authenticating to tower. Check user/password.")
        error("Error authenticating to tower. Check user/password.")
    response.raise_for_status()
    return json.loads(response.text)


def apiGet(api_uri):
    # called_url = requests.utils.quote(root_url + api_uri)
    called_url = root_url + api_uri
    headers = {'Content-Type': 'application/json'}
    response = requests.get(called_url, auth=(auth_username, auth_password),
                            headers=headers, verify=ssl_verify)
    if response.status_code == 401:
        log_run("Error authenticating to tower. Check user/password.")
        error("Error authenticating to tower. Check user/password.")
    response.raise_for_status()
    return json.loads(response.text)


if not args.template.isdigit():
    try:
        # when --template is a name, we need the number
        # find_template = apiGet('/job_templates/')
        url = '/job_templates/?name__icontains={}'.format(args.template)
        find_template = apiGet(url)
        template_number = find_template['results'][0]['id']
    except Exception as err:
        log_run("ERROR: template not found")
        print(err)
        error("The template {} could not be found.".format(args.template))
else:
    # when --template is a number
    template_number = args.template

try:
    job_check = apiGet('/job_templates/{}'.format(template_number))
    if args.verbose:
        print("Found Job")
except Exception as err:
    log_run("ERROR: template not found")
    print(err)
    error("The template {} could not be found.".format(template_number))


if (job_check['ask_inventory_on_launch'] and not args.inventory):
    log_run("ERROR: template requires inventory")
    error("This job template requires an inventory number.")

if not args.inventory.isdigit():
    try:
        # when --inventory is a name, we need a number
        url = '/inventories/?name__icontains={}'.format(args.inventory)
        find_inventory = apiGet(url)
        if find_inventory['count'] == 0:
            error("Inventory search returned no results")
        inventory_number = find_inventory['results'][0]['id']
    except Exception as err:
        log_run("ERROR: inventory not found")
        print(err)
        error("The inventory name {} could not be found."
              .format(args.inventory))
else:
    # when --inventory is a number
    inventory_number = args.inventory

try:
    inventory_check = apiGet('/inventories/{}'.format(inventory_number))
    job_data['inventory'] = inventory_number
except Exception as err:
    log_run("ERROR: inventory not found")
    print(err)
    error("The inventory id {} could not be found.".format(inventory_number))

if (job_check['ask_variables_on_launch']):
    if not args.state and not args.extra_vars:
        # probably means we are in interactive mode
        error("The job requires extra_vars in JSON format.")
    try:
        if args.extra_vars:
            job_data['extra_vars'] = json.loads(args.extra_vars)
        else:
            job_data['extra_vars'] = "{ 'nagios_no_extra_var': true }"
    except ValueError:
        error("The extra_vars parameter is not valid JSON.")

if(job_check['ask_limit_on_launch'] and not args.limit):
    log_run("ERROR: job requires --limit")
    error("The job requires a list of hosts to limit the run.")
else:
    job_data['limit'] = args.limit

try:
    job_started = apiPost('/job_templates/{}/launch/'.format(template_number),
                          data=job_data)
    # print(json.dumps(job_started, indent=2))
    if(job_started['id'] and job_started['job']):
        job_number = job_started['id']
        job_status = "STARTED"
        log_run("OK: job started")
        info("Tower job {} started.".format(job_number))
    else:
        job_status = "FAILED"
        log_run("ERROR: API call to start job failed")
        error("Could not start tower job: {}"
              .format(job_started['result_stdout']))
except Exception as err:
    log_run("ERROR: bad request on API call -- \
            URI[/job_templates/{}/launch/] DATA[{}]"
            .format(template_number, job_data))
    print(err)
    error("There was a bad request on the API call -- \
          URI[/job_templates/{}/launch/] DATA[{}]"
          .format(template_number, job_data))
