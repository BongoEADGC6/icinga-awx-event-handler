# AWX Icinga/Nagios Event Handler Wrapper

Utilizes the AWX API to launch jobs based on Icinga/Nagios event handler rules.

python3 awx_event_handler.py -H tower.radnetmgt.com --username admin --password password --template Icinga - Service Restart --inventory Icinga2 Monitored Hosts --limit caoverwatch01.radnet.rdlx.pvt --extra_vars {"service_to_restart":"logstash","service_manager":"upstart"}

Software requirements
Python 3+
Nagios 3.5 or higher | Icinga2 
Ansible Tower 3.2 or higher

## Icinga configuration


## Nagios configuration

### Example 1 - short call to the handler, wide impact
This will trigger the job run against all the hosts on the specified inventory.

/etc/nagios/conf.d/eventhandlers.cfg
define command {
    command_name        tower-handler-min
    # when playbook does not require extra_vars, and you want to run on full inventory
    command_line        $HANDLERS$/awx_event_handler.py --state '$SERVICESTATE$' --attempt '$SERVICEATTEMPT$' --downtime '$SERVICEDOWNTIME$' --host_downtime '$HOSTDOWNTIME$' --service '$SERVICEDESC$' --hostname '$HOSTADDRESS$' --template '$ARG1$' --inventory '$ARG2$'
}
/etc/nagios/hosts.d/server01.example.com.cfg
define service {
    use                         generic-service
    host_name                   server01.example.com
    service_description         MyAppService
    contact_groups              it-production
    check_command               check_myappservice
    event_handler               tower-handler-min!My Template!My Inventory
}

### Example 2 - longer call to the handler, more precise action
This allows the use of all parameters during the handler call, which provides more information to the job template, allowing fore more precise action.

/etc/nagios/conf.d/eventhandlers.cfg
define command {
    command_name        tower-handler-full
    command_line        $HANDLERS$/tower_handler.py --state '$SERVICESTATE$' --attempt '$SERVICEATTEMPT$' --downtime '$SERVICEDOWNTIME$' --host_downtime '$HOSTDOWNTIME$' --service '$SERVICEDESC$' --hostname '$HOSTADDRESS$' --template '$ARG1$' --inventory '$ARG2$' --extra_vars '$ARG3$' --limit '$ARG4$'
}
/etc/nagios/hosts.d/server01.example.com.cfg
define service {
    use                         generic-service
    host_name                   server01.example.com
    service_description         MyAppService
    contact_groups              it-production
    check_command               check_myappservice
    event_handler               tower-handler-full!My Template!My Inventory!my_variable: value!<fqdn>"
}

Note: in this case, <fqdn> can be either the host itself, or a totally different host, as long as it exists in the inventory.

Useful variations
Run against the host itself -- By adding --limit '$HOSTADDRESS$' to the command definition, the job will run only against the host which called the handler.
Run in WARNING state -- By default, the script only runs when the alert is in CRITICAL or UNKNOWN state. Adding --warning to the command definition will allow it to trigger during a WARNING state.