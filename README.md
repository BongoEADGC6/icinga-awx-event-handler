Utilizes the AWX API to launch jobs based on Icinga/Nagios event handler rules.

python3 awx_event_handler.py -H tower.radnetmgt.com --username admin --password password --template Icinga - Service Restart --inventory Icinga2 Monitored Hosts --limit caoverwatch01.radnet.rdlx.pvt --extra_vars {"service_to_restart":"logstash","service_manager":"upstart"}
