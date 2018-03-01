# A10_Health_Check
Automated Health Check for A10 Devices

This health check was written to automate the A10 Health Check document (provided). The goal of the health check is to run operational & system level commands to collect output from customer production A10 ADC's that can ensure that the device(s) being tested are running in a state that is optimum to provide highly available application services. 

With this script, the time required to collect the data goes from hours to minutes. The output created can then be reviewed by an A10 expert who can verify the health of the systems and identify any potential issues.


### Running the Health Check

Linux

    ./Health_Check.py -d [device address] -u [username] -p [password] [-vvv] -w [n] -r [x]
    
  Windows

    python3 Health_Check.py -d [device address] -u [username] -p [password] [-vvv] -w [n] -r [x]

where
    -d - Device(s) under test. Multiple devices may be included separated by a comma.
    -u - username
    -p - password
    -w - the wait time (in seconds) between functions. (Slower calls == less CPU utilization)
    -r - the number of times to repeat a command. (A few of the calls will loop for x times). 
         For example, if x is 60, 'show slb performance' is repeated for 1 minute. 

### Requirements
* ACOS v4.x or newer (AxAPIv3 is required). 
* Python 3.x or newer
* The following libraries
    * argparse
    * requests
    * json
    * ruamel.yaml
    * time.sleep
    * logging
    * datetimerequests
    * inspect
    * re
