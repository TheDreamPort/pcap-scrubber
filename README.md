# pcap-scrubber
This is a python utility designed to remove frames from a PCAP file for anonymization. this project was created to serve a need for PCAP analysis at DreamPort. The more realistic PCAP we study the better off we are HOWEVER we must ensure not to reveal personally or professionally identifiable information from the environment where we gathered our data in the first place.

At this time, this script is written for (and tested on) Python 2.7 but we are confident it will easily port to Python 3.7. This script was developed and tested on Ubuntu 18.04.1 LTS desktop.

# installation
This project is meant to be installed and configured with PIP. Once you clone this repository you should be able to install the required packages with the following syntax:

`pip install -r requirements.txt`

This project makes use of the following Python modules:
* DPKT - https://dpkt.readthedocs.io/en/latest/

# operation
Execution of this script is meant to be as simple as possible. To put it simply, this utility is meant to remove packets from a source PCAP file and write the results to a new file. Packets are specified for removal by protocol or port. In the following example a PCAP file is cleaned of all BROWSER frames (UDP source/dest port of 138):

`./pcap_scrub.py -P browser <TARGET PCAP>`

In the next example, a target PCAP file is cleaned of all BROWSER, POP and LDAP frames:

`./pcap_scrub.py -P browser,pop,ldap <TARGET PCAP>`

In the next example, a target PCAP file is cleaned of any TCP or UDP packe t whose source or destination port matches the following:

`./pcap_scrub.py -p 3535,1248,9100 <TARGET PCAP>`

You can display the options that this script supports with the following example:

`./pcap_scrub.py -h`
