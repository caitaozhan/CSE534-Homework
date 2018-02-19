# External libraries used:

import dns.query
import dns.message
import re
import ipaddress
import time
import datetime
import random
from enum import Enum
import pandas


# Instuction on how to run your program
mydig.py is developed using Python 3.6

Example input:

python mydig.py www.cnn.com A ---- find the IP address of www.cnn.com
python mydig.py amazon.com  NS --- find the Name Server of amazon.com
python mydig.py amazon.com  MX --- find the Mail eXange of amazon.com

python mydig.py dnssec-failed.org A +dnssec --- find the IP address of densec-faild.org using the DNSSEC protocal
python mydig.py paypal.com A +dnssec        --- find the IP address of paypal.com using the DNSSEC protocal
