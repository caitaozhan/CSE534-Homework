Hi TA, 

All the code for Part A and Part B is in mydig.py

There are also three Jupyter notebook files. I did not delete them because I actually code in notebooks. When I finish implementing and debugging, I copy the code from the notebook to mydig.py

The output for Part A is in mydig_output.txt. The output for Part B is in mydig_dnssec_output.txt

There are also two PDF files as required


Thanks for your time,

Caitao Zhan


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

import matplotlib.pyplot as plt

import numpy as np

---

# Instuction on how to run your program
mydig.py is developed using Python 3.6

Example input:

python mydig.py www.cnn.com A ---- find the IP address of www.cnn.com

python mydig.py amazon.com  NS --- find the Name Server of amazon.com

python mydig.py amazon.com  MX --- find the Mail eXange of amazon.com

python mydig.py dnssec-failed.org A +dnssec --- find the IP address of densec-faild.org using the DNSSEC protocal

python mydig.py paypal.com A +dnssec        --- find the IP address of paypal.com using the DNSSEC protocal
