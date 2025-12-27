#!/bin/bash
goaccess -a -g -f /home/*/logs/access_*_log -o /opt/tinopanel/private_html/index.html --log-format=COMBINED --real-time-html