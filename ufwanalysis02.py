#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Aug 16 02:41:02 2021

@author: jak
"""

import os
import re

WORKDIR = '/home/jak/Documents/pyprogs/logreader'

#LOGFILE = 'ufw.log.copy'
LOGFILE = '/var/log/ufw.log'

log_contents = {}

big = {} # to hold all of the lines once they've been parsed
failed = [] # to hold any lines that drop out

""" first step in splitting the log lines: """
logline_regex = re.compile(r"""
                           (.+)
                           \[UFW\s(BLOCK|ALLOW|LOG)\]
                           (.+)
                           """, re.VERBOSE)
                           

""" timestamp regex """
timestamp_regex = re.compile(r"""
        (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) # month
        \s+
        (\d+) # day
        \s+
        (\d{2}:\d{2}:\d{2}) # time
        \s+
        (\w+) # hostname
        \s+
        \w+\: # message source (discard)
        \s+
        (\[\s*\d+.\d+\]) # cpu uptime
        \s*.*
        """, flags=re.VERBOSE)

def load_file(): 
    """ opens and loads the file into log_contents """
    global log_contents
    try:
        with open(os.path.join(WORKDIR, LOGFILE)) as ufw_log:
            log_contents = ufw_log.read().splitlines()
    except IOError:
        print('Could not open LOGFILE: ', LOGFILE)


def accumulate(string_in):
    """ process an entire line from the log"""
        
    global big # to store the broken-out data
    global failed # for fallout lines
    timestamp = ''
    restofline = {}
    
    if m := logline_regex.match(string_in):
        i = 1
        for g in m.groups():
            # print('group {}: "{}"'.format(i, g))
            if i == 1: 
                # first group is the time data - get the timestamp: 
                timestamp = make_timestamp(g)
            # elif i == 2: # discard the hostname for now
            #    hostname = g
            elif i == 3: 
                restofline = make_restofline(g)
            i = i + 1
    else:
        print("\nNO Match on line: {}\n".format(string_in))
        failed.append(string_in)
        
        
    if timestamp not in big: 
        big[timestamp] = restofline
    else: 
        print('Timestamp already exists in database, skipping line: ', timestamp)
    

def make_timestamp(string_in): 
    """ the first few fields in a log line make up the timestamp
        discard the hostname and [UFW XXX] from those fields but
        keep the cpu timestamp as part of the return value
    """
    result = timestamp_regex.match(string_in)
    
    # there should be 5 fields, month, day, time, hostname, cpu uptime
    # if result in null, the regex didn't match

    if result and len(result.groups()) == 5 : 
        timestamp = ''
        # print('result is not none')
        i = 1
        for x in result.groups(): 
            if i != 4: # we don't want the hostname
                timestamp += '{} '.format(x)
            i += 1
    #else:
    #    print('result is none')

    timestamp = timestamp.strip()
    #print('*{}*'.format(timestamp))
    return timestamp

def make_restofline(string_in): 
    """ break out the rest of the line:
        creates key-value pairs or flags
    
        There are 3 formats for data in the line: 
            1. KEY=value - a key/value pair
            2. KEY=(nothing)- a key with no value
            3. FLAG - a flag value, doesn't follow the k=v format
    """
    restofline_dict = {}
    flags = ''
    
    for x in string_in.split(): 
    
        if re.match('\w+=.+', x):  # best case - a key and value pair
            
            (k,v) = x.split('=')
            # print('type 1 entry: ', x)
            #print('key: {}, value: "{}"'.format(k,v))
            restofline_dict[k] = v
        elif re.match('\w+=', x): # don't store these since there's no value
            #print('type 2 entry: ', x)
            pass 
        elif re.match('\w+', x): # concatenate these into a flags field
            #print('type 3 entry: ', x)
            flags += x
        else: 
            #print('no match: ', x)
            pass
    
    if flags: 
        #print('flags: ', flags)
        restofline_dict['FLAGS'] = flags
    
    
    #print('\nRest Of Line Dictionary: ', restofline_dict, '\n')
    
    return restofline_dict

def main(): 
    load_file()
    for line in log_contents: 
        accumulate(line)
    
    if big: 
        print('parsed ', len(big), 'lines')
    if failed: 
        print('failed lines count: ', len(failed))
        #print('detail: ', failed)
        
            

if __name__ == "__main__":
    print('running main')
    main()
    