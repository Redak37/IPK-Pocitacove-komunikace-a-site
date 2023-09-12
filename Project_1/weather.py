#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on 16.2.2019

@author Radek Duchoň
"""
import sys
import socket
import json

def error_msg(string = "", code = 1):
    """
    Function for formated print of help when error occured and exit program unsuccesfully
    Args:   string - string with information about error
            code - exiting error code
    """
    print('Error:', string, '\nRun in shape:\nmake run api_key="api_key" city="city"')
    sys.exit(code)

def data_get(host, url, port = 80):
    """
    Function to get JSON data from server
    Args:   host - website with wanted data
            url - next part of url adress
            port - port to connect, implicitly 80
    return received JSON data in utf-8
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    s.sendall(bytes('GET ' + url + 'HTTP/1.1\r\nHost: ' + host + '\r\n\r\n', 'utf-8'))
    return s.recv(1024).decode('utf-8')

    """
    Function to print formated string if there is value to print
    Args:   data - dict with data
            key - under which key should be the value in data searched
            before - string before message 
            after - string after message
    """
def my_print(data, key, before = '', after = ''):
    if key in data:
        print(before + str(data[key]) + after)

def data_process(data):
    """
    Function to process and print ofrmated data from server
    Args:   data - dict with data to process
    """
    if 'message' in data:
        error_msg(data['message'])

    my_print(data, 'name')
    my_print(inside(data, 'weather'), 'description')
    if 'temp' in inside(data, 'main'):
        temp = inside(data, 'main')['temp'] - 273.15
        print('temp:', '{0:.1f}'.format(temp) + '°C')

    my_print(inside(data, 'main'), 'humidity', 'humidity: ', '%')
    my_print(inside(data, 'main'), 'pressure', 'pressure: ', 'hPa')
    if 'speed' in inside(data, 'wind'):
        speed = inside(data, 'wind')['speed'] * 3.6
        print('wind-speed:', '{0:.1f}'.format(speed) + 'km/h')

    my_print(inside(data, 'wind'), 'deg', 'wind-deg: ')

def inside(data, key):
    """
    Function gettig data from dict or list in dict
    Args:   data - dict with data
            key - key to search
    return data if key is in data. Otherwise return empty dict.
    """
    if key in data:
        if isinstance(data[key], (list,)):
            return data[key][0]
        else:
            return data[key]
    return {}


"""
Main body of program processing data from api.openweathermap.org
"""
if len(sys.argv) is not 3:
    error_msg('Missing arguments.')


url = '/data/2.5/weather?q=' + sys.argv[2] + '&APPID=' + sys.argv[1] + '&units=metric' 
data = json.loads(data_get('api.openweathermap.org', url))
data_process(data)
