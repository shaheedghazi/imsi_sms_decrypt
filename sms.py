# coding: latin-1

"""
About: This program shows you sender number, receiver number, sms text, sending time of cellphones around you. The get_sms function listens to the live capture of GSM SMS packets on a specified port and interface. It then extracts relevant information like the sender, receiver, text and sending time of the SMS packet. If the options.number argument is not specified, it prints out all SMS packets captured. If it is specified, it checks if the specified number matches the sender or receiver of the SMS packet and prints it out if there is a match.

In summary, the purpose of this program is to sniff and display GSM SMS packets on a specified port and interface, and to optionally save the captured messages to an SQLite database. However, it's worth noting that the program's author has included a disclaimer that it's for educational purposes only, and should not be used for illegal activities.

Disclaimer:-
This program was made to understand how GSM network works. Not for bad hacking !
We are not responsible for any illegal activity !

About:-
Author: o3t1w
Created on : 11/5/2023
"""

import pyshark
from optparse import OptionParser
import os, sys

class SmsSniffer:

    text = ""
    sender = ""
    receiver = ""
    time = ""

    def save_data(self):
        import sqlite3
        sql_conn = sqlite3.connect(options.save)
        sql_conn.execute('CREATE TABLE IF NOT EXISTS sms_data(id INTEGER PRIMARY KEY, text TEXT, sender TEXT, receiver TEXT , date_time timestamp)')
        sql_conn.execute('INSERT INTO sms_data(text, sender, receiver, date_time) VALUES ( ?, ?, ?, ?)',(self.text, self.sender, self.receiver, self.time + " " + self.date))
        sql_conn.commit()

    def output(self):
        if options.save:
            self.save_data()
        print(" \033[0;37;48m{:7s} \033[0;31;48m; \033[0;37;48m{:12s} \033[0;31;48m; \033[0;37;48m\033[0;37;48m{:12s} \033[0;31;48m; \033[0;37;48m{:20s}".format(self.time, self.sender, self.receiver, self.text))
        print ("\033[0;31;48m................................................................................")

    def header(self):
        os.system('clear')
        title = '''
 _|_|_|    _|_|_|_|  _|_|_|      _|_|_|  _|_|_|_|    _|_|_|       
 _|    _|  _|        _|    _|  _|        _|        _|           \`~'/     
 _|    _|  _|_|_|    _| CODED BY: o3t1w _|_|_|    _|           (o o)  
 _|    _|  _|        _|    _|        _|  _|        _|            \ / \ 
 _|_|_|    _|_|_|_|  _|_|_|    _|_|_|    _|_|_|_|    _|_|_|       " 
	               MOBILE PHONE SNIFFING TOOL     '''
        print ("\033[0;31;48m" + title)
        print ("................................................................................")
        print("\033[0;37;48m  Time   \033[0;31;48m;    \033[0;37;48mSender    \033[0;31;48m;   \033[0;37;48mReceiver   \033[0;31;48m;                  \033[0;37;48mText                  ")
        print ("\033[0;31;48m................................................................................")

    def get_sms(self, capture):
        for packet in capture:
            layer = packet.highest_layer
            if (layer == "GSM_SMS"):
                gsm_sms = packet.gsm_sms
                if hasattr(gsm_sms, 'sms_text'):
                    self.time = packet.gsm_sms.scts_hour + ":" + packet.gsm_sms.scts_minutes + ":" + packet.gsm_sms.scts_seconds
                    self.date = packet.gsm_sms.scts_day + "/" + packet.gsm_sms.scts_month + "/" + packet.gsm_sms.scts_year
                    self.sender = packet.gsm_sms.tp_oa
                    self.receiver = packet[6].gsm_a_dtap_cld_party_bcd_num
                    self.text = packet.gsm_sms.sms_text
                    if options.number == "":
                        self.output()
                    elif options.number == self.sender:
                        self.output()
                    elif options.number == self.receiver:
                        self.output()
