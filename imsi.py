# IMSI Decrypter
# Author: o3t1w
# Description: This is a Python script that implements an IMSI Decrypter using the Scapy library. It listens for GSM traffic on the specified interface and extracts the IMSI and TMSI from the packets. It then stores this information in a SQLite database and displays it on the screen. The IMSI is validated to ensure that it has 15 digits and the TMSI is validated to ensure that it has between 4 and 8 hexadecimal digits. The user can also specify an IMSI to filter the output and only display data for that IMSI. The script uses the tabulate library to display the data in a table format.


import datetime
import os
import re
import sqlite3
from optparse import OptionParser
from scapy.all import *
from tabulate import tabulate

class ImsiDecrypter:
    sql_conn = None
    imsi = ""
    tmsi = ""
    mcc = ""
    mnc = ""
    lac = ""
    ci = ""
    id_ = 0
    live_db = {}

    def sql_db(self):
        self.sql_conn = sqlite3.connect(options.save)
        self.sql_conn.execute('CREATE TABLE IF NOT EXISTS imsi_data(id INTEGER PRIMARY KEY, imsi TEXT, tmsi TEXT, mcc INTEGER, mnc INTEGER, lac INTEGER, ci INTEGER, date_time timestamp)')

    def save_data(self):
        date_time = datetime.datetime.now()
        self.sql_conn.execute('INSERT INTO imsi_data(imsi, tmsi, mcc, mnc, lac, ci, date_time) VALUES (?, ?, ?, ?, ?, ?, ?)',(self.imsi, self.tmsi, self.mcc, self.mnc, self.lac, self.ci, date_time))
        self.sql_conn.commit()

    def get_data(self):
        self.cur = self.sql_conn.cursor()
        self.cur.execute('SELECT * FROM imsi_data WHERE imsi=?', (self.imsi,))
        self.data = self.cur.fetchall()

    def update_data(self, id_, tmsi):
        self.sql_conn.execute('UPDATE imsi_data SET tmsi=?, date_time=? WHERE id=?',(tmsi, datetime.datetime.now(), id_))
        self.sql_conn.commit()

    def filter_imsi(self):
        if options.save:
            self.sql_db()
            self.get_data()
            data = self.data
            if data:
                data = self.data[0]
                if(self.imsi != data[1]):
                    self.save_data()
                else:
                    if (self.tmsi != data[2]) & (self.tmsi != ''): #Check if tmsi is different than update in file db
                        self.update_data(data[0],self.tmsi)
            else:
                self.save_data()

        if self.imsi in self.live_db:
            if self.live_db[self.imsi]['tmsi'] != self.tmsi: #Check if tmsi is different than update in live db
                self.live_db[self.imsi]['tmsi'] = self.tmsi
        else:
            self.id_ += 1
            self.live_db[self.imsi] = {"id" : self.id_,"tmsi" : self.tmsi, "mcc" : self.mcc, "mnc" : self.mnc, "lac": self.lac, "ci": self.ci}
        self.output()

    def validate_imsi(self, imsi):
        pattern = re.compile("^[0-9]{15}$")
        if pattern.match(imsi):
            return True
        return False

    def validate_tmsi(self, tmsi):
        pattern = re.compile("^[0-9A-F]{4,8}$")
        if pattern.match(tmsi):
            return True
        return False

    def header(self):
        os.system('clear')
        title = '''
                          IMSI Decrypter
                     ======================

        '''
        print ("\033[0;31;48m" + title)
    def output(self):
        os.system('clear')
        headers = ["ID", "IMSI", "TMSI", "MCC", "MNC", "LAC", "CI"]
        table = []
        for imsi in self.live_db:
            data = self.live_db[imsi]
            row = [data["id"], imsi, data["tmsi"], data["mcc"], data["mnc"], data["lac"], data["ci"]]
            table.append(row)
        print(tabulate(table, headers, tablefmt="fancy_grid"))

    def get_imsi(self, packet):
        if packet.haslayer(GSM_SMS):
            gsm_sms = packet.getlayer(GSM_SMS)
            if hasattr(gsm_sms, "rpdu") and hasattr(gsm_sms.rpdu, "tpdu") and hasattr(gsm_sms.rpdu.tpdu, "tp_ud"):
                tp_ud = gsm_sms.rpdu.tpdu.tp_ud
                match = re.findall(r'\b([0-9]{15})\b', tp_ud)
                if match:
                    self.imsi = match[0]
                    self.filter_imsi()
        elif packet.haslayer(GSM_RR):
            gsm_rr = packet.getlayer(GSM_RR)
            if hasattr(gsm_rr, "channel_type"):
                if gsm_rr.channel_type == "BCCH":
                    if hasattr(gsm_rr, "cell_identity"):
                        self.ci = gsm_rr.cell_identity
                        self.lac = gsm_rr.location_area_identification
                        self.mcc = gsm_rr.mobile_country_code
                        self.mnc = gsm_rr.mobile_network_code
                elif gsm_rr.channel_type == "AGCH":
                    if hasattr(gsm_rr, "channel_description"):
                        channel_description = gsm_rr.channel_description
                        match = re.findall(r'([0-9A-F]{4,8})\b', channel_description)
                        if match:
                            self.tmsi = match[0]
                            if self.validate_tmsi(self.tmsi):
                                if options.imsi == '':
                                    self.filter_imsi()
                                elif options.imsi == self.imsi:
                                    self.filter_imsi()
    elif packet.haslayer(GSM_A_CCCH):
        gsm_a_ccch = packet.getlayer(GSM_A_CCCH)
        if hasattr(gsm_a_ccch, "channel_type"):
            if gsm_a_ccch.channel_type == "BCCH":
                if hasattr(gsm_a_ccch, "gsm_a_bssmap_cell_ci"):
                    self.ci = gsm_a_ccch.gsm_a_bssmap_cell_ci
                    self.lac = gsm_a_ccch.gsm_a_lac
                    self.mcc = gsm_a_ccch.gsm_a_bssmap_plmn_mcc
                    self.mnc = gsm_a_ccch.gsm_a_bssmap_plmn_mnc
            elif gsm_a_ccch.channel_type == "SDCCH":
                if hasattr(gsm_a_ccch, "e212.imsi"):
                    self.imsi = gsm_a_ccch.e212_imsi
                    self.tmsi = ""
                    if self.validate_imsi(self.imsi):
                        if options.imsi == '':
                            self.filter_imsi()
                        elif options.imsi == self.imsi:
                            self.filter_imsi()
                elif hasattr(gsm_a_ccch, "gsm_a_rr_tmsi_ptmsi"):
                    self.tmsi = gsm_a_ccch.gsm_a_rr_tmsi_ptmsi
                    if self.validate_tmsi(self.tmsi):
                        if options.imsi == '':
                            self.filter_imsi()
                        elif options.imsi == self.imsi:
                            self.filter_imsi()
