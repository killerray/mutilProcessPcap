# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     utility
   Description :
   Author :       KillerRay
   date：          2019/7/12
-------------------------------------------------
   Change Activity:
                   2019/7/12:
-------------------------------------------------
"""

import platform
import os
import logging


def get_utility():
    return proc_pcap


def proc_pcap(filename,filterExp,filenum, resPath):
    try:
        (filepath, tempfilename) = os.path.split(filename)
        (realfilename, extension) = os.path.splitext(tempfilename)
        newPcapfile ='{realname}_{num}{ext}'.format(realname=realfilename,num=str(filenum),ext=extension)
        newPcapPath = os.path.join(resPath,newPcapfile)
        sysstr = platform.system()
        if (sysstr == "Windows"):
            # TsharkPath = r'D:\Wireshark\tshark.exe'
            TsharkPath = r'tshark.exe'
        else:
            TsharkPath = r'tshark'
        exeCmd ='{sharkPath} -2 -r {input} -R "{filter}" -w {output}'.format(sharkPath=TsharkPath,
                                                                           input=filename,
                                                                           filter=filterExp,
                                                                           output=newPcapPath)
        # print exeCmd
        res = os.popen(exeCmd)
        log_message='{inputfile} extract into {outputfile}'.format(inputfile=filename,
                                                                   outputfile=newPcapPath)
        logging.info(log_message)
    except Exception,e:
        log_message_error='{inputfile} process error,{error}'.format(inputfile=filename,error=e)
        logging.error(log_message_error)
    """
    else:
        log_message='{inputfile} has no {filter}'.format(inputfile=filename,
                                                         filter=filterExp)
        logging.warning(log_message)
    """
