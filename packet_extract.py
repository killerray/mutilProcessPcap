# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     process_pcap
   Description :
   Author :       KillerRay
   date：          2019/7/1
-------------------------------------------------
   Change Activity:
                   2019/7/1:
-------------------------------------------------
"""
import os
import logging
from multiprocessing import Pool
import time
import sys
import utility


class PacketExtract:
    pcapFileExtensions = ['.pcap', 'pcapng', 'cap']

    def __init__(self, inputDir, process_num,func):
        self.func = func
        self.pcapFilePathList = []
        self.create_file_list(inputDir)
        self.processNum = process_num
        log_message = '{processNum} process need to process {filenum} pcaps'.format(processNum=self.processNum,
                                                                                    filenum=str(len(self.pcapFilePathList)))
        logging.info(log_message)

        pass

    def create_file_list(self, inputDir):
        if os.path.isfile(inputDir):
            if self.judge_file_extensions(inputDir):
                self.pcapFilePathList.append(inputDir)
        elif os.path.isdir(inputDir):
            for s in os.listdir(inputDir):
                newdir = os.path.join(inputDir, s)
                self.create_file_list(newdir)

    @staticmethod
    def judge_file_extensions(filename):
        if os.path.splitext(filename)[-1] in PacketExtract.pcapFileExtensions:
            return True
        else:
            return False

    def fetch_info(self, filterExp, resPath):
        fileindex_list = list(range(len(self.pcapFilePathList)))
        fileindex_groupList = [fileindex_list[i:i + self.processNum] for i in range(0, len(fileindex_list), self.processNum)]
        for filegroup in fileindex_groupList:
            # print filegroup
            self.multi_process(filegroup, filterExp, self.func,resPath)

    def multi_process(self,filegroup,filterExp,func,resPath):
        p = Pool(len(filegroup))
        for i in range(len(filegroup)):
            p.apply_async(func, args=(self.pcapFilePathList[filegroup[i]], filterExp, filegroup[i], resPath))
        p.close()
        p.join()

    @staticmethod
    def mkdir(resPath):
        folder = os.path.exists(resPath)
        if not folder:  # 判断是否存在文件夹如果不存在则创建为文件夹
            os.makedirs(resPath)  # makedirs 创建文件时如果路径不存在会创建这个路径
            logging.info('Create dir: {dirpPath}'.format(dirpPath=resPath))
            return resPath
        else:
            prefix = str(int(time.time()))
            newresPath = resPath+prefix
            os.makedirs(newresPath)
            logging.info('{oldPath} already existed, create dir:{newPath}'.format(oldPath=resPath, newPath=newresPath))
            return newresPath


logging.basicConfig(level=logging.INFO,
                            format='%(asctime)s %(levelname)s %(message)s',
                            datefmt='%a,%d/%b/%Y-%H:%M:%S',
                            filename=os.path.join(os.path.split(os.path.realpath(__file__))[0], 'log.txt'),
                            filemode='a+')

def main():
    if len(sys.argv) != 4:
        print 'sys.argv[1]:pcapFilePath'
        print 'sys.argv[2]:process num'
        print 'sys.argv[3]:tshark filter Exp'
        exit(1)
    else:
        pe = PacketExtract(sys.argv[1], int(sys.argv[2]), utility.get_utility())
        resPath = PacketExtract.mkdir(os.path.join(os.path.split(os.path.realpath(__file__))[0], 'resultPath'))
        pe.fetch_info(sys.argv[3], resPath)

        '''
        try:
            sysstr = platform.system()
            if (sysstr == "Windows"):
                MergecapPath = r'D:\Wireshark\mergecap.exe'
            else:
                MergecapPath = r'mergecap'
            writer = os.path.join(os.path.split(os.path.realpath(__file__))[0], 'mergefile.pcap')

            mergecapCmd = r'{Cmd} -w {writer} {resPath}'.format(Cmd=MergecapPath,
                                                              writer=writer,
                                                               resPath=os.path.join(resPath,'*.pcap'))
            p=os.popen(mergecapCmd)
            print mergecapCmd
            log_message = 'merge pcap from {resPath}'.format(resPath=resPath)
            logging.info(log_message)
        except Exception,e:
            log_message = 'merge pcap wrong, {error}'.format(error=e)
            logging.info(log_message)
        '''


if __name__ == '__main__':
    main()





