# !/usr/bin/python3
import time
import os
import argparse
import logging
from disassembler_analysis import APK_Analysis

parser = argparse.ArgumentParser()
parser.add_argument('--source_folder','-s', type=str, default="F:/Study/510/APK_BaseInfo/Test_APK/",
        help='APK source path')
parser.add_argument('--result_folder','-r', type=str, default="F:/Study/510/APK_BaseInfo/analysis/",
        help='Result save path')
parser.add_argument('--log_folder','-l', type=str, default="F:/Study/510/APK_BaseInfo/analysis/",
        help="Log save path")


class APKAnalysis():
    def __init__(self,logger):
        self.logger = logger


    # 主分析函数
    def MainAnalysis(self,srcfolder,savefolder):
        Files = self.eachFile(srcfolder)
        for eachfile in Files:
            try:
                print("start analysis:",eachfile)
                self.logger.info("start analysis:" + eachfile)
                filename_base = eachfile.split('/')[-1].split('.')[0]
                apk_name,deal_msg = self.BaseInfo_Extra(eachfile,savefolder)
                print(apk_name,':',deal_msg)
                self.logger.info(apk_name + ':' + deal_msg)
            except Exception:
                print(Exception)
                logger.error(eachfile + " Faild to analysis from logger.error",exc_info = True)
        self.logger.info("Finish")


    def eachFile(self,folder):
        child=[]
        pathDir =  os.listdir(folder)
        for allDir in pathDir:
            child.append(os.path.join('%s%s' % (folder, allDir)))
        return child

    # 对APK文件初步分析，函数嵌入
    def BaseInfo_Extra(self,filepath,savefolder):
        AnalysisHandle = APK_Analysis()
        apk_name,deal_msg = AnalysisHandle.AnalysisStart(filepath,savefolder)
        return apk_name,deal_msg

def Path_Format(path):
    if path.find('\\') != -1:
        path.replace('\\','/')
    if path[-1] != '/':
        path += '/'
    return path


if __name__ == "__main__":
    args = parser.parse_args()
    print("="*20)
    print(args)
    print("="*20)

    File_folder = args.source_folder
    Save_folder = args.result_folder
    Log_folder = args.log_folder

    File_folder = Path_Format(File_folder)
    Save_folder = Path_Format(Save_folder)
    Log_folder = Path_Format(Log_folder)

    # create logger
    logger_name = "APKAnalysis"
    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.DEBUG)

    # create file handler
    log_path = Log_folder + 'log.txt'
    fh = logging.FileHandler(log_path,encoding='utf-8')
    fh.setLevel(logging.DEBUG)

    # create formatter
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    # add handler and formatter to logger
    fh.setFormatter(formatter)
    logger.addHandler(fh)

    try:
        DOAPK_Analysis = APKAnalysis(logger)
        DOAPK_Analysis.MainAnalysis(File_folder,Save_folder)
    except Exception:
        print(Exception)
        logger.error("Faild to do APKAnalysis from logger.error",exc_info = True)

