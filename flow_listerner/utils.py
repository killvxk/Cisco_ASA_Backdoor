#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2017/9/5 16:40
# @Author  : weizinan
# @File    : utils.py

import logging

def init_logger(loggerName, logLevel):
    #创建日志记录
    logger = logging.getLogger(loggerName)
    logger.setLevel(logLevel)

    logFormatter = logging.Formatter('[%(asctime)s] [%(levelname)s] -> %(message)s')
    consoleHandler = logging.StreamHandler()
    consoleHandler.setFormatter(logFormatter)
    consoleHandler.setLevel(logLevel)
    logger.addHandler(consoleHandler)

    return logger

gl_Logger = init_logger("Logger", logging.INFO)