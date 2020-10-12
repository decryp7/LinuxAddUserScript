#!/usr/bin/env python
import sys
import getopt
import os
import crypt
from optparse import OptionParser
import shutil
import fcntl
import re
import datetime

class fileFormatError(Exception) : pass
class entryFormatError(Exception) : pass
class formatError(Exception): pass
class argError(Exception) : pass
class fileError(Exception): pass
class notImplementedError(Exception) : pass

class fileBase:
    regExpr = ''
    fileType = 'base'
    
    def __init__(self, filePath):
        #get the file
        self.filePath = filePath
        self.fileObj = self.getFile('r') #get file in read mode
        self.lockFile() #lock file

    #cleanup routine
    def cleanUp(self):
        os.remove(self.filePath + '.backup')
    
    #backup routine
    def backupFile(self):
        self.backupFile = open(self.filePath + '.backup', 'w')
        listlines = self.getLines()
        self.backupFile.writelines(listlines)
    
    #undo routine
    def undo(self):
        self.backupFile = open(self.filePath + '.backup', 'r')
        self.backupFile.seek(0)
        listlines = self.backupFile.readlines()
        self.unLockFile()
        self.fileObj = self.getFile('w')
        self.lockFile()
        self.fileObj.writelines(listlines)
        #get file in read mode
        self.unLockFile()
        self.fileObj = self.getFile('r')
        self.lockFile()
    
    #get the file
    def getFile(self, mode='r'): #default to read mode
        #check whether the file exist and is a file not a dir
        if os.path.exists(self.filePath) and os.path.isfile(self.filePath):
            openedFile = open(self.filePath, mode)
            return openedFile
        else:
            raise fileError, 'File does not exist or is not a file'

    #check the string against a regular expression, throws a formatError exception if it doesn't match
    def checkLineWithRE(self, line):
        p = re.compile(self.regExpr)
        m = p.match(line)
        if m is not None:
            return m.group()
        else:
            raise formatError, 'Line not in correct format'

    #lock the file excusively to prevent ppl from accessing it
    def lockFile(self):
        #lock the file
        try:
            fcntl.flock(self.fileObj, fcntl.LOCK_EX)
        except IOError:
            raise fileError, 'Cannot obtain a lock on %s. Please make sure no other process is accessing it' % filePath
    
    #unlock the file 
    def unLockFile(self):
        #lock the file
        try:
            fcntl.flock(self.fileObj, fcntl.LOCK_UN)
        except IOError:
            raise fileError, 'Cannot remove lock on %s. Please make sure no other process is accessing it' % filePath
    
    #get all the content from the file
    def getLines(self):
        #get all the lines of the file
        self.fileObj.seek(0) #reset position
        return self.fileObj.readlines()
    
    #check whether the content of the file conforms to a certain format
    def checkFileFormat(self): #check file format
        lineList = self.getLines()
        lineCount = 0
        try: 
            for line in lineList:
                lineCount = lineCount+1 #line count to tell user which line is in the wrong format
                if line != '\n': #empty line
                    self.checkLineWithRE(line)
        except formatError:
            raise fileFormatError, '%s (%s) not in correct format. Check Line %s' % (self.fileType, self.filePath, lineCount)
    
    #append a string to end of the file
    def appendLine(self,line):
        lineList = self.getLines()  
        lastLine = lineList[len(lineList)-1]     
        if lastLine == '\n':
            lineList[len(lineList)-1] = line
        elif lastLine.endswith('\n'):
            lineList.append(line)
        else:
            lineList.append('\n' + line)
        #print lineList
        #get file in write mode
        self.unLockFile()
        self.fileObj = self.getFile('w')
        self.lockFile()
        self.fileObj.writelines(lineList)
        #get file in read mode
        self.unLockFile()
        self.fileObj = self.getFile('r')
        self.lockFile()
    
    #replace the whole file
    def replace(self, lineList):
        #get file in write mode
        self.unLockFile()
        self.fileObj = self.getFile('w')
        self.lockFile()
        self.fileObj.writelines(lineList)
        #get file in read mode
        self.unLockFile()
        self.fileObj = self.getFile('r')
        self.lockFile()

#shdwFile class loads, verify and control the Shadow File
class shdwFile(fileBase): 
    def __init__(self, filePath):
        fileBase.__init__(self, filePath)
        self.regExpr = '^[A-Za-z0-9-]+(:)[A-Za-z0-9-!.*/\$]+(:[0-9]*)*$'
        self.fileType = 'Shadow File'
        #Check file is a shadow file
        self.checkFileFormat()
        self.backupFile()
    
    #ensure that the entry u are appending to the file is in the correct format
    def checkShadowEntryValid(self, shdwEntry):
        try:
            self.checkLineWithRE(shdwEntry, self.regExpr)
            return True
        except formatError:
            return False

#grpFile class loads, verify and control the Group File
class grpFile(fileBase): 
    def __init__(self, filePath):
        fileBase.__init__(self, filePath)
        self.regExpr = '^[A-Za-z0-9-_]+(:x:)[0-9]+:[A-Za-z0-9-,]*$'
        self.fileType = 'Group File'
        #check file is a group file
        self.checkFileFormat()
        self.backupFile()
        self.generateGroupIDs()
    
    #create a groupIDs dictionary for use later
    def generateGroupIDs(self):
        #cdrom:x:24:vivek,student13,raj
        lineList = self.getLines()
        self.groupids = {}
        for line in lineList:
            splitString = line.split(':')
            if len(splitString) >= 4:
                self.groupids[splitString[2]] = line.replace('\n','')
    
    #ensure the group id exist in the group file
    def checkGroupIDExist(self, groupID):
        if groupID in self.groupids:
            return True
        else:
            return False
        
    #add a new user to the group
    def addUserToGroup(self, groupID, username):
        self.groupids[groupID] = self.groupids[groupID] + ',' + username
        
    #get the new group list
    def getNewGroupList(self):
        linelist = []
        for groupentry in self.groupids.values():
            linelist.append(groupentry+'\n')
        return linelist
    
#pwdFile class loads, verify and control the password file
class pwdFile(fileBase): 
    def __init__(self, filePath):
        fileBase.__init__(self, filePath)
        self.regExpr = '^[A-Za-z0-9-]+(:x:)[0-9]+(:)[0-9]+(:)[A-Za-z0-9-\s(),]*(:)[A-Za-z0-9-/]+(:)[A-Za-z0-9-/]+$'
        self.fileType = 'Password File'
        #check file is a password file
        self.checkFileFormat()
        self.backupFile()
        self.generateDetails()
        
    #create a list of details
    def generateDetails(self):
        #smithj:x:561:561:Joe Smith:/home/smithj:/bin/
        lineList = self.getLines()
        self.userids = []
        self.users = []
        self.homepaths = []
        self.shellpaths = []
        for line in lineList:
            splitString = line.split(':')
            if len(splitString) >= 6:
                self.userids.append(splitString[2])
                self.users.append(splitString[0])
                self.homepaths.append(splitString[5])
                self.shellpaths.append(splitString[6])
    
    #check whether user exist in the password file
    def checkUserAlreadyExist(self, username):
        if username in self.users:
            return True
        else:
            return False
    
    #check whether user id is in the reserved range
    def checkUserIDNotInReservedRange(self, userid):
        try:
            if int(userid) > 999:
                return True
            else:
                return False
        except Exception:
            return False
    
    #check whether user id already exist
    def checkUserIDAlreadyExist(self, userid):
        if userid in self.userids:
            return True
        else:
            return False
    
    #check whether the home path is already taken or is already created
    def checkHomePathAlreadyTaken(self, homepath):
        if homepath in self.homepaths:
            return True
        else:
            if os.path.exists(homepath):
                return True
            return False
        
    #check whether that the shell path is a valid file
    def checkShellPathValid(self, shellpath):
        if os.path.exists(shellpath) and os.path.isfile(shellpath):
            return True
        else:
            return False
    
    #check whether the password file new entry is of the correct format
    def checkPwdEntryValid(self, pwdEntry):
        try:
            self.checkLineWithRE(pwdEntry, self.regExpr)
            return True
        except formatError:
            return False
        
username = 'username'
userid = 'userid'
groupid = 'groupid'
homepath = 'homepath'
shellpath = 'shellpath'

#decide what to do
def decide(opts):
    global pwdFileObj
    global shdwFileObj
    global grpFileObj
    
    # these options must be specified
    if opts.password_file is None or opts.shadow_file is None or opts.group_file is None:
        print 'You must use with -P -S -G. For more details, use -h.'
    
    #checking files in the correct format
    if opts.password_file is not None:
        pwdFileObj = pwdFile(opts.password_file)
        
    if opts.shadow_file is not None:
        shdwFileObj = shdwFile(opts.shadow_file)
    
    if opts.group_file is not None:
        grpFileObj = grpFile(opts.group_file)
            
    if opts.password_file_entry is not None and opts.shadow_file_entry is not None:
        checkNewPasswordEntry(opts.password_file_entry)
        checkNewShadowEntry(opts.shadow_file_entry)
        savePwdEntryAndShdwEntry(opts.password_file_entry, opts.shadow_file_entry)
    elif opts.password_file_entry is not None and opts.shadow_file_entry is None:
        print 'You must use BOTH -p and -s(missing).'
    elif opts.password_file_entry is None and opts.shadow_file_entry is not None:
        print 'You must use BOTH -s and -p(missing).'
    else:
        promptUser()

#save the new password entry and shadow entry that are specified using -p -s
#also contain logics to check validity of both parameters
def savePwdEntryAndShdwEntry(pwdentry, shdwentry):
    pwdEntryDetails = getDetailsFromPwdEntry(pwdentry)
    shdwEntryDetails = getDetailsFromShdwEntry(shdwentry)
    errMsg = 'Password file entry (%s:\'%s\') does not match shadow file entry (%s:\'%s\')'
    
    if pwdEntryDetails[username] != shdwEntryDetails[username]:
        raise argError, errMsg % ('Username', pwdEntryDetails[username], 'Username', shdwEntryDetails[username])
    
    if pwdFileObj.checkUserAlreadyExist(pwdEntryDetails[username]) == True:
        raise argError, '%s already exist. Please use another username.' % pwdEntryDetails[username]
    
    if pwdFileObj.checkUserIDNotInReservedRange(pwdEntryDetails[userid]) != True:
        raise argError, '%s UserID in reserved range. Please use another userid (>999).' % pwdEntryDetails[userid]
    
    if pwdFileObj.checkUserIDAlreadyExist(pwdEntryDetails[userid]) == True:
        raise argError, '%s UserID already exist. Please use another userid.' % pwdEntryDetails[userid]
    
    if grpFileObj.checkGroupIDExist(pwdEntryDetails[groupid]) != True:
        raise argError, '%s is not a valid groupid. Valid Groupids: %s' % (pwdEntryDetails[groupid], str(grpFileObj.groupids.keys()))

    if pwdFileObj.checkHomePathAlreadyTaken(pwdEntryDetails[homepath]) == True:
        raise argError, '%s cannot be used as homepath. Please specify another homepath.' % pwdEntryDetails[homepath]
    
    if pwdFileObj.checkShellPathValid(pwdEntryDetails[shellpath]) != True:
        raise argError, '%s is an invalid shellpath. Please specify a correct shellpath.' % pwdEntryDetails[shellpath]
    
    pwdFileObj.appendLine(pwdentry)
    shdwFileObj.appendLine(shdwentry)
    grpFileObj.addUserToGroup(pwdEntryDetails[groupid], pwdEntryDetails[username])
    grpFileObj.replace(grpFileObj.getNewGroupList())
    makeDirectory(pwdEntryDetails[homepath], pwdEntryDetails[userid])

#make dir
def makeDirectory(path, owneruid):
    try:
        os.makedirs(path)
        os.chown(path, int(owneruid), -1)
    except OSError:
        raise argError, 'Cannot create home directory. You may want to run this script as root.'
    

#ensure that the new password entry is of the correct format
def checkNewPasswordEntry(pwdentry):
    try:
        pwdFileObj.checkLineWithRE(pwdentry)
    except formatError:
        raise formatError, '-p argument (%s) is not in the correct format.' % pwdentry

#divide the password entry into a easier to use format
def getDetailsFromPwdEntry(pwdEntry):
    #smithj:x:561:561:Joe Smith:/home/smithj:/bin/
    details = {}
    splitString = pwdEntry.split(':')
    details[username] = splitString[0]
    details[userid] = splitString[2]
    details[groupid] = splitString[3]
    details[homepath] = splitString[5]
    details[shellpath] = splitString[6]
    return details

#divide the shadow entry into a easier to use format
def getDetailsFromShdwEntry(shdwEntry):
    #jobs:jk1h23kjh12kj3h12kj3h:123:0:0:0:0:0:0:0
    details = {}
    splitString = shdwEntry.split(':')
    details[username] = splitString[0]
    details[groupid] = splitString[3]
    return details

#ensure the new shadow entry is of the correct format
def checkNewShadowEntry(shdwentry):
    try:
        shdwFileObj.checkLineWithRE(shdwentry)
    except formatError:
        raise formatError, '-p argument (%s) is not in the correct format.' % shdwentry

#prompt user if he did not specify -p and -s
def promptUser():
    username = promptUsername()
    password = promptPassword()
    userid = promptUserID()
    groupid = promptGroupID()
    #print 'Username: %s Password: %s Userid: %s Groupid: %s' % (username, crypt.crypt(password, 'test'), userid, groupid)
    #smithj:x:561:561:Joe Smith:/home/smithj:/bin/
    pwdentry = '%s:x:%s:%s:%s:/home/%s:/bin/bash' % (username, userid, groupid, username, username)
    #jobs:jk1h23kjh12kj3h12kj3h:123:0:0:0:0:0:0:0
    shdwentry = '%s:%s:%s:0:0:0:0:0:0' % (username, crypt.crypt(password, 'test'), calculatePasswordAge())
    pwdFileObj.appendLine(pwdentry)
    shdwFileObj.appendLine(shdwentry)
    grpFileObj.addUserToGroup(groupid, username)
    grpFileObj.replace(grpFileObj.getNewGroupList())
    makeDirectory('/home/'+username, userid)

#calculate days since Jan 1,1970 that the password was last changed
def calculatePasswordAge():
    startDate = datetime.date(1970, 1, 1)
    dateDiff = datetime.date.today() - startDate
    return dateDiff.days

#undo all operations
def undo():
    if globals().has_key('pwdFileObj'):
        pwdFileObj.undo()
    if globals().has_key('shdwFileObj'):
        shdwFileObj.undo()
    if globals().has_key('grpFileObj'):
        grpFileObj.undo()
    print 'No changes made.'
    
#cleanup
def cleanUp():
    if globals().has_key('pwdFileObj'):
        pwdFileObj.cleanUp()
    if globals().has_key('shdwFileObj'):
        shdwFileObj.cleanUp()
    if globals().has_key('grpFileObj'):
        grpFileObj.cleanUp()

#ensure the string conforms to a certain format
def checkStringFormat(regrExp, string):
        p = re.compile(regrExp)
        m = p.match(string)
        if m is not None:
            return True
        else:
            return False
        
#prompt for password and check its validity
def promptPassword():
    password = raw_input('Enter Password: ')
    return password

#prompt for username and check its validity
def promptUsername():
    username = raw_input('Enter Username: ')
    if checkStringFormat('(?=^[A-Za-z0-9]+$).{3,8}', username) != True:
        print 'Please enter a username with length 3 - 8 with NO symbols.'
        username = promptUsername()
    
    if pwdFileObj.checkUserAlreadyExist(username) == True:
        print 'User already exist. Please use another username.'
        username = promptUsername()
    
    return username

#prompt for groupid and check its validity
def promptGroupID():
    groupid = raw_input('Enter Groupid: ')
    if checkStringFormat('^[0-9]+$', groupid) != True:
        print 'Please enter a groupid in digits only.'
        groupid = promptGroupID()
    
    if grpFileObj.checkGroupIDExist(groupid) != True:
        print 'Please enter a valid groupid.'
        print 'Valid Groupids: ' + str(grpFileObj.groupids.keys())
        groupid = promptGroupID()
        
    return groupid

#prompt for userid and check its validity
def promptUserID():
    userid = raw_input('Enter Userid: ')
    if checkStringFormat('^[0-9]+$', userid) != True:
        print 'Please enter a userid in digits only.'
        userid = promptUserID()
    
    if pwdFileObj.checkUserIDNotInReservedRange(userid) != True:
        print 'UserID in reserved range. Please use another userid (>999).'
        userid = promptUserID()
    
    if pwdFileObj.checkUserIDAlreadyExist(userid) == True:
        print 'UserID already exist. Please use another userid.'
        userid = promptUserID()
    
    return userid

#define all the valid options for optionParser
def processArguments():
    #-P name of password file to update
    #-S name of shadow file to update
    #-G group file to consult
    #-p specify new entry to be added to password file
    #-s specify the entry to be added to the shadow password file
    myParser = OptionParser()
    myParser.add_option("-P", "--pwdfile", action="store", dest="password_file", help="Password file")
    myParser.add_option("-S", "--shadowfile", action="store", dest="shadow_file", help="Shadow file")
    myParser.add_option("-G", "--groupfile", action="store", dest="group_file", help="Group file")
    myParser.add_option("-p", "--pwdentry", action="store", dest="password_file_entry", help="Entry to be added to password file")
    myParser.add_option("-s", "--shadowentry", action="store", dest="shadow_file_entry", help="Entry to be added to shadow file")
    myParser.set_usage("%prog [-PSGps]")
    return myParser.parse_args()

def main():
    try:
        #Use better parser, OptionParser
        #opts, args = getopt.getopt(sys.argv[1:], "P:S:G:psh")
        opts, args = processArguments()
        decide(opts)
    except KeyboardInterrupt:
        #Ctrl-C
        undo()
    except Exception, err:
        #undo
        print str('Error has occurred : %s' % err)
        undo()
    finally:
        cleanUp()
    
if __name__ == "__main__":
    main()
