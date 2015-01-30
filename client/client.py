import io
import mimetypes
import os
import string
import sys
import urllib, urllib2
import base64
import getpass

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from wrapper import Wrapper
import requests

import cipherModule
import decipherModule
import bcrypt
import pbkdf2
from hashlib import sha1
import hmac
import rsa
import sys
import PyKCS11

import textwrap

os.environ["PYKCS11LIB"] = "/usr/local/lib/libpteidpkcs11.so"

class Client(object):
    '''
        client constructor
    '''

    userName = ""
    userID = ""
    RSApassphrase = ""
    RSAKeyFileName = ""
    RSAkey = None
    sessionKey = None
    loginb = 0

    def __init__(self):

        if os.path.isfile("config.cfg") == True:
            try:
                configFile = open("config.cfg", 'r')

                self.userName = configFile.readline()[:-1]
                self.userID = self.userName

                self.RSApassphrase = getpass.getpass("Password: ")

                self.RSAKeyFileName = configFile.readline()[:-1]

                configFile.close()

                self.RSAkey = cipherModule.getRSAKey(self.RSAKeyFileName, self.RSApassphrase)
            except:
                print "Your password might be wrong or your config file corrupted"
                sys.exit()

        if os.path.isfile("config.cfg") == False:
            #generate init file
            configFile = open("config.cfg", 'w')

            #username
            userName = raw_input("Choose a username: ")
            self.userName = userName
            configFile.write(self.userName+"\n")
            self.userID = self.userName

            #passphrase
            passphrase = getpass.getpass("Choose a password: ")
            self.RSApassphrase = passphrase

            #RSA key file name
            self.RSAKeyFileName = 'RSAkey.pem'
            configFile.write(self.RSAKeyFileName+"\n")

            configFile.close()

            cipherModule.generateAndWriteRSAKey( self.RSAKeyFileName, self.RSApassphrase )
            self.RSAkey = cipherModule.getRSAKey(self.RSAKeyFileName, self.RSApassphrase)
            self.newUser()


        


    '''
        WORKING
        register the user in the db
    '''
    def newUser(self):

        pubk = self.exportRSAPublicKey()
        salt = bcrypt.gensalt()
        (ccmodulus, ccexponent) = self.CCgetExponentAndModulus()
        dealer = Wrapper()
        dealer.login()
        bi = dealer.getBI()
        dealer.logout()

        serverPubKey = requests.get("http://localhost:3030/getServerPublicRSAKey")
        

        if serverPubKey.content == '':
            print 'No server public key'
            return

        serverPubKey = RSA.importKey( base64.urlsafe_b64decode(serverPubKey.content))
        
        hashed = self.hashNsalt(self.RSApassphrase, salt)
        hashed = cipherModule.processObjectRSA(hashed, serverPubKey)
        hashed = base64.urlsafe_b64encode(hashed)

        requests.get("http://localhost:3030/addUser?userID=" + self.userName +'&userBI='+ bi +'&pubKey=' + pubk + '&passwordHS=' + hashed + '&salt=' + salt + '&ccmodulus=' + ccmodulus + '&ccexponent=' + ccexponent, verify = False)

    def loginPassword(self):
        self.RSApassphrase = getpass.getpass("User " + self.userName + '\nPassword: ')

        if self.verifyPassword() == True:
            print 'User Authenticated!'
            self.getSessionKey()
            self.loginb = 1
        else:
            print 'User not authenticated!'
            self.loginb = 0

    def loginCC(self):
        r = requests.get("http://localhost:3030/getCCChallenge?userID="+self.userName)
        challenge = (r.content)

        dealer = Wrapper()
        dealer.login()
        certChain = dealer.getCertificateChain()
        challengeSigned = dealer.sign(challenge.decode('hex'))
        dealer.logout()
        
        certChain = ';;:.:;;'.join(certChain)
        certChain = base64.urlsafe_b64encode(certChain)

        response = requests.get("http://localhost:3030/authenticateCC?challengeSigned=" + challengeSigned + '&userID=' + self.userName + '&certChain=' + certChain)
        if response.content == '1':
            print 'User Authenticated!' 
            self.getSessionKey()
            self.loginb = 1
        else:
            print 'User not Authenticated!'
            self.loginb = 0

    def CCsign(self, toSign = None):
        if toSign == None:
            print "CCsign - missing toSign"
            return
        pkcs11 = PyKCS11.PyKCS11Lib()
        pkcs11.load()
        slots = pkcs11.getSlotList()
        session = pkcs11.openSession(slots[0])
        objects = session.findObjects()

        all_attributes = PyKCS11.CKA.keys()
        all_attributes.remove(PyKCS11.CKA_PRIVATE_EXPONENT)
        all_attributes.remove(PyKCS11.CKA_PRIME_1)
        all_attributes.remove(PyKCS11.CKA_PRIME_2)
        all_attributes.remove(PyKCS11.CKA_EXPONENT_1)
        all_attributes.remove(PyKCS11.CKA_EXPONENT_2)
        all_attributes.remove(PyKCS11.CKA_COEFFICIENT)
        all_attributes = [e for e in all_attributes if isinstance(e, int)]

        for o in objects:
            attributesPrivateKey = session.getAttributeValue(o, all_attributes)
            attrDictPrivateKey = dict(zip(all_attributes, attributesPrivateKey))
            if attrDictPrivateKey[PyKCS11.CKA_CLASS] == PyKCS11.CKO_PRIVATE_KEY and attrDictPrivateKey[PyKCS11.CKA_LABEL] == 'CITIZEN AUTHENTICATION KEY':
                mech = PyKCS11.Mechanism(PyKCS11.CKM_SHA1_RSA_PKCS, "")
                signature = session.sign(o, toSign, mech)
                #print signature
                s = ''.join(chr(c) for c in signature).encode('hex')
                break
        session.closeSession()
        return s

    def CCgetExponentAndModulus(self):
        pkcs11 = PyKCS11.PyKCS11Lib()
        pkcs11.load()
        slots = pkcs11.getSlotList()
        session = pkcs11.openSession(slots[0])
        objects = session.findObjects()

        all_attributes = PyKCS11.CKA.keys()
        all_attributes.remove(PyKCS11.CKA_PRIVATE_EXPONENT)
        all_attributes.remove(PyKCS11.CKA_PRIME_1)
        all_attributes.remove(PyKCS11.CKA_PRIME_2)
        all_attributes.remove(PyKCS11.CKA_EXPONENT_1)
        all_attributes.remove(PyKCS11.CKA_EXPONENT_2)
        all_attributes.remove(PyKCS11.CKA_COEFFICIENT)
        all_attributes = [e for e in all_attributes if isinstance(e, int)]

        for o in objects:
            attributesPublicKey = session.getAttributeValue(o, all_attributes)
            attributesDictPublicKey = dict(zip(all_attributes, attributesPublicKey))
            if attributesDictPublicKey[PyKCS11.CKA_CLASS] == PyKCS11.CKO_PUBLIC_KEY and attributesDictPublicKey[PyKCS11.CKA_LABEL] == 'CITIZEN AUTHENTICATION CERTIFICATE':
                m = attributesDictPublicKey[PyKCS11.CKA_MODULUS]
                e = attributesDictPublicKey[PyKCS11.CKA_PUBLIC_EXPONENT]
                if m and e:
                    mx = ''
                    ex = ''
                    for c in m:
                        mx += chr(c).encode('hex')
                    for c in e:
                        ex += chr(c).encode('hex')
                    break
        session.closeSession()
        return (mx, ex)

    def getSessionKey(self):
        r = requests.get("http://localhost:3030/generateSessionKey?userID=" + self.userName, verify = False)
        cipher = PKCS1_OAEP.new(self.RSAkey)
        self.sessionKey = cipher.decrypt(r.content)

    def hashArgs(self, args = None):
        if args == None:
            print 'hashArgs - missing args'
            return


        string = ''

        for a in args:
            string += str(a)


        hashed = hmac.new(self.sessionKey, string, sha1)
        hashClient = hashed.digest().encode("hex").rstrip('\n')

        #print hashClient

        return hashClient

    def hashNsalt(self, password = None, salt = None):
        if password == None:
            print 'saltnhash - missing password'
            return

        hashed = pbkdf2.pbkdf2_hex(password, salt)

        return hashed

    def verifyPassword(self):

        userID = self.userName
        password = self.RSApassphrase

        serverPubKey = requests.get("http://localhost:3030/getServerPublicRSAKey")
        

        if serverPubKey.content == '':
            print 'No server public key'
            return

        serverPubKey = RSA.importKey( base64.urlsafe_b64decode(serverPubKey.content))

        cipheredID = cipherModule.processObjectRSA(userID, serverPubKey)
        cipheredID = base64.urlsafe_b64encode(cipheredID)

        r = requests.get("http://localhost:3030/getSalt?userID=" + userID + '&hashClient=' + cipheredID, verify = False)
        


        """  If there is no record corresponding to the desired combination  """
        if r.content == '':
            print 'No record'
            return


        hashed = self.hashNsalt(password, r.content)
        hashed = cipherModule.processObjectRSA(hashed, serverPubKey)
        hashed = base64.urlsafe_b64encode(hashed)
        
        valid = requests.get("http://localhost:3030/validatePassword?userID=" + userID + '&passwordHash=' + hashed + '&hashClient=' + cipheredID, verify=False)

        if valid.content == '0':
            return False
        else:
            return True
        
    '''
        WORKING
        exports the public part of the RSA key
    '''
    def exportRSAPublicKey(self):
        return base64.standard_b64encode(cipherModule.getRSAKey(self.RSAKeyFileName, self.RSApassphrase).publickey().exportKey())
        
    '''
        WORKING
        request a RSA Public Key from a chosen user (used for sharing)
    '''
    def getRSAPublicKey(self, userToGetID=None):
        if userToGetID == None:
            print 'No userToGetID specified'
            return
        
        r = requests.get("http://localhost:3030/getRSAPublicKey?userID=" + self.userName + '&pubKeyUser=' + userToGetID + '&hashClient=' + self.hashArgs([self.userName, userToGetID]), verify = False)
        
        if r.content == '':
            print 'User not registered'
        else:
            print r.content
        
        return RSA.importKey(base64.standard_b64decode(r.content))
    
    
    '''
        WORKING
        upload a file to cherrypy
    '''
    def sendFile(self, filePath=None, userID=None, realFilePath = None):
        if userID == None:
            print 'No userID specified'
            return
    
        if filePath == None:
            print "No file specified"
            return

        if realFilePath == None:
            print "No file name specified"
            return

        if not os.path.exists(filePath):
            print "File not found"
            return


        #print filePath
        #print realFilePath
    
        f = FileLenIO(filePath, 'rb')
    
        request = urllib2.Request('http://127.0.0.1:3030/upload', f)
        request.add_header('Content-Type', 'application/octet-stream')
        """  custom header with the name of the file  """
        request.add_header('File-Name', os.path.basename(realFilePath))
        request.add_header('User-ID', str(userID))
        request.add_header('hashClient', self.hashArgs([os.path.basename(realFilePath), userID]) )
    
        response = urllib2.urlopen(request)
       
       
    '''
        WORKING
        downloads a file from cherrypy
    '''
    def receiveFile(self, fileName=None, userID=None):        
        if userID == None:
            print 'No userID specified'
            return
    
        if fileName == None:
            print "No file specified"
            return
    
        r = requests.get("http://localhost:3030/download?fileName=" + str(fileName)+"&userID="+str(userID)+'&hashClient='+self.hashArgs([fileName, userID]), stream=True, verify=False)
        size = 0
        
        path = os.path.join('/home', getpass.getuser(), 'Desktop/clienteDL/')
        #print path
        if not os.path.exists(path):
            os.makedirs(path)
        while True:
            
            #advances to the content that hasn't been read
            r.iter_content(size)
            #reads 100mb at a time so it doesn't fill up the RAM
            data = r.raw.read(10240000)
            
            newFile = open(path+str(fileName), 'a+')
            newFile.write(data)
            newFile.close
    
            size += len(data)
    
            if len(data) < 10240000:
                break
        
        return path
            
    
    '''
        WORKING
        update a file
    '''
    def updateFile(self, filePath = None):
        if filePath == None:
            print 'updateFile - Missing filePath'
            return

        recordPath = self.getRecord(filePath, self.userName)

        fin = open(recordPath, 'rb')
        secret = fin.read(344)
        iv = fin.read(344)
        fin.close()


        secret = base64.standard_b64decode(secret)
        iv = base64.standard_b64decode(iv)

        secret = decipherModule.processObjectRSA(secret, self.RSAkey)
        iv = decipherModule.processObjectRSA(iv, self.RSAkey)

        """  Encrypt file with the same AES key that it receives in the record  """
        output = self.encryptFileAESwSecret(filePath, secret, iv)


        f = FileLenIO(output, 'rb')
    
        request = urllib2.Request('http://127.0.0.1:3030/updateFile', f)
        request.add_header('Content-Type', 'application/octet-stream')
        """  custom header with the name of the file  """
        request.add_header('File-Name', os.path.basename(filePath))
        request.add_header('User-ID', self.userName)
        request.add_header('hashClient', self.hashArgs([os.path.basename(filePath), self.userName]) )
    
        response = urllib2.urlopen(request)

        os.remove(recordPath)
        os.remove(output)
    
    '''
        WORKING
        delete a file
    '''
    def delete(self, fileName = None):
        if fileName == None:
            print 'delete - Missing fileName'
            return

        r = requests.get("http://localhost:3030/deleteFile?fileName=" + fileName + "&userID=" + self.userName + '&hashClient=' + self.hashArgs([fileName, self.userName]), verify = False)

    '''
        WORKING
        share a file with an user
    '''
    def shareFile(self,  fileName = None, fileReceiverID = None):        
        """  Get public key   """

        """  Get Record  """
    
        """  Decipher own record  """
    
        """  Cipher record with the public key received  """

        if fileName == None:
            print 'shareFile - Missing fileName'
            return
        if fileReceiverID == None:
            print 'shareFile - Missing fileReceiverID'
            return


        fileHolderID = self.userName
        
        shareKey = self.getRSAPublicKey(fileReceiverID)
        #shareKey = RSA.importKey(shareKey)
        
        recordName = self.getRecord(fileName, fileHolderID)
        


        fin = open(recordName, 'rb')
        secret = fin.read(344)
        iv = fin.read(344)
        fin.close()
    
        secret = base64.standard_b64decode(secret)
        iv = base64.standard_b64decode(iv)

        secret = decipherModule.processObjectRSA(secret, self.RSAkey)
        iv = decipherModule.processObjectRSA(iv, self.RSAkey)

        secret = cipherModule.processObjectRSA(secret, shareKey)
        iv = cipherModule.processObjectRSA(iv, shareKey)

        secret = base64.standard_b64encode(secret)
        iv = base64.standard_b64encode(iv)


        fout = open(recordName, 'wb')
        fout.write(secret)
        fout.write(iv)
        fout.close()
        
        f = FileLenIO(recordName, 'rb')
    
        request = urllib2.Request('http://127.0.0.1:3030/shareFile', f)
        request.add_header('Content-Type', 'application/octet-stream')
        """  custom header with the name of the file  """
        request.add_header('File-Name', str(fileName))
        request.add_header('File-Holder', str(fileHolderID))
        request.add_header('File-Receiver', str(fileReceiverID))
        request.add_header('hashClient', self.hashArgs([fileName, fileHolderID, fileReceiverID]))
        #request.add_header('Record-ID', str(fileHolderID))
    
        response = urllib2.urlopen(request)
        
        
        os.remove(recordName)
        
    '''
        WORKING
        get a record from db 
    '''
    def getRecord(self, fileName = None, userID = None):
        if fileName == None:
            print 'getRecord - Missing fileName'
            return
        if userID == None:
            print 'getRecord - Missing userID'
            return

        r = requests.get("http://localhost:3030/getRecord?fileName=" + str(fileName)+"&userID="+str(userID)+'&hashClient='+self.hashArgs([fileName, userID]), verify = False)
        
        """  If there is no record corresponding to the desired combination  """
        if r.content == '':
            print 'No record'
            return
    
        print r.headers['Record-ID']

        newFile = open(os.path.join('/home', getpass.getuser(), 'Desktop/',r.headers['Record-ID']), 'wb')
        newFile.write(r.content)
        newFile.close()

        return os.path.join('/home', getpass.getuser(), 'Desktop/',r.headers['Record-ID'])

    
    '''
        WORKING
        list the user files
    '''
    def listFiles(self):

        r = requests.get("http://localhost:3030/listFiles?userID=" + self.userName + '&hashClient=' + self.hashArgs([self.userName]), verify = False)
        
        if r.content == '':
            print 'User not registered'
        else:
            print r.content
            
    def listPboxes(self):
        r = requests.get("http://localhost:3030/listPboxes", verify = False)
        if r.content == '':
            print 'There are no Pboxes'
        else:
            print r.content

    def listPboxesOfSharedFile(self, fileName = None):
        r = requests.get("http://localhost:3030/listPboxesOfSharedFile?fileName="+fileName+"&userID="+self.userName+'&hashClient='+self.hashArgs([fileName, self.userName]), verify = False)
        if r.content == '':
            print 'There are no Pboxes'
        else:
            print r.content

    '''
        WORKING
        encapsulation method for the RSA encryption
        needs a fileName + RSA key
    '''
    def encryptFileRSA(self, fileName=None, key=None):
        if fileName == None:
            print("\nNothing to be done in Client.encryptFileRSA\n")
            return
        if key == None:
            print("\nNothing to be done in Client.encryptFileRSA\n")
            return
        
        outputFileName = "cipheredFile."+(fileName.split("."))[1]
        
        cipherModule.processFileRSA(fileName, outputFileName, key)
        
        return outputFileName
    
    '''
        WORKING
        encapsulation method for the RSA decryption
    '''
    def decryptFileRSA(self, fileName=None, key=None):
        if fileName == None:
            print("\nNothing to be done in Client.decryptFileRSA\n")
            return
        if key == None:
            print("\nNothing to be done in Client.decryptFileRSA\n")
            return
        
        outputFileName = "decipheredFile." + (fileName.split("."))[1]
        
        decipherModule.processFileRSA(fileName, outputFileName, key)
        
        return outputFileName
    
    '''
        WORKING
        encapsulation method for the AES encryption
    '''
    def encryptFileAES(self, fileName=None):
        if fileName == None or fileName == '':
            print("\nNothing to be done in Client.encryptFileAES\n")
            return
        
        '''
            Call the AES encryption method (encapsulation)
        '''
        split = fileName.split(".")
        outputFileName = split[0]+"_c."+split[1]
        cipherModule.processFileAES(fileName, outputFileName)
        
        
        return outputFileName

    def encryptFileAESwSecret(self, fileName=None, secret = None, iv=None):
        if fileName == None or fileName == '':
            print("\nNothing to be done in Client.encryptFileAES\n")
            return
        if secret == None:
            print 'encryptFileAESwSecret - Missing secret'
            return
        if iv == None:
            print 'encryptFileAESwSecret - Missing iv'
            return

        '''
            Call the AES encryption method (encapsulation)
        '''
        split = fileName.split(".")
        outputFileName = split[0]+"_c."+split[1]
        cipherModule.processFileAESwSecret(fileName, outputFileName, secret, iv)

        return outputFileName
    
    '''
        WORKING
        encapsulation method for the AES decryption
    '''
    def decryptFileAES(self, fileName=None):
        if fileName == None or fileName == '':
            print("\nNothing to be done in Client.decryptFileAES\n")
            return
        
        '''
            Call the RSA decryption method (encapsulation)
        '''
        split = fileName.split(".")
        outputFileName = split[0][:-2]+"_d."+split[1]
        decipherModule.processFileAES(fileName, outputFileName)
        
        return outputFileName
    
    '''
        WORKING
        encapsulation method for the AES Hybrid encryption
    '''
    def encryptFileAESH(self, fileName=None):
        if fileName == None or fileName == '':
            print("\nNothing to be done in Client.encryptFileAESH\n")
            return
        
        '''
            Call the AES encryption method (encapsulation)
        '''
        split = fileName.split(".")
        outputFileName = split[0]+"_c."+split[1]
        cipherModule.processFileHybridAES(fileName, outputFileName, self.RSAkey)
        
        
        return outputFileName
    
    '''
        WORKING
        encapsulation method for the AES Hybrid decryption
    '''
    def decryptFileAESH(self, fileName=None):
        if fileName == None or fileName == '':
            print("\nNothing to be done in Client.decryptFileAESH\n")
            return
        
        '''
            Call the RSA decryption method (encapsulation)
        '''
        split = fileName.split(".")
        outputFileName = split[0][:-2]+"_d."+split[1]
        decipherModule.processFileHybridAES(fileName, outputFileName, self.RSAkey)
        
        return outputFileName
    
    '''
        main for testing encryption and decryption
    '''
    def main(self, inputFileName, mode):

    	if mode == 'send':
    		self.send(inputFileName)
    		print("Done!")

    	if mode == 'res':
    		self.receive(inputFileName)
        	print("Done!")

        if mode == 'client side' or mode == '' or mode == None:
            print("Encrypting "+ inputFileName+" ...")
            output = self.encryptFileAES(inputFileName)
            
            print("Decrypting "+ inputFileName +" ...")
            self.decryptFileAES(output)
            print("Main| mode = "+mode+" testing done!")
        if mode == 'client server':
            self.send(inputFileName)
            self.receive(inputFileName)
            print("Main| mode = "+mode+" testing done!")
            
        if mode == 'encAES':
            print("Encrypting "+ inputFileName+" ...")
            self.encryptFileAES(inputFileName)
            
        if mode == 'decAES':
            print("Decrypting "+ inputFileName +" ...")
            self.decryptFileAES(inputFileName)
        
        if mode == 'encAESH':
            print("Encrypting "+ inputFileName+" ...")
            self.encryptFileAESH(inputFileName)
            
        if mode == 'decAESH':
            print("Decrypting "+ inputFileName +" ...")
            self.decryptFileAESH(inputFileName)
        
        
        
        
        if mode == 'encRSA':
            print("Encrypting "+ inputFileName+" ...")
            key = cipherModule.getRSAKey(self.RSAKeyFileName, self.RSApassphrase)
            self.encryptFileRSA(inputFileName, key)
            
        if mode == 'decRSA':
            print("Decrypting "+ inputFileName +" ...")
            key = cipherModule.getRSAKey(self.RSAKeyFileName, self.RSApassphrase)
            self.decryptFileRSA(inputFileName, key)
            
        print("Exiting Client Main...")
    
    '''
        WORKING
        encrypts and sends
    '''
    def send(self, inputFileName = None):
        if inputFileName == None:
            print 'send - Missing inputFileName'
            return


        print("Encrypting "+ inputFileName+" ...")
        
        output = self.encryptFileAESH(inputFileName)
        
        print("Sending "+output+" to server...")
        
        self.sendFile(output, self.userID, inputFileName)
        os.remove(output)
        print("Client.send done!")
    
    '''
        WORKING
        receives and decrypts
    '''
    def receive(self, inputFileName = None):

        if inputFileName == None:
            print 'receive - Missing inputFileName'
            return

        print("Receiving "+ inputFileName + " ...")

        path = self.receiveFile(inputFileName, self.userID)

        print("Decrypting "+ inputFileName +" ...")
        print path+inputFileName

        aux = path+inputFileName
        aux = str(aux)
        self.decryptFileAESH(aux)
        
        os.remove(aux)
        
        print("Client.receive done!")
        



class FileLenIO(io.FileIO):

  def __init__(self, name, mode = 'r', closefd = True):
    io.FileIO.__init__(self, name, mode, closefd)

    self.__size = statinfo = os.stat(name).st_size

  def __len__(self):
    return self.__size


'''
    create an object for testing
'''
c = Client()

while(1):
    if c.loginb == 1:
        print '-----------------------------------------'
        print '------           1. Logout         ------'
        print '------    2. List Files in Pbox    ------'
        print '------        3. Upload File       ------'
        print '------       4. Download File      ------'
        print '------        5. List Pboxes       ------'
        print '------ 6. List Pboxes sharing file ------'
        print '------        7. Share file        ------'
        print '------        8. Update file       ------'
        print '------        9. Delete file       ------'


        var = raw_input("Option: ")


        if int(var) == 0:
            print c.CCgetExponentAndModulus()
        elif int(var) == 1:
            c.loginb = 0
            c.passphrase = ''
        elif int(var) == 2:
            c.listFiles()
        elif int(var) == 3:
            path = raw_input("Path to file: ")
            c.send(path)
        elif int(var) == 4:
            fileName = raw_input("File name: ")
            c.receive(fileName)
        elif int(var) == 5:
            c.listPboxes()
        elif int(var) == 6:
            fileName = raw_input("File name: ")
            c.listPboxesOfSharedFile(fileName)
        elif int(var) == 7:
            fileName = raw_input("File name: ")
            userToShare = raw_input("User to share: ")
            c.shareFile(fileName, userToShare)
        elif int(var) == 8:
            filePath = raw_input("File path: ")
            c.updateFile(filePath)
        elif int(var) == 9:
            fileName = raw_input("File name: ")
            c.delete(fileName)

    else:
        print '-----------------------------------------'
        print '------           1. Login          ------'

        var = raw_input("Option: ")

        if int(var) == 1:
            print '-----------------------------------------'
            print '------             1. CC           ------'
            print '------          2. Password        ------'

            log = raw_input("Option: ")

            if int(log) == 1:
                c.loginCC()
            elif int(log) == 2:
                c.loginPassword()