import os, os.path
from os.path import isfile, join
from os import listdir
import cherrypy
from cherrypy.lib.static import serve_file
import shutil
import mimetypes
import string
import sqlite3
import random
import getpass
import hmac
import base64
from Crypto.PublicKey import RSA
import cipherModule
import decipherModule
from Crypto.Cipher import AES, PKCS1_OAEP
from hashlib import sha1
from wrapper import Wrapper
from datetime import date
import rsa
import PAM
import hashlib
import sys
import time



config = {
  'global' : {
	'server.socket_host' : '127.0.0.1',
	'server.socket_port' : 3030,
	# remove any limit on the request body size; cherrypy's default is 100MB
	'server.max_request_body_size' : 0,
	# increase server socket timeout to 60s; cherrypy's defult is 10s
	'server.socket_timeout' : 300,

  }
}

class Server(object):
	sessionKey = {}
	challenges = {}
	RSAkey = None

	def __init__(self):
		self.RSAkey = RSA.generate(2048)

  

	@cherrypy.expose
	def generateSessionKey(self, userID = None):
		if userID == None:
			print 'generateSessionKey - Missing userID'
			return

		self.sessionKey[userID] = os.urandom(64)
		
		key = RSA.importKey(base64.standard_b64decode(self.getRSAPublicKeyServer(userID)))
		cipher = PKCS1_OAEP.new(key)
		enData = cipher.encrypt(self.sessionKey[userID])
		return enData


	def checkArgs(self, args = None, hashClient = None, userID = None):
		if args == None:
			print 'checkArgs - Missing args'
			return

		if hashClient == None:
			print 'checkArgs - Missing hash'
			return

		if userID == None:
			print 'checkArgs - Missing userID'
			return

		hashed = hmac.new(self.sessionKey[userID], args, sha1)
		hashServer = hashed.digest().encode("hex").rstrip('\n')


		if hashClient == hashServer:
			print 'True'
			return True
		else:
			print 'False'
			return False


	@cherrypy.expose
	def getCCChallenge(self, userID = None):
		if userID == None:
			print 'getCCChallenge - Missing userID'
			return
		if not self.registeredUser(userID):
			return None

		challenge = os.urandom(64)
		m = hashlib.sha1(challenge)
		digest = m.digest()
		
		self.challenges[userID] = digest.encode('hex')
		return digest.encode('hex')

	@cherrypy.expose
	def authenticateCC(self, challengeSigned = None, userID = None, certChain = None):
		if userID == None:
			print 'authenticateCC - Missing userID'
			return

		if certChain == None:
			print 'No cert chain provided'
			return '0'
		else:
			dbconn = sqlite3.connect('seg.db')
			dbcursor = dbconn.cursor()
			dbcursor.execute('SELECT last_date FROM User WHERE user_id =:ID', {'ID': userID})
			lastDate = dbcursor.fetchone()[0]
			dbconn.close()
			today = date.today()

			if lastDate == '':
				insertDate = today.isoformat()
				dbconn = sqlite3.connect('seg.db')
				dbcursor = dbconn.cursor()
				dbcursor.execute('UPDATE User SET last_date = ? WHERE user_id = ?', (insertDate, userID))
				dbconn.commit()
				dbconn.close()
				days = 1
			else:
				lastDate = lastDate.split('-')
				lastDate = date(int(lastDate[0]), int(lastDate[1]), int(lastDate[2]))
				days = abs(today - lastDate)
				days = days.days
			

			if days > 0:
				certChain = base64.urlsafe_b64decode(str(certChain))
				certChain = certChain.split(';;:.:;;')

				dealer = Wrapper()
				response = dealer.validateExportedCertificateChain(certChain)
				if response == 'Error':
					print 'Internal Error'
					return '0'
				if response == False:
					print 'certChain not valid'
					return '0'
				if response == True:
					print 'certChain valid'


				response = dealer.checkExportedRevokedCertificates(certChain)
				if response == 'Error':
					print 'Internal Error'
					return '0'
				if response == False:
					print 'certificates revoked'
					return '0'
				if response == True:
					print 'certificates ok'	
				else:
					print response

				insertDate = today.isoformat()
				dbconn = sqlite3.connect('seg.db')
				dbcursor = dbconn.cursor()
				dbcursor.execute('UPDATE User SET last_date = ? WHERE user_id = ?', (insertDate, userID))
				dbconn.commit()
				dbconn.close()

		dbconn = sqlite3.connect('seg.db')
		dbcursor = dbconn.cursor()
		dbcursor.execute('SELECT challenge FROM challenge WHERE challenge.user_id = ?', (userID, ) )
		challenge = dbcursor.fetchone()
		dbconn.close()

		if challenge == None:
			"""  Creates the challenge in the Database  """
			dbconn = sqlite3.connect('seg.db')
			dbcursor = dbconn.cursor()
			args = (userID, self.challenges[userID], challengeSigned, 0)
			dbcursor.execute('INSERT INTO challenge VALUES(?,?,?,?)', args)
			dbconn.commit()
			dbconn.close()
		else:
			dbconn = sqlite3.connect('seg.db')
			dbcursor = dbconn.cursor()
			dbcursor.execute('UPDATE challenge SET challenge = ?, signature = ?, dirty = ? WHERE user_id = ?', ( self.challenges[userID], challengeSigned, 0, userID,) )
			dbconn.commit()
			dbconn.close()


		service = '/etc/pam.d/safebox'
		auth = PAM.pam()
		auth.start(service)
		
		print ''
		auth.set_item(PAM.PAM_USER, userID)
		print ''
		auth.set_item(PAM.PAM_CONV, pam_conv)

		try:
			print ''
			auth.authenticate()
			print ''
		except PAM.error, resp:
			print 'Go away! (%s)' % resp
			return '0'
		except:
			print 'Internal error'+str(sys.exc_info())
			return '0'
		else:
			print 'Good to go!'
			return '1'


	@cherrypy.expose
	def getServerPublicRSAKey(self):
		return base64.urlsafe_b64encode(self.RSAkey.publickey().exportKey())

	def getRSAPublicKeyServer(self, userID = None):
		if userID == None:
			print 'getRSAPublicKey - Missing userID'
			return

		
		if not self.registeredUser(userID):
			return None
		else:
			"""  Checks for the user's public key in the Database  """
			dbconn = sqlite3.connect('seg.db')
			dbcursor = dbconn.cursor()
			dbcursor.execute('SELECT rsa_pk FROM User WHERE user_id =?', (userID,))
			pk = dbcursor.fetchone()
			dbconn.close()

			if pk == None:
				return None
			else:
				return pk[0]



	@cherrypy.expose
	def getRSAPublicKey(self, userID = None, pubKeyUser = None, hashClient = None):
		if userID == None:
			print 'getRSAPublicKey - Missing userID'
			return

		if pubKeyUser == None:
			print 'getRSAPublicKey - Missing pubKeyUser'

		if hashClient == None:
			print 'getRSAPublicKey - Missing hashClient'
			return

		if not self.checkArgs(userID+pubKeyUser, hashClient, userID):
			print 'getSalt - Corrupt Args'
			return
		
		if not self.registeredUser(userID) or not self.registeredUser(pubKeyUser):
			return None
		else:
			"""  Checks for the user's public key in the Database  """
			dbconn = sqlite3.connect('seg.db')
			dbcursor = dbconn.cursor()
			dbcursor.execute('SELECT rsa_pk FROM User WHERE user_id =?', (pubKeyUser,))
			pk = dbcursor.fetchone()
			dbconn.close()

			if pk == None:
				return None
			else:
				return pk[0]



	def registeredUser(self, userID):
		"""  Checks for the user in the Database  """
		dbconn = sqlite3.connect('seg.db')
		dbcursor = dbconn.cursor()
		dbcursor.execute('SELECT user_id FROM User WHERE user_id =?', (userID,))
		username = dbcursor.fetchone()
		dbconn.close()

		if username == None:
			return False
		else:
			return True


	def insertUser(self, userID, userBI, rsa_PubKey, passwordSalted, salt, ccmodulus, ccexponent):
		"""  Creates the user in the Database  """
		dbconn = sqlite3.connect('seg.db')
		dbcursor = dbconn.cursor()
		args = (userID, userBI, rsa_PubKey, passwordSalted, salt, ccexponent, ccmodulus ,'')
		dbcursor.execute('INSERT INTO User VALUES(?,?,?,?,?,?,?,?)', args)
		dbconn.commit()
		dbconn.close()

	@cherrypy.expose
	def getSalt(self, userID = None, hashClient = None):
		if userID == None:
			print 'getSalt - Missing userID'
			return

		if hashClient == None:
			print 'getSalt - Missing hashClient'
			return

		if not self.registeredUser(userID):
			print 'user not registered'
			return

		clearText = base64.urlsafe_b64decode(str(hashClient))
		clearText = decipherModule.processObjectRSA(clearText, self.RSAkey)
		if clearText != userID:
			print 'getSalt - Corrupt Args'
			return
	

		dbconn = sqlite3.connect('seg.db')
		dbcursor = dbconn.cursor()
		dbcursor.execute('SELECT salt FROM User WHERE user_id =?', (userID,))
		salt = dbcursor.fetchone()
		dbconn.close()

		return salt


	@cherrypy.expose
	def validatePassword(self, userID = None, passwordHash = None, hashClient = None):
		if userID == None:
			print 'validatePassword - Missing userID'
			return
		if passwordHash == None:
			print 'validatePassword - Missing password'
			return
		
		if hashClient == None:
			print 'getSalt - Missing hashClient'
			return

		clearText = base64.urlsafe_b64decode(str(hashClient))
		clearText = decipherModule.processObjectRSA(clearText, self.RSAkey)
		if clearText != userID:
			print 'getSalt - Corrupt Args'
			return


		password = base64.urlsafe_b64decode(str(passwordHash))
		password = decipherModule.processObjectRSA(password, self.RSAkey)

		dbconn = sqlite3.connect('seg.db')
		dbcursor = dbconn.cursor()
		dbcursor.execute('SELECT password FROM password WHERE password.user_id = ?', (userID, ) )
		challenge = dbcursor.fetchone()
		dbconn.close()

		if challenge == None:
			dbconn = sqlite3.connect('seg.db')
			dbcursor = dbconn.cursor()
			dbcursor.execute('INSERT INTO password VALUES(?,?,?)', (userID, password, 0, ))
			dbconn.commit()
			dbconn.close()
		else:
			dbconn = sqlite3.connect('seg.db')
			dbcursor = dbconn.cursor()
			dbcursor.execute('UPDATE password SET password = ?, dirty = ? WHERE user_id = ?', ( password, 0, userID,) )
			dbconn.commit()
			dbconn.close()

	


		service = '/etc/pam.d/safebox'
		auth = PAM.pam()
		auth.start(service)
		print ''
		auth.set_item(PAM.PAM_USER, userID)
		print ''
		auth.set_item(PAM.PAM_CONV, pam_conv_pw)

		try:
			print ''
			auth.authenticate()
		except PAM.error, resp:
			print 'Go away! (%s)' % resp
			return '0'
		except:
			print 'Internal error'
			return '0'
		else:
			print 'Good to go!'
			return '1'




	def getPbox(self, userID):
		"""  Checks if user already has a Pbox  """
		dbconn = sqlite3.connect('seg.db')
		dbcursor = dbconn.cursor()
		dbcursor.execute('SELECT pbox_id FROM Pbox WHERE user_id =?', (userID,))
		userpbox = dbcursor.fetchone()
		dbconn.close()

		if userpbox == None:
			return -1
		else:
			return int(userpbox[0])




	def createPbox(self, userID):
		"""  Creates the user's Pbox in the Database  """
		dbconn = sqlite3.connect('seg.db')
		dbcursor = dbconn.cursor()
		dbcursor.execute('INSERT INTO Pbox VALUES(NULL, ?)', (userID,))
		dbconn.commit()
		dbconn.close()

		"""  Create a folder to store the user's file  """
		if not os.path.exists(os.path.join('/home', getpass.getuser(), 'Desktop/', userID)):
			os.makedirs(os.path.join('/home', getpass.getuser(), 'Desktop/', userID))




	def validateUser(self, userID = None):
		"""  If the user is not on the database  """
		if not self.registeredUser(userID):
			"""  Insert user into Users table  """
			print 'User not registered'
			return None

		user_pbox = int(self.getPbox(userID))

		"""  If the user still doesn't have a Pbox  """
		if user_pbox == -1:
			"""  creates a pbox for the desired user  """
			self.createPbox(userID)
			user_pbox = self.getPbox(userID)
			print 'New PBOX created for user '+ userID + ': Pbox ' + str(user_pbox)
			return user_pbox
		else:
			return user_pbox
	'''
		NOT USED
		FOR TESTING PURPOSES ONLY
	'''
	@cherrypy.expose
	def getPasswordHash(self, userID = None, passwordSalted = None):
		if userID == None:
			print 'userLogIn - Missing userID'
			return
		if passwordSalted == None:
			print 'userLogIn - Missing passwordSalted'
			return

		if not self.registeredUser(userID):
			"""  Insert user into Users table  """
			print 'User not registered'
			return None

	@cherrypy.expose
	def listFiles(self, userID = None, hashClient = None):

		if userID == None:
			print 'listFiles - Missing userID'
			return

		if hashClient == None:
			print 'listFiles - Missing hashClient'
			return


		if not self.registeredUser(userID):
			return None

		dbconn = sqlite3.connect('seg.db')
		dbcursor = dbconn.cursor()

		fileList = '\n'
		for row in dbcursor.execute('SELECT file_name FROM User, File, Pbox, Contains WHERE User.user_id=Pbox.user_id \
		  and Pbox.pbox_id = Contains.contains_pbox_id and Contains.contains_file_filepath = File.file_path \
		  and User.user_id =?', (userID,)):
			fileList += str(row[0])+'\n'
		
		dbconn.close()
		
		return fileList


	def listFilesServer(self, userID = None):
		if userID == None:
			print 'listFiles - Missing userID'
			return


		"""     REVER O RETURN    """
		if not self.registeredUser(userID):
			return None

		dbconn = sqlite3.connect('seg.db')
		dbcursor = dbconn.cursor()

		fileList = '\n'
		for row in dbcursor.execute('SELECT file_name FROM User, File, Pbox, Contains WHERE User.user_id=Pbox.user_id \
		  and Pbox.pbox_id = Contains.contains_pbox_id and Contains.contains_file_filepath = File.file_path \
		  and User.user_id =?', (userID,)):
		  fileList += str(row[0])+'\n'
		
		dbconn.close()
		
		return fileList

	def associateFileToPbox(self, pbox_id = None, filePath = None):
		"""  Verifications  """

		if pbox_id == None:
			print 'associateFileToPbox - Missing pbox_id'
			return
		if filePath == None:
			print 'associateFileToPbox - Missing filePath'
			return

		"""  Associate file to desired pbox in the DB  """
		dbconn = sqlite3.connect('seg.db')
		dbcursor = dbconn.cursor()

		dbcursor.execute('INSERT INTO Contains VALUES(NULL, ?, ?)', (pbox_id, filePath, ))
		dbconn.commit()
		dbconn.close()




	def saveFile(self, userID = None, filePath = None, fileName = None, userPbox = None):
		"""  Verifications  """
		if userID == None:
			print 'saveFile - Missing userID'
			return
		if filePath == None:
			print 'saveFile - Missing fileDestination'
			return
		if fileName == None:
			print 'saveFile - Missing fileName'
			return
		if userPbox == None:
			print 'saveFile - Missing userPbox'
			return



		"""  Creates the file in the Database  """
		dbconn = sqlite3.connect('seg.db')
		dbcursor = dbconn.cursor()
		dbcursor.execute('INSERT INTO File VALUES(?, ?, ?, datetime(strftime(\'%s\', \'now\'), \'unixepoch\'), ?)', (filePath, userID, userID, fileName, ))
		dbconn.commit()
		dbconn.close()


		self.associateFileToPbox(userPbox, filePath)



	@cherrypy.expose
	def addUser(self, userID = None, userBI= None, pubKey = None, passwordHS = None, salt = None, ccmodulus = None, ccexponent = None):
		if userID == None:
			print 'addUser - Missing userID'
			return
		if userBI == None:
			print 'addUser - Missing userBI'
			return
		if pubKey == None:
			print 'addUser - Missing pubKey'
			return
		if passwordHS == None:
			print 'addUser - Missing password'
			return
		if salt == None:
			print 'addUser - Missing salt'
			return
		if ccmodulus == None:
			print 'addUser - Missing ccmodulus'
			return
		if ccexponent == None:
			print 'addUser - Missing ccexponent'
			return


		password = base64.urlsafe_b64decode(str(passwordHS))
		password = decipherModule.processObjectRSA(password, self.RSAkey)

		"""  If the user is not on the database  """
		if not self.registeredUser(userID):
			"""  Insert user into Users table  """
			self.insertUser(userID, userBI, pubKey, password, salt, ccmodulus, ccexponent)
			self.createPbox(userID)
		else:
			print 'User is already registered'
			return
	
	
	@cherrypy.expose
	def upload(self):

		"""  Get user from header -- Validate User  """
		userID = cherrypy.request.headers['User-ID']

		userPbox = self.validateUser(userID)


		if not self.checkArgs(cherrypy.request.headers['File-Name'] + userID, cherrypy.request.headers['hashClient'], userID):
			print 'upload - Corrupt Args'
			return


		"""  Chose path to store the file according to the user  """
		destination = os.path.join('/home', getpass.getuser(), 'Desktop/', userID)

		if not os.path.exists(destination):
			os.makedirs(destination)

		randomname = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(10))


		destination = os.path.join(destination, randomname)                

		"""  Copy file into the selected folder  """
		with open(destination, 'wb') as f:
			shutil.copyfileobj(cherrypy.request.body, f)


		fin = open(destination, 'rb')

		secretEncodedSize = ivEncodedSize = 344

		#seek to the record position
		fin.seek( (os.path.getsize(destination) - secretEncodedSize - ivEncodedSize) )

		#read the encoded secret and iv from the file
		record = fin.read( secretEncodedSize + ivEncodedSize )
		
		#remove the record from the file
		fin.close()

		fin = open(destination, 'a')
		fin.truncate((os.path.getsize(destination) - secretEncodedSize - ivEncodedSize))
		fin.close()




		"""  Save file's metadata in the DB  """
		self.saveFile(userID, destination, cherrypy.request.headers['File-Name'], userPbox )


		"""  Query the DB for the desired record  """
		dbconn = sqlite3.connect('seg.db')
		dbcursor = dbconn.cursor()
		dbcursor.execute('SELECT contains_record FROM Contains WHERE Contains.contains_file_filepath = ? and Contains.contains_pbox_id = ?', (destination, userPbox, ))
		result = dbcursor.fetchone()
		dbconn.close()

		if result == None:
			print 'upload - Missing recordID'
			return

		recordID = str(result[0])

		if not os.path.exists(os.path.join('/home', getpass.getuser(), 'Desktop/records')):
			os.makedirs(os.path.join('/home', getpass.getuser(), 'Desktop/records'))

		recordfile = open(os.path.join('/home', getpass.getuser(), 'Desktop/records', recordID), 'wb')

		recordfile.write(record)

		recordfile.close()


	@cherrypy.expose
	def listPboxes(self):
		dbconn = sqlite3.connect('seg.db')
		dbcursor = dbconn.cursor()

		pboxlist = '\n'
		for row in dbcursor.execute('SELECT user_id, pbox_id FROM Pbox'):
			pboxlist += 'User: ' + str(row[0]) + '  Pbox: ' + str(row[1]) +'\n'
		
		dbconn.close()
		
		return pboxlist

	@cherrypy.expose
	def listPboxesOfSharedFile(self, fileName = None, userID = None, hashClient = None):
		if fileName == None:
			print 'listPboxesOfSharedFile - Missing fileName'
			return
		if userID == None:
			print 'listPboxesOfSharedFile - Missing userID'
			return
		if hashClient == None:
			print 'listPboxesOfSharedFile - Missing hashClient'
			return

		if not self.checkArgs(fileName + userID, hashClient, userID):
			print 'upload - Corrupt Args'
			return


		if not self.registeredUser(userID):
			print 'listPboxesOfSharedFile - user not registered'
			return

		if not self.fileExists(fileName, userID):
			print 'listPboxesOfSharedFile - file isnt shared by the user'
			return

		pboxID = self.getPbox(userID)

		if pboxID == -1:
			print 'listPboxesOfSharedFile - User doesn\'t have a pbox'
			return

		filepath = self.getFilePath(fileName, pboxID)

		if filepath == None:
			print 'listPboxesOfSharedFile - bad filepath'
			return


		dbconn = sqlite3.connect('seg.db')
		dbcursor = dbconn.cursor()

		pboxlist = '\n'
		for row in dbcursor.execute('SELECT user_id, pbox_id FROM Pbox, Contains WHERE Pbox.pbox_id = Contains.contains_pbox_id and Contains.contains_file_filepath = ?', (filepath,)):
			pboxlist += 'User: ' + str(row[0]) + '  Pbox: ' + str(row[1]) + '\n'
		
		dbconn.close()

		return pboxlist


	def fileExists(self, fileName = None, userID = None):
		fileList = self.listFilesServer(userID)

		if fileList == None:
			return False

		if '\n'+fileName+'\n' in fileList:
			return True
		else:
			return False
  
	@cherrypy.expose
	def download(self, fileName = None, userID = None, hashClient = None):

		if fileName == None:
			print 'download - Missing fileName'
			return

		if not userID:
			print 'download - Missing userID'
			return

		if hashClient == None:
			print 'download - Missing hashClient'
			return


		if not self.checkArgs(fileName+userID, hashClient, userID):
			print 'download - corrupt data'
			return


		"""  Checks if file exists in the user's Pbox  """
		if not self.fileExists(fileName, userID):
			print 'File doesn\'t exist in the user\'s Pbox'
			return
		else:


			"""  Query the DB for the desired file path  """
			dbconn = sqlite3.connect('seg.db')
			dbcursor = dbconn.cursor()
			dbcursor.execute('SELECT contains_file_filepath, contains_record FROM User, File, Pbox, Contains WHERE User.user_id=Pbox.user_id \
				and Pbox.pbox_id = Contains.contains_pbox_id and Contains.contains_file_filepath = File.file_path \
				and User.user_id = ? and File.file_name = ?', (userID, fileName, ))
			result = dbcursor.fetchone()
			dbconn.close()

			if result == None:
				print 'download - Missing filePath from DB'
				return
			else:
				filePath = result[0]
				recordID = result[1]

			if not os.path.exists(filePath):
				print 'download - file path doesn\'t exist'
				return
			else:

				destination = 'tempfile'
				destinationfile = open(destination, 'wb')
				shutil.copyfileobj(open(filePath, 'rb'), destinationfile)
				destinationfile.close()
				
				recordfile = open(os.path.join('/home', getpass.getuser(), 'Desktop/records', str(recordID)), 'rb')
				destinationfile = open(destination, 'ab')
				destinationfile.write(recordfile.read())

				recordfile.close()

				
				"""  open file to read in binary mode  """
				destinationfile.close()


				f = open(destination, 'rb')
				size = os.path.getsize(destination)
				
				"""  print file type  """
				#mime = mimetypes.guess_type(filePath)[0]


			
				"""  response type is the file type, the file name is the original and the length is the size of the file  """
				#cherrypy.response.headers["Content-Type"] = mime
				cherrypy.response.headers["Content-Disposition"] = 'attachment; filename="%s"' % fileName
				cherrypy.response.headers["Content-Length"] = size
				return serve_file(os.path.abspath('tempfile'), "application/x-download", "attachment", fileName)
	download._cp_config = {'response.stream': True}


	"""  Gets a file's path in the File System from the file's name and the Pbox ID  """
	@cherrypy.expose
	def getFilePath(self, fileName = None, pboxID = None):
		if fileName == None:
			print 'getFilePath - Missing fileName'
			return
		if pboxID == None:
			print 'getFilePath - Missing pboxID'
			return

		"""  Checks if user already has a Pbox  """
		dbconn = sqlite3.connect('seg.db')
		dbcursor = dbconn.cursor()
		dbcursor.execute('SELECT file_path FROM Contains, File WHERE \
		  File.file_path = Contains.contains_file_filepath and \
		  Contains.contains_pbox_id = ? and File.file_name = ?', (pboxID, fileName, ))
		filePath = dbcursor.fetchone()
		dbconn.close()

		if filePath == None:
			return None
		else:
			return filePath[0]


	@cherrypy.expose
	def getRecord(self, fileName = None, userID = None, hashClient = None):

		if userID == None:
			print 'getRecord - Missing userID'
			return
		if fileName == None:
			print 'getRecord - Missing fileName'
			return
		if hashClient == None:
			print 'getRecord - Missing hashClient'
			return

		if not self.checkArgs(fileName+userID, hashClient, userID):
			print 'getRecord - corrupt data'
			return


		if not self.fileExists(fileName, userID):
			print 'getRecord - No such file in user\'s Pbox'
			return 


		"""  Query the DB for the desired file path  """
		dbconn = sqlite3.connect('seg.db')
		dbcursor = dbconn.cursor()
		dbcursor.execute('SELECT contains_record FROM User, File, Pbox, Contains WHERE User.user_id=Pbox.user_id \
		  and Pbox.pbox_id = Contains.contains_pbox_id and Contains.contains_file_filepath = File.file_path \
		  and User.user_id = ? and File.file_name = ?', (userID, fileName, ))
		recordID = dbcursor.fetchone()
		dbconn.close()
	   
		if recordID == None:
			print 'getRecord - No such file in user\'s Pbox'
			return 
		else:
		  recordID = recordID[0]

		"""  Chose path to the file's record  """
		recordPath = os.path.join('/home', getpass.getuser(), 'Desktop/records', str(recordID))

		"""  Create a folder to store the user's file record  """
		if not os.path.exists(recordPath):
			print 'getRecord - Bad Record Path'
			return 

		f = open(recordPath, 'rb')
		size = os.path.getsize(recordPath)
		"""  print file type  """
		#mime = mimetypes.guess_type(recordPath)[0]

		   
		"""  response type is the file type, the file name is the original and the length is the size of the file  """
		#cherrypy.response.headers["Content-Type"] = mime
		cherrypy.response.headers["Content-Disposition"] = 'attachment; filename="%s"' % recordID
		cherrypy.response.headers["Content-Length"] = size
		cherrypy.response.headers["Record-ID"] = recordID
		return serve_file(os.path.abspath(recordPath), "application/x-download", "attachment", recordID)
	getRecord._cp_config = {'response.stream': True}


	@cherrypy.expose
	def shareFile(self):
		"""  Receives the file record. Other required info is in headers  """
		fileHolderID = cherrypy.request.headers['File-Holder']
		fileReceiverID = cherrypy.request.headers['File-Receiver']
		#recordID = cherrypy.request.headers['Record-ID']
		fileName = cherrypy.request.headers['File-Name']
		hashClient = cherrypy.request.headers['hashClient']

		if fileHolderID == None:
			print 'shareFile - Missing file holder ID'
			return
		if fileName == None:
			print 'shareFile - Missing fileName'
			return
		if fileReceiverID == None:
			print 'shareFile - Missing file receiver ID'
			return
		if hashClient == None:
			print 'shareFile - Missing hashClient'
			return

		if not self.checkArgs(fileName+fileHolderID+fileReceiverID, hashClient, fileHolderID):
			print 'shareFile - corrupt data'
			return

		"""  Check if users are registered  """
		if not self.registeredUser(fileHolderID):
			print 'shareFile - file holder is not registered'
			return
		if not self.registeredUser(fileReceiverID):
			print 'shareFile - file receiver is not registered'
			return

		"""  Checks if file exists in the file holder's pbox  """
		if not self.fileExists(fileName, fileHolderID):
			print 'shareFile - file doesn\'t exist in the sharer\'s Pbox'
			return

		"""  Checks if file exists in the file receiver's pbox  """
		if self.fileExists(fileName, fileReceiverID):
			print 'shareFile - file already exists in the receiver\'s Pbox'
			return

		"""  Get their Pbox numbers  """
		fileHolderPbox = self.getPbox(fileHolderID)
		fileReceiverPbox = self.getPbox(fileReceiverID)


		"""  Get the shared file path in the server to associate with the received record  """
		filePath = self.getFilePath(fileName, fileHolderPbox)
		if filePath == None:
			print 'shareFile - Missing filePath'
			return
		else:
			self.associateFileToPbox(fileReceiverPbox, filePath)


		dbconn = sqlite3.connect('seg.db')
		dbcursor = dbconn.cursor()
		dbcursor.execute('SELECT contains_record FROM Contains WHERE Contains.contains_file_filepath = ? and Contains.contains_pbox_id = ?', (filePath, fileReceiverPbox, ))
		result = dbcursor.fetchone()
		dbconn.close()

		if result == None:
			print 'upload - Missing recordID'
			return

		recordID = str(result[0])


		"""  Chose path to store the file's record  """
		destination = os.path.join('/home', getpass.getuser(), 'Desktop/records', recordID)

		"""  Create a folder to store the user's file record  """
		if not os.path.exists(os.path.join('/home', getpass.getuser(), 'Desktop/records')):
			os.makedirs(os.path.join('/home', getpass.getuser(), 'Desktop/records')) 


		"""  Copy record into the selected folder  """
		#with open(destination, 'wb') as f:
		  #shutil.copyfileobj(cherrypy.request.body, f)

		newrec = open(destination, 'wb')
		newrec.write(cherrypy.request.body.read())
		newrec.close()



	@cherrypy.expose
	def updateFile(self):
		userID = cherrypy.request.headers['User-ID']
		fileName = cherrypy.request.headers['File-Name']
		hashClient = cherrypy.request.headers['hashClient']

		if userID == None:
			print 'updateFile - Missing userID'
			return
		if fileName == None:
			print 'updateFile - Missing fileName'
			return
		if hashClient == None:
			print 'updateFile - Missing hashClient'
			return

		if not self.checkArgs(fileName+userID, hashClient, userID):
			print 'download - corrupt data'
			return

		if not self.registeredUser(userID):
			print 'updateFile - User not registered'
			return

		"""  Get the user's pbox id  """
		userPbox = self.getPbox(userID)

		if not self.fileExists(fileName, userID):
			print 'updateFile - File doesn\'t exist in user\'s pbox'
			return

		"""  Get the file's path from the database  """
		filePath = self.getFilePath(fileName, userPbox)

		"""  delete the existing file  """
		os.remove(filePath)

		"""  Copy new file into the selected folder  """
		with open(filePath, 'wb') as f:
			shutil.copyfileobj(cherrypy.request.body, f)

		"""  Updates the file in the Database  """
		dbconn = sqlite3.connect('seg.db')
		dbcursor = dbconn.cursor()
		dbcursor.execute('UPDATE File SET file_updateauthor = ?, file_lastupdate = datetime(strftime(\'%s\', \'now\'), \'unixepoch\')\
		  WHERE file_path = ?', (userID, filePath, ))
		dbconn.commit()
		dbconn.close()


	def isFileOwner(self, filePath = None, userID = None):
		if userID == None:
			print 'isFileOwner - Missing userID'
			return
		if filePath == None:
			print 'isFileOwner - Missing filePath'
			return

		"""  Query the DB for the desired file path  """
		dbconn = sqlite3.connect('seg.db')
		dbcursor = dbconn.cursor()
		dbcursor.execute('SELECT file_owner FROM File WHERE File.file_path = ?', (filePath, ))
		owner = dbcursor.fetchone()
		dbconn.close()

		if owner == None:
			return False

		if owner[0] == userID:
			return True
		else:
			return False


	@cherrypy.expose
	def deleteFile(self, fileName = None, userID = None, hashClient = None):
		if userID == None:
			print 'deleteFile - Missing userID'
			return
		if fileName == None:
			print 'deleteFile - Missing fileName'
			return

		if hashClient == None:
			print 'deleteFile - Missing hashClient'
			return

		if not self.checkArgs(fileName+userID, hashClient, userID):
			print 'download - corrupt data'
			return

		if not self.registeredUser(userID):
			print 'deleteFile - User not registered'
			return

		if not self.fileExists(fileName, userID):
			print 'deleteFile - File doesn\'t exist in the user\'s dropbox'
			return

		pboxID = self.getPbox(userID)

		if pboxID == -1:
			print 'deleteFile - User doesn\'t have a pbox'
			return

		filePath = self.getFilePath(fileName, pboxID)
		
		if filePath == None:
			print 'deleteFile - Missing filePath'
			return

		

		"""  If the user is the file's owner  """
		if self.isFileOwner(filePath, userID) == True:

			"""  Query the DB for the file records  """
			dbconn = sqlite3.connect('seg.db')
			dbcursor = dbconn.cursor()

			for row in dbcursor.execute('SELECT contains_record FROM Contains WHERE Contains.contains_file_filepath = ?', (filePath, )):
				os.remove(os.path.join('/home', getpass.getuser(), 'Desktop/records', str(row[0]) ))

			dbconn.close()

		  
			"""  delete the file  """
			os.remove(filePath)

			"""  delete every file association with pbox  """
			dbconn = sqlite3.connect('seg.db')
			dbcursor = dbconn.cursor()
			dbcursor.execute('DELETE FROM Contains WHERE contains_file_filepath = ?', (filePath,))
			dbconn.commit()
			dbconn.close()

			"""  delete the file in the DB  """
			dbconn = sqlite3.connect('seg.db')
			dbcursor = dbconn.cursor()
			dbcursor.execute('DELETE FROM File WHERE file_path = ?', (filePath,))
			dbconn.commit()
			dbconn.close()

		else:
			"""  If the user is not the file's owner  """


			"""  Query the DB for the desired file path  """
			dbconn = sqlite3.connect('seg.db')
			dbcursor = dbconn.cursor()
			dbcursor.execute('SELECT contains_record FROM Contains WHERE Contains.contains_file_filepath = ? and Contains.contains_pbox_id = ?', (filePath, pboxID,))
			record = dbcursor.fetchone()
			dbconn.close()

			if record == None:
				print 'No record of the file associated with the user'
				return
			else:
				record = record[0]

			os.remove(os.path.join('/home', getpass.getuser(), 'Desktop/records', str(record) ))


			"""  delete file association with pbox  """
			dbconn = sqlite3.connect('seg.db')
			dbcursor = dbconn.cursor()
			dbcursor.execute('DELETE FROM Contains WHERE contains_file_filepath = ? and contains_pbox_id =  ?', (filePath, pboxID, ))
			dbconn.commit()
			dbconn.close()

def pam_conv( auth, query_list, userData):
	resp = []
	#print query_list
	for i in range(len(query_list)):
		query, type = query_list[i]
		if type == PAM.PAM_PROMPT_ECHO_ON:
			dbconn = sqlite3.connect('seg.db')
			dbcursor = dbconn.cursor()
			dbcursor.execute('SELECT signature FROM challenge WHERE challenge.user_id = ?', (query,))
			signatureb64 = dbcursor.fetchone()
			dbconn.close()
			#print '----------------------'
			#print signatureb64[0]
			#print signatureb64[0].decode('hex')
			#print signatureb64[0].decode('hex').encode('base64')
			#print len(signatureb64[0].decode('hex').encode('base64'))
			#print '----------------------'
			resp.append((signatureb64[0].decode('hex').encode('base64'), 0))
		elif type == PAM.PAM_PROMPT_ECHO_OFF:
			"""  Query the DB for the desired file path  """
			dbconn = sqlite3.connect('seg.db')
			dbcursor = dbconn.cursor()
			dbcursor.execute('SELECT challenge, dirty FROM challenge WHERE challenge.user_id = ?', (query,))
			challengeb64 = dbcursor.fetchone()
			dbconn.close()
			#print '----------------------'
			#print challengeb64[0]
			#print challengeb64[0].decode('hex')
			#print challengeb64[0].decode('hex').encode('base64')
			#print len(challengeb64[0].decode('hex').encode('base64'))
			#print '----------------------'
			m = hashlib.sha1(challengeb64[0].decode('hex'))
			digestToSign = m.digest()
			if challengeb64[1] == '1':
				resp.append(('', 0))
			else:
				resp.append((digestToSign.encode('base64'), 0))
		elif type == PAM.PAM_TEXT_INFO:
			dbconn = sqlite3.connect('seg.db')
			dbcursor = dbconn.cursor()
			dbcursor.execute('SELECT ccexponent, ccmodulus FROM User WHERE User.user_id = ?', (query,))
			response = dbcursor.fetchone()
			dbconn.close()
			#print '----------------------------'
			#print response[0]
			#print response[1]
			#print '-----------------------------'
			resp.append((response[0] + ':' + response[1], 0))
		else:
			return None
	#print 'pam_conv return'
	return resp


def pam_conv_pw( auth, query_list, userData):
	resp = []
	#print query_list
	for i in range(len(query_list)):
		query, type = query_list[i]
		if type == PAM.PAM_PROMPT_ECHO_OFF:
			dbconn = sqlite3.connect('seg.db')
			dbcursor = dbconn.cursor()
			dbcursor.execute('SELECT password FROM User WHERE User.user_id = ?', (query,))
			response = dbcursor.fetchone()
			dbconn.close()
			#print 'resp0'
			#print response[0]
			resp.append((response[0], 0))
		if type == PAM.PAM_PROMPT_ECHO_ON:
			dbconn = sqlite3.connect('seg.db')
			dbcursor = dbconn.cursor()
			dbcursor.execute('SELECT password, dirty FROM password WHERE password.user_id = ?', (query,))
			response = dbcursor.fetchone()
			dbconn.close()
			#print 'resp1'
			#print response[0]
			if response[1] == '1':
				resp.append(('',0))
			else:
				resp.append((response[0], 0))
	#print resp
	#print 'ret pam_conv_pw'
	return resp

if __name__ == '__main__':
	cherrypy.quickstart(Server(), '/', config)
