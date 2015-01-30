import PyKCS11
import sys
import platform
import OpenSSL
import urllib
import os
from M2Crypto import X509
from datetime import datetime

class Wrapper:
	def __init__(self, lib='/usr/local/lib/libpteidpkcs11.so'):
		#standart lib
		self.lib = lib
		#create a pkcs11 object
		self.pkcs11 = PyKCS11.PyKCS11Lib()
		#load our lib
		self.pkcs11.load(self.lib)
		#create a slot list
		self.slots = self.pkcs11.getSlotList()
		#useful objects for later
		self.objects = None
		self.session = None
		self.attributes = None

	def hexx(self, intval):
		x = hex(intval)[2:]
		if (x[-1:].upper() == 'L'):
			x = x[:-1]
		if len(x) % 2 != 0:
			return "0%s" % x
		return x

	def login(self, slot=0L):
		self.session = self.pkcs11.openSession(slot)
		try:
			self.session.login('')
		except:
			return 'Error'

		self.objects = self.session.findObjects()

		self.attributes = PyKCS11.CKA.keys()

		self.attributes.remove(PyKCS11.CKA_PRIVATE_EXPONENT)
		self.attributes.remove(PyKCS11.CKA_PRIME_1)
		self.attributes.remove(PyKCS11.CKA_PRIME_2)
		self.attributes.remove(PyKCS11.CKA_EXPONENT_1)
		self.attributes.remove(PyKCS11.CKA_EXPONENT_2)
		self.attributes.remove(PyKCS11.CKA_COEFFICIENT)

		self.attributes = [e for e in self.attributes if isinstance(e, int)]
		for o in self.objects:
			attributes = self.session.getAttributeValue(o, self.attributes)

		return 'Success'

	def logout(self):
		try:
			self.session.logout()
			self.session.closeSession()
			return 'Success'
		except:
			return 'Error'


	def _os2str(self, os):
		
		"""Convert octet string to python string"""
		
		return ''.join(chr(c) for c in os)


	def verifyCertificate(self, certificate_object, pkey):
		result = certificate_object.verify(pkey)
		if result:
			return 'Success'
		else:
			return 'Error'

	def verifySignature(self, signature, data):
		try:
			if self.m and self.e:
				decrypted = pow(signature, self.ex, self.mx)
				d = self.hexx(decrypted).decode('hex')
				if data == d[-20:]:
					return 'Success'
			else:
				return 'Error'
		except:
			return 'Error'

	def sign(self, data):
		if data == None:
			print "sign - missing data"
			return

		all_attributes = PyKCS11.CKA.keys()
		all_attributes.remove(PyKCS11.CKA_PRIVATE_EXPONENT)
		all_attributes.remove(PyKCS11.CKA_PRIME_1)
		all_attributes.remove(PyKCS11.CKA_PRIME_2)
		all_attributes.remove(PyKCS11.CKA_EXPONENT_1)
		all_attributes.remove(PyKCS11.CKA_EXPONENT_2)
		all_attributes.remove(PyKCS11.CKA_COEFFICIENT)
		all_attributes = [e for e in all_attributes if isinstance(e, int)]

		for o in self.objects:
			attributesPrivateKey = self.session.getAttributeValue(o, all_attributes)
			attrDictPrivateKey = dict(zip(all_attributes, attributesPrivateKey))
			if attrDictPrivateKey[PyKCS11.CKA_CLASS] == PyKCS11.CKO_PRIVATE_KEY and attrDictPrivateKey[PyKCS11.CKA_LABEL] == 'CITIZEN AUTHENTICATION KEY':
				mech = PyKCS11.Mechanism(PyKCS11.CKM_SHA1_RSA_PKCS, "")
				signature = self.session.sign(o, data, mech)
				#print signature
				s = ''.join(chr(c) for c in signature).encode('hex')
				break
		return s



	def encrypt(self, data):
		if self.m and self.e:
			for o in self.objects:
				try:
					padded = "\x00\x02%s\x00%s" % ("\xFF" * (128 - (len(data)) - 3), data)
					encrypted = pow(eval('0x%sL' % padded.encode('hex')), self.ex, self.mx)  # RSA
					encrypted = self.hexx(encrypted).decode('hex')
					return encrypted
				except:
					return 'Error'
		else:
			return 'Error'

	def decrypt(self, cipher_text):
		if self.m and self.e:
			for o in self.objects:
				try:
					decrypted = self.session.decrypt(o, cipher_text)
					decrypted = ''.join(chr(i) for i in decrypted)
					return decrypted
				except:
					return 'Error'
		else:
			return 'Error'

	def getCertificates(self):
		try:
			certificates = []
			for o in self.objects:
				d = o.to_dict()
				if d['CKA_CLASS'] == 'CKO_CERTIFICATE':
					der = self._os2str(d['CKA_VALUE'])
					cert = X509.load_cert_string(der, X509.FORMAT_DER)
					certificates.append(cert)
			return certificates
		except:
			return 'Error'

	def exportCertificates(self):
		certificates = self.getCertificates()
		export = []
		for c in certificates:
			export.append(c.as_der())
		return export

	def getUserCertificates(self):
		userCertificates = [c for c in self.getCertificates() if not c.check_ca()]
		return userCertificates

	def getBI(self):
		certificates = self.getUserCertificates()
		if certificates == 'Error':
			return 'Error'
		if certificates != []:
			for c in certificates:
				text = c.as_text()
				text = str(text)
				index = text.find("serialNumber=BI")
				return text[index+len("serialNumber=BI"):index+len("serialNumber=BI")+9]

	def getUserName(self):
		certificates = self.getUserCertificates()
		if certificates == 'Error':
			return 'Error'
		if certificates != []:
			for c in certificates:
				return c.get_subject().commonName

	def validateCertificateChain(self):
		status = False
		certificates = self.getCertificates()
		try:
			for c in certificates:
				for u in certificates:
					if c.get_issuer().commonName == u.get_subject().commonName:
						print u.get_issuer().commonName +' verifies '+u.get_subject().commonName +' that belongs to '+ c.get_subject().commonName +'?'
						publicKey = u.get_pubkey()
						if c.verify(publicKey):
							print 'Yes'
							status = True
						else:
							print 'No'
							status = False
		except:
			return 'Error'
		return status

	def getCertificateChain(self):
		certificates = self.getCertificates()
		chain = []
		try:
			for c in certificates:
				for u in certificates:
					if c.get_issuer().commonName == u.get_subject().commonName:
						chain.append(c.as_der())
						chain.append(u.as_der())
		except:
			return 'Error'
		return chain

	def validateExportedCertificateChain(self, certChain=None):
		if certChain == None:
			return 'Error'
		status = False
		try:
			i = 0
			while i < len(certChain):
				c = X509.load_cert_der_string(certChain[i])
				u = X509.load_cert_der_string(certChain[i+1])
				publicKey = u.get_pubkey()
				if c.verify(publicKey):
					status = True
				else:
					status = False
				i += 2
		except:
			return 'Error'
		return status

	def checkRevokedCertificates(self):
		try:
			certificates = self.getCertificates()
			urls = []
			searchString = []
			searchString.append("X509v3 CRL Distribution Points: \n\n                Full Name:\n                  URI:")
			searchString.append("X509v3 Freshest CRL: \n\n                Full Name:\n                  URI:")
			for c in certificates:
				for s in searchString:
					text = c.as_text()
					text = str(text)
					l = len(s)
					index = text.find(s)
					if index == -1:
						continue
					url = ''
					text = text[index+l:]
					
					for ch in text:
						if ch == '\n':
							break
						else:
							url += ch
					urls.append(url)

			filenames = []
			urls = set(urls)
			opener = urllib.URLopener()
			for u in urls:
				filename = u.split('/')[-1:]
				filenames.append(filename[0])
				opener.retrieve(u, filename[0])

			serials = []
			for c in certificates:
				serials.append(c.get_serial_number())

			rvkFlag = False
			for f in filenames:
				with open(f, 'r') as crlFile:
					crl = "".join(crlFile.readlines())

				crlObject = OpenSSL.crypto.load_crl(OpenSSL.crypto.FILETYPE_ASN1, crl)

				revokedObjects = crlObject.get_revoked()

				for rvk in revokedObjects:
					for s in serials:
						if rvk.get_serial() == s:
							rvkFlag = True 

			if rvkFlag == True:
				message = "An existing certificate was revoked"
			else:
				message = "No revoked certificates\n"

			for f in filenames:
				os.remove(f)
		except:
			return 'Error'
		return message

	def checkExportedRevokedCertificates(self, export=None):
		if export == None:
			return 'Error'
		certificates = []

		for e in export:
			certificates.append(X509.load_cert_der_string(e))

		try:
			urls = []
			searchString = []
			searchString.append("X509v3 CRL Distribution Points: \n\n                Full Name:\n                  URI:")
			searchString.append("X509v3 Freshest CRL: \n\n                Full Name:\n                  URI:")
			for c in certificates:
				for s in searchString:
					text = c.as_text()
					text = str(text)
					l = len(s)
					index = text.find(s)
					if index == -1:
						continue
					url = ''
					text = text[index+l:]
					
					for ch in text:
						if ch == '\n':
							break
						else:
							url += ch
					urls.append(url)

			filenames = []
			urls = set(urls)
			opener = urllib.URLopener()
			for u in urls:
				filename = u.split('/')[-1:]
				filenames.append(filename[0])
				opener.retrieve(u, filename[0])

			serials = []
			for c in certificates:
				serials.append(c.get_serial_number())

			rvkFlag = False
			for f in filenames:
				with open(f, 'r') as crlFile:
					crl = "".join(crlFile.readlines())

				crlObject = OpenSSL.crypto.load_crl(OpenSSL.crypto.FILETYPE_ASN1, crl)

				revokedObjects = crlObject.get_revoked()

				for rvk in revokedObjects:
					for s in serials:
						if rvk.get_serial() == s:
							rvkFlag = True 

			if rvkFlag == True:
				message = False
			else:
				message = True

			for f in filenames:
				os.remove(f)
		except:
			return 'Error'
		return message
