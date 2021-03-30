#!/usr/bin/python

import socket
import socketserver
import select

import tftp
import cvtfile

data_retry_timeout = 2.0 # seconds
data_retry_max = 3  # resend DATA packets this many times before giving up

class Error(Exception) : pass

class internal_error(Error) : pass

class Nettftpd( socketserver.BaseRequestHandler ) :
	data_sock = None
	debugging = 2

	def set_debuglevel(self, level):
		# took this from ftplib.py
		'''Set the debugging level.
		The required argument level means:
		0: no debugging output (default)
		1: print commands and responses but not body text etc.
		2: also print raw lines read and sent before stripping CR/LF'''
		self.debugging = level

	def send( self, pkt ) :
		if self.debugging :
			print(pkt)
		pkt.pack()
		self.data_sock.sendto( pkt.packet, self.client_address )

	def pathcheck( self, tftppkt ) :
		# if trying to get any file with a path component, slap 'em
		# down and refuse
		if tftppkt.filename.find( "/" ) >= 0 :
			print("Filename \"%s\" with path component rejected." % tftppkt.filename)
			errpkt = tftp.Error( tftp.ERROR_ACCESS_VIOLATION, "Ignorning filename with path." )
			self.send( errpkt )
			return 0

		return 1

	def filemodecheck( self, tftppkt ) :
		if tftppkt.mode != "octet" :
			print("Invalid file mode \"%s\"." % tftppkt.mode)
			errpkt = tftp.Error( tftp.ERROR_ILLEGAL_TFTP_OP, "Only octet mode is supported." )
			self.send( errpkt )
			return 0

#		if tftppkt.mode != "netascii" and tftppkt.mode != "octet" :
#			print "Invalid file mode \"%s\"." % tftppkt.mode
#			errpkt = tftp.Error( tftp.ERROR_ILLEGAL_TFTP_OP, "Only netascii and octet mode are supported." )
#			self.send( errpkt )
#			return 0

		return 1

	def write_request( self, tftppkt ) :
		assert tftppkt.filename
		assert tftppkt.mode

		self.data_sock = socket.socket( socket.AF_INET, socket.SOCK_DGRAM )
		self.data_sock.bind( ("",0) )

		if not self.pathcheck( tftppkt ) :
			self.data_sock.close()
			return

		if not self.filemodecheck( tftppkt ) :
			self.data_sock.close()
			return

		# TODO disable writing to files and writing to existing files
		try :
			if tftppkt.mode == "netascii" :
				file = cvtfile.UnixToDosFile()
				file.open( tftppkt.filename, "wb" )
			else :
				file = open( tftppkt.filename, "wb" )
		except IOError as err :
			print("Failed to open %s : " % tftppkt.filename, err)
			errpkt = tftp.Error( tftp.ERROR_NO_SUCH_FILE, err.strerror )
			self.send( errpkt )
			self.data_sock.close()
			return

		ackpkt = tftp.Ack()
		self.send(ackpkt)
		next_block_num = 1

		# wait for the DATA; resend ACK if we don't get data
		retry_count = 0
		last = 0

		while retry_count < data_retry_max and not last :
			rfds,wfds,efds = select.select( [self.data_sock.fileno()], [], [], float(data_retry_timeout) )
			if rfds :
				(buffer,addr) = self.data_sock.recvfrom(1024)
				try :
					datapkt = tftp.parse( buffer )
				except tftp.packet_error as err :
					# ignore bad packets
					print("Ignoring bad packet from peer:",err.errmsg)
				else :
					if datapkt.op != tftp.DATA:
						print("Bad packet from peer (expected DATA).")
					elif datapkt.block_num != next_block_num :
						print("Bad DATA from peer; got block=%d expected block=%d." % (datapkt.block_num,next_block_num))
					else :
						# success! 
						file.write( datapkt.data )
						ackpkt.block_num += 1
						self.send( ackpkt )

						next_block_num += 1

						retry_count = 0

						# last packet; we're done
						if len(datapkt.data) < 512 :
							last = 1
				
			else :
				print("No response from peer; resending ACK.")
				self.send( ackpkt )
				retry_count += 1

		if retry_count >= data_retry_max :
			print("Too many retries.  Giving up.")

		self.data_sock.close()
		file.close()


	def read_request( self, tftppkt ) :
		assert tftppkt.filename
		assert tftppkt.mode

		self.data_sock = socket.socket( socket.AF_INET, socket.SOCK_DGRAM )
		self.data_sock.bind( ("",0) )

		print(self.data_sock.getsockname())

		if not self.pathcheck( tftppkt ) :
			self.data_sock.close()
			return

		if not self.filemodecheck( tftppkt ) :
			self.data_sock.close()
			return

		try :
			if tftppkt.mode == "netascii" :
				file = cvtfile.UnixToDosFile()
				file.open( tftppkt.filename, "rb" )
			else :
				file = open( tftppkt.filename, "rb" )

		except IOError as err :
			print("Failed to open %s : " % tftppkt.filename, err)
			errpkt = tftp.Error( tftp.ERROR_NO_SUCH_FILE, err.strerror )
			self.send( errpkt )
			self.data_sock.close()
			return

		datapkt = tftp.Data()

		last = 0
		while not last :
			datapkt.data = file.read( 512 )
			if len(datapkt.data) < 512 :
				# Note that if file size is an exact multiple of 512, we need
				# to send one more packet of zero data length to indicate end
				# of transfer.
				last = 1

			datapkt.block_num += 1
			self.send( datapkt )

			# wait for the ACK; resend data if we don't get ACK'd
			retry_count = 0
			while retry_count < data_retry_max :
				rfds,wfds,efds = select.select( [self.data_sock.fileno()], [], [], float(data_retry_timeout) )
				if rfds :
					(buffer,addr) = self.data_sock.recvfrom(1024)
					try :
						ackpkt = tftp.parse( buffer )

						if ackpkt.op != tftp.ACK :
							print("Bad packet from peer (expected ACK).")
						elif ackpkt.block_num != datapkt.block_num :
							print("Bad ACK from peer; got block=%d expected block=%d." % (ackpkt.block_num,datapkt.block_num))
						else :
							# success! leave the ACK retry loop
							break
					except tftp.packet_error as err :
						# ignore bad packets
						print("Ignoring bad packet from peer:",err.errmsg)
				else :
					print("No response from peer; resending DATA.")
					self.send( datapkt )
					retry_count += 1

			if retry_count >= data_retry_max :
				print("Too many retries.  Giving up.")

				# leave outer transmit loop
				last = 1

		file.close()
		self.data_sock.close()

	def serveit( self ) :
		try :
			pkt = tftp.parse( self.request[0] )
		except tftp.packet_error as err :
			print(err.errmsg)
		else :
			if pkt.op == tftp.RRQ :
				self.read_request( pkt )
			elif pkt.op == tftp.WRQ :
				self.write_request( pkt )
			else :
				print("Ignoring unexpected op.")

	def handle( self ) :
		print("client_address=",self.client_address)
		self.serveit()
		print("handle() done")

class ReuseUDPServer(socketserver.UDPServer):

	def server_bind(self) :
		print("ReuseUDPServer.server_bind()")
		self.allow_reuse_address = 1
		socketserver.UDPServer.server_bind(self)

	def server_activate(self) :
		print("ReuseUDPServer.server_activate()")
		socketserver.UDPServer.server_activate(self)

	def close_request(self,request) :
		print("ReuseUDPServer.close_request()")
		socketserver.UDPServer.close_request(self,request)

tftp.debugging = 1

server = ReuseUDPServer( ( '', tftp.UDP_PORT ), Nettftpd )
server.serve_forever()

