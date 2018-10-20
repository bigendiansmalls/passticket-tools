#!/usr/bin/env python2
from Crypto.Cipher import DES
from time import time
import argparse

################################################################################
#                                                                              #
#  Date:      April 9, 2018                                                    #
#  Author:    Big E. Smalls                                                    #
#  Thanks to:                                                                  #
#      Andrew VanVleet - initial passticket research                           #
#      This github https://github.com/chrrel/racf-passticket-generator         #
#        for the Java version of the implementation I used to sort out some    #
#        of the complicated bits.                                              #
#                                                                              #
#  Manual describing the algo:                                                 #
#    https://www.ibm.com/support/knowledgecenter/en/                           #
#        SSLTBW_2.1.0/com.ibm.zos.v2r1.icha300/skalgo.htm#skalgo               #
#                                                                              #
#    https://www.ibm.com/support/knowledgecenter/en/                           #
#        SSLTBW_2.1.0/com.ibm.zos.v2r1.icha300/algor.htm#algor                 #
#                                                                              #
#  This program will generate RACF passtickets for authentication to           #
#       z/os.                                                                  #
#                                                                              #
################################################################################

################################################################################
#   Python passticket generation test                                          #
################################################################################

def mainprog(u, a, s):
	user_plain = u.upper()
	app_plain = a.upper()

	# Right padded & EBCDIC encoded
	userid = (user_plain + ((8-len(user_plain)) * " ")).encode('cp500')
	app    =  (app_plain + ((8-len(app_plain)) * " ")).encode('cp500')
 	sec    = str(s).decode('hex')

	print "User ID: {0:s}".format(user_plain)
	print "App ID: {0:s}".format(app_plain)

	# 16 bytes 0-F

	##
	# Result 1
	##
	c = DES.new(sec, DES.MODE_ECB)
	ct = c.encrypt(userid)
	r1 = ct
	# print("Result 1: {0:s}".format(r1.encode('hex').upper()))

	##
	# Result 2a
	##
	r2a = "".join([ chr(ord(x) ^ ord(y)) for (x,y) in zip(r1,app)])

	##
	# Result 2
	##
	c = DES.new(sec, DES.MODE_ECB)
	ct = c.encrypt(r2a)
	r2 = ct

	##
	# Result 3
	##
	r3 = r2[0:4]

	##
	# Time info bytes
	##
	tib = bytearray("{0:0X}".format(int(time())))
	tib = str(tib).decode('hex')

	##
	# Result 4
	##
	r4 = "".join([ chr(ord(x) ^ ord(y)) for (x,y) in zip(r3,tib)])

	##
	# Result 5
	##
	num = 6 # num rounds
	l2b = r4[0:2]
	r2b = r4[2:4]

	upad = (user_plain.encode('cp500') + ((12-len(user_plain)) * "\x55"))

	# step A
	pad1 = upad[0:6]
	pad2 = upad[6:12]

	for i in range(1, num+1):
		# step B
		if (i % 2) != 0:     # rounds 1,3,5
			resB = r2b + pad1
		else:                # rounds 2,4,6
			resB = r2b + pad2

		# step C
		c = DES.new(sec, DES.MODE_ECB)
		resC = c.encrypt(resB)

		# step D	
		resD = resC[0:2]

		# step E
		resE = "".join([ chr(ord(x) ^ ord(y)) for (x,y) in zip(l2b,resD)])

		# step F
		l2b = r2b
		r2b = resE	

		# step G
		t1 = [10,2,12,4,14,6,16,8,9,1,11,3,13,5,15,7]
		t2 = [1,10,3,12,13,16,7,15,9,2,11,4,5,14,8,6]
		t3 = [3,10,1,12,13,16,9,15,7,2,14,4,5,11,8,6]
		t4 = [10,4,12,2,14,8,16,6,9,1,13,3,11,5,15,7]
		t5 = [4,10,12,1,8,16,14,5,9,2,13,3,11,7,15,6]
		t6 = [1,16,15,14,13,12,11,10,9,8,7,6,5,4,3,2]
		t0 = [0,t1,t2,t3,t4,t5,t6]

		br2b = "".join(["{0:08b}".format(ord(x)) for x in (resE)])
		tempb = ""
		
		for bb in range(0, 16):
			val = t0[i][bb]-1
			tempb = tempb + br2b[val]

		resG = tempb

		r2b = "{0:04X}".format(int(resG,2)).decode('hex')
		
		# step H (loop)

	# step I
	r5 = l2b + r2b
	# print("Result 5: {0:s}".format(r5.encode('hex').upper()))

	##
	# Result 6
	##
	r5b = "".join(["{0:08b}".format(ord(x)) for x in (r5)])

	tt = ['A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R',
		'S','T','U','V','W','X','Y','Z','0','1','2','3','4','5','6','7','8','9']

	finb = ""
	rnum = 27
	for finc in range(0,8):
		bits = ""
		rnum = (rnum + 4) % 32   # start with 31
		for bb in range(0,6):    # 6 bits at a time
			bits = bits + r5b[(rnum+bb-1) % 32]

		ind = int(bits,2)	% 36
		finb = finb + tt[ind]

	print "Passticket: {0:s}".format(finb)	

if __name__ == "__main__":
		parser = argparse.ArgumentParser(description=
			"Generate RACF Passticket.  Help Screen.", epilog="End of help screen.")
		parser.add_argument('-u','--user', type=str, 
			help="The User ID.", required=True)
		parser.add_argument('-a','--app', 
			type=str, help="The App to be used.", required=True)
		parser.add_argument('-s','--seckey', 
			type=str, help="The secret key from Racf",required=True)
		args = parser.parse_args()
		mainprog(args.user, args.app, args.seckey)
