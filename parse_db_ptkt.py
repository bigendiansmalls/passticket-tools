#!/usr/bin/env python

################################################################################
#                                                                              #
#  Date:      April 9, 2018                                                    #
#  Author:    Big E. Smalls                                                    #
#                                                                              #
#  This program will dump passtickets from a RACF Database in binary format    #
#   the passtickets, if masked, can then be 'unmasked' and the secret          #
#   key retrieved by the unmasking program (not included here)                 #
#                                                                              #
#  Layout of the racf database & templates can be found in these 2 manuals:    #
# https://www.ibm.com/support/knowledgecenter/en/SSLTBW_2.3.0/                 #
#       com.ibm.zos.v2r3.icha300/toc.htm                                       #
#                                                                              #
# https://www.ibm.com/support/knowledgecenter/en/SSLTBW_2.3.0/                 #
#       com.ibm.zos.v2r3.ichb200/toc.htm                                       #
#                                                                              #
################################################################################

import re
import sys
import argparse

################################################################################
#      Variables and Constants                                                 #
################################################################################

BLKSIZE         = 4096
T_IND           = b'\x8A'
T_INDREG        = b'\x00'
T_INDNOR        = b'\x21'
T_INDGRP        = b'\x01'
T_INDGEN        = b'\x05'
T_SEGSSIG       = b'\x04'
IT_ALIAS        = b'\x62'
I_BLKID         = b'\x4e'
recEntryName = ""

################################################################################
#     dump the user ptkts to the screen                                        #
################################################################################

def parseTickets(ssrecords, ptkts, f):
        for u in ssrecords:

                # found indicator
                found = False
                if u[2]=="PTICKET":

                        # pticket record - 256 bytes
                        found = True
                        pt = u[0]

                        # list of ssrecords
                        slist = list()

                        # pticket address and length
                        pta = u[1]
                        ptl = 256

                        # entire pticket record
                        ptr = f[pta:pta+ptl]

                        # passticket name
                        ptnl = int(ptr[18:19].hex(), 16)
                        ptn =  ptr[21:21+ptnl-1].decode('cp500')

                        # passticket value
                        ptvs = 21+ptnl
                        ptvl = int(ptr[ptvs:ptvs+1].hex(), 16)
                        ptv  = ptr[ptvs+1:ptvs+1+ptvl]
                        hdr = ptv[0:5].decode('cp500')
                        val = ptv[5:]
                        ptkt = hdr + val.hex().upper()
                        slist.append(ptkt)

                # add to the list if we've found them
                if found:
                        ptkts.append([ptn, slist])
                        found = False

        #return list of tickets
        return ptkts

################################################################################
#       parse index records                                                    #
################################################################################

def parseIndexRecords(j, indBlk, blkoff, curr, ssrecords):
        global recEntryName
        indRecIdent= indBlk[curr:curr+1]                             # identificate of record
        indRecType = indBlk[curr+1:curr+2]                           # this record's type
        indRecLen  = int((indBlk[curr+2:curr+4]).hex(), 16)   # length of this record

        # focus on the records we want
        rec = indBlk[curr:curr+indRecLen]

        recComp = int((rec[6:8]).hex(), 16)
        recEntryNameLen = int((rec[8:10]).hex(), 16)
        recSegOff = 12 + recEntryNameLen

        ##
        # add compresed bytes back
        # note there cannot be a "compressed" entry until the entry prior has been
        # saved - the compression basically repeats the first XXX matching bytes of the
        # preview recEntryName so we have to save that off globally or return it/pass it back
        ##
        if recComp != 0:
            compBytes = recEntryName[0:recComp]
        else:
            compBytes = ''
        recEntryName = compBytes + rec[12:recSegOff].decode('cp500')

        ##
        # if rec type is genrec ->  x'21' && x'05'
        ##
        if indRecIdent== T_INDNOR and  indRecType == T_INDGEN:
                segData = rec[recSegOff:indRecLen]

                # record segment type
                recSegType = segData[0:1]

                # ensure we have a non-alias
                if recSegType != IT_ALIAS:
                        rba = 0
                        rst = int(recSegType.hex(), 16)
                        sd = segData[1:]

                        # parse segment for SSIGNON
                        for k in range(0, len(sd), 7):
                                segIdent = sd[k:k+1]

                                # this is the type we're looking for
                                if segIdent == T_SEGSSIG:
                                        rba = int(sd[k+1:k+7].hex(), 16)
                                        recEntryName = re.sub(r'[^\x00-\x7F]+', ' ', recEntryName)

                                        # verify generic typ record and PTKTDATA header, add to our list
                                        if (indRecType == T_INDGEN and recEntryName[0:8] == 'PTKTDATA'):
                                                ssrecords.append([recEntryName, rba, "PTICKET"])

        curr = curr + indRecLen
        return curr, ssrecords

################################################################################
# main prog function
################################################################################

def mainprog(ff):
        # read our file variable
        f = ff.read()

        # calculate # of 4096 blocks (per documentation)
        numblks = len(f) // 4096
        s_block = 1

        # lists of users, passtickets
        ssrecords = list()
        ptkts = list()

        for i in range(1, 10):
                # next 9 blocks are template blocks
                blkoff = BLKSIZE * i

                # increment s_block
                s_block = s_block + 1

        # loop through all the blocks
        for i in range(s_block, numblks):
                # block size / type / id  variables
                blkoff = BLKSIZE * i
                bt = f[blkoff:blkoff+1]
                bid = f[blkoff+3:blkoff+4]

                # if block type is index
                if (bt == T_IND and bid == I_BLKID): # 0x8a && 0x4e

                        # size of index
                        indSz  = int((f[blkoff+1:blkoff+3]).hex(), 16)

                        # index block
                        indBlk = f[blkoff:blkoff+indSz]

                        # index block type
                        indType = indBlk[4:5]

                        # if block type is index
                        if indType == T_INDREG:  # 0x00

                                # counter of index blocks
                                indCount = int(indBlk[12:14].hex(), 16)

                                # first record offset - accounts for header
                                curr = 14

                                # for loop through blocks index entries
                                for j in range(indCount):
                                        curr, ssrecords = parseIndexRecords(j, indBlk, blkoff, curr, ssrecords)

        # get results of parsing passticket records
        res = parseTickets(ssrecords, ptkts, f)

        # print output
        print ("Passtickets:")

        for i in res:
                print(("{0:s}{1:s}{2:s}".format(i[0], " " * (40-len(i[0])), i[1][0][5:])))

################################################################################
#    Main method                                                               #
################################################################################

if __name__ == "__main__":
        parser = argparse.ArgumentParser(description="Parse binary RACF database file.  Help Screen.", epilog="End of help screen.")
        parser.add_argument('file', type=argparse.FileType('rb'), help="The file to be parsed.")
        args = parser.parse_args()
        mainprog(args.file)
