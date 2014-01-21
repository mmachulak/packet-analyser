#!/usr/bin/python

# Misc

import os
import glob
import sys
import logging
import json
import urllib
import urllib2

# XML

import xml.parsers.expat, xml.etree.ElementTree as etree

from socket import inet_aton
from struct import unpack

logging.basicConfig(level=logging.ERROR,
                    format='%(asctime)s %(levelname)s %(message)s',
                    filename='error.log',
                    filemode='w')

logger = logging.getLogger('processPSML')


def processLogs(path):
	pathToLogs = glob.glob(os.path.join(path, '*')) # Gather file names of all files in this directory, and store them in a list.
	pathToLogs.sort(reverse=False) # Order dumps starting with the lowest timestamp (i.e., the oldest).
	for psmlFile in pathToLogs[:]:
		timestampStartCapture=psmlFile[-15:-5]
		tree = getElements(psmlFile)
		root = tree.getroot()
		parsePackets(root,tree,psmlFile,timestampStartCapture)
		#checkLogType(tree, psmlFile)
		
def getElements(logFile):
	"""Function parses an XML file"""
	global parseCount, parseErrorCount
	try:
		tree = etree.parse(logFile)
		return tree
	except xml.parsers.expat.ExpatError:
		#print "Parse error.  Skipping and logging."
		logger.exception("\nError when parsing "+logFile)
		parseErrorCount+=1
	except etree.ParseError:
		#print "Parse error.  Skipping and logging."
		logger.exception("\nError when parsing "+logFile)
		parseErrorCount+=1
"""
def checkLogType(tree, psmlFile):
	timestampStartCapture=psmlFile[-15:-5]
	print "Processing: "+psmlFile
	if psmlFile[-21:-16] == "tcpRT":
		print "RT found"
		parsePackets(tree, psmlFile, timestampStartCapture, "tcpretran")
	elif psmlFile[-21:-16] == "tcpOO":
		print "OO found"
		parsePackets(tree, psmlFile, timestampStartCapture, "tcpoutorder")
	elif psmlFile[-21:-16] == "tcpZW":
		print "ZW found"
		parsePackets(tree, psmlFile, timestampStartCapture, "tcpzerowindow")
"""

def parsePackets(root, tree, psmlFile, timestampStartCapture):
	#global pathToJSON
  print("ENTRY")
  try:
    cd = len(root)
    devid = None
    topjson = '{ "reporttype" : "net", "smbevents" : ['
    for packet in root:
      packetDetails={"uid":"","timestamp":"","ipv6dst":"","ipv6src":"","username":"","filename":[]}
      for proto in packet.iter("proto"):
        if proto.attrib["name"] == "geninfo": #OBTAIN TIMESTAMP
          for field in proto.iter("field"):
            if field.attrib["name"] == "timestamp":
              packetDetails["timestamp"]=field.attrib["value"]
#              print(packetDetails["timestamp"])
        if proto.attrib["name"] == "ipv6": #OBTAIN IPv6 DST/SRC
          for field in proto.iter("field"):
              if field.attrib["name"] == "ipv6.dst":
                packetDetails["ipv6dst"]=field.attrib["show"]
								#print packetDetails["ipv6dst"]
              if field.attrib["name"] == "ipv6.src":
                if devid == None:
                  devid = field.attrib["show"]
                packetDetails["ipv6src"]=field.attrib["show"]
								#print packetDetails["ipv6src"]
        if proto.attrib["name"] == "smb2": #OBTAIN TIMESTAMP
          listOfFiles=[]
          for field in proto.iter("field"):
            if field.attrib["show"] == "SMB2 Header":
              for subfield in field:
                if subfield.attrib["name"] == "smb2.sesid":
                  packetDetails["uid"]=subfield.attrib["show"]
										#print packetDetails["smb2ses"]
              if field.attrib["name"] == "ntlmssp.auth.username":
                packetDetails["username"]=field.attrib["show"]
              if field.attrib["name"] == "smb2.filename":
								#print field.attrib["show"]
                if field.attrib["show"] != "" or "." or "..":
                  listOfFiles.append(field.attrib["show"])
          packetDetails["filename"] = listOfFiles
#          print(listOfFiles)
#      print(packetDetails)
      packetjson = '{{ "uid" : "{}", "timestamp": "{}", "username": "{}", "tree" : "{}", "filename" : ['.format(packetDetails['uid'], packetDetails['timestamp'], packetDetails['username'], "")
      icd = len(packetDetails['filename'])
      for fn in packetDetails['filename']:
        packetjson += '"{}"'.format(fn)
        icd = icd - 1
        if icd > 0:
          packetjson += ','
      packetjson += ']}'
      cd = cd - 1
      if cd > 0:
        packetjson += ','
      topjson += packetjson
    topjson += '], "deviceid" : "{}" }}'.format(devid)
    print(topjson)
#    postdata = urllib.urlencode({"data" : topjson})
#    response = urllib2.urlopen(server_addr, postdata)
#    print(response)


	    	

    print("********** Packet **********")
  except AttributeError:
    print("Attribute reference of assignment failed.")
    logger.exception("\nAttribute reference or assignment failed.")

"""
							if len(listOfFiles) > 1:
								print listOfFiles
								packetDetails["filename"]=listOfFiles
"""

"""


		for elementPacket in tree.findall('//packet'):
			for child in elementPacket:
				print child.tag
			packetDetails={}
			count=0
			for elementSection in elementPacket.findall('//proto'):
				sectionContents=elementSection.text
				#print sectionContents


			for elementSection in elementPacket.findall('section'):
				sectionContents=elementSection.text # Store element contents as a variable.
				if count==0:
					packetDetails['packetno']=sectionContents
				elif count==1:
					packetTime=float(timestampStartCapture)+float(sectionContents)
					packetDetails['timestamp']=packetTime
				elif count==2:
					ipSrcLong = ipConv(sectionContents)
					packetDetails['src']=ipSrcLong
				elif count==3:
					ipDstLong = ipConv(sectionContents)
					packetDetails['dst']=ipDstLong
				elif count==4:
					packetDetails['proto']=sectionContents
				elif count==5:
					if dbTableName == "tcpretran" and "TCP Retransmission" in sectionContents:
						packetDetails['info']="TCP Retransmission"
					elif dbTableName == "tcpretran" and "TCP Fast Retransmission" in sectionContents:
						packetDetails['info']="TCP Fast Retransmission"
					elif dbTableName == "tcpoutorder":
						packetDetails['info']="TCP Out of Order"
					elif dbTableName == "tcpzerowindow":
						packetDetails['info']="TCP Zero Window"
					else:
						packetDetails['info']=sectionContents[0:24]
				else:
					logger.exception("\nExiting.  Malformed packet: "+psmlFile)
					sys.exit("Exiting.  Malformed packet: "+psmlFile)
				count+=1
			dbInsert(packetDetails, dbTableName)
"""

def ipConv(ip_addr):
	try:
		ip_packed = inet_aton(ip_addr)
	except socket.error:
		print("Invalid IP")
		ip_packed = inet_aton("255.255.255.255")

	ip = unpack("!L", ip_packed)[0]
	return ip

##############

pathToXML=os.getcwd()+"/xmlDumps/" # Defines where PDML files will be stored.
#pathToJSON=os.getcwd()+"/xmlDumps/json/"

##############


processLogs(pathToXML)


##############
