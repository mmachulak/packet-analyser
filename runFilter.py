#!/usr/bin/python

import datetime
import glob
import logging
import os
import sys
from time import gmtime, strftime

# !!!!!!!!! Requires further implementation.
logging.basicConfig(level=logging.ERROR,
                    format='%(asctime)s %(levelname)s %(message)s',
                    filename='error.log',
                    filemode='w')

logger = logging.getLogger('filterDumps')


def checkLogCount(pathToLogs):
	"""
	Ensures more than one log file exists, if not the application exits.
	"""
	if len(glob.glob1(pathToDumps,"*.pcap")) > 1: # Ensures more than one file in the dump directory, otherwise there is only the file currently being used for capture (single pcap = working pcap).
		print "More than one *.pcap file.  Moving onto processing."
		getLatestDump(pathToLogs)
	else:
		exitTime=strftime("%Y-%m-%d %H:%M:%S GMT", gmtime()) # Uses GMT, not BST - to fix.
		logger.exception("Error. Not enough capture files exist at "+exitTime)
		sys.exit("Error. Not enough capture files exist at "+exitTime)

def getLatestDump(path):
	pathToDumps = glob.glob(os.path.join(path, '*')) # Gather file names of all files in this directory, and store them in a list.
	pathToDumps.sort(reverse=False) # Order dumps starting with the lowest timestamp (i.e., the oldest).
	for dumpFile in pathToDumps[:]:
		dumpCount = len(os.listdir(path))
		if dumpCount > 1:
			print "Procesing: "+dumpFile
			timestampStartCapture=dumpFile[-15:-5]
			print "Timestamped", timestampStartCapture
			processDumps(dumpFile, timestampStartCapture)
			try:
				print "Deleting pcap"				
				#os.remove(dumpFile) # After processing, delete the raw tcpdump capture.
			except:
				logger.exception("Error. Unable to delete tcpdump capture: "+dumpFile)
		else:
			print "Only the current capture file exists - not processing"

def processDumps(dumpFile, timestampStartCapture):
	"""Applies display filters to tcpdump captures.  
	Files are then stored in /xmlDump as PDML files.
	File prefixes indicating the type of display filter, and t"""
	global pathToXML
	#print "(Debug) Path to XML:", pathToXML+"smbUID-"+timestampStartCapture+".pdml"
	print "tshark will now apply display filters to the capture dumps for the time period beginning " + timestampStartCapture
	print "Processing SMB Security Blog (Associate User with Session ID)..."
	os.system("tshark -r "+dumpFile+" \"ntlmssp.auth.username\" -T pdml > "+pathToXML+"smbUID-"+timestampStartCapture+".pdml")
	print "Processing SMB Filename..."
	os.system("tshark -r "+dumpFile+" \"smb2.filename\" -T pdml > "+pathToXML+"smbFilename-"+timestampStartCapture+".pdml")
	#print "Processing SMB Tree ID..."
	#os.system("tshark -r "+dumpFile+" \"smb2.tid\" -T pdml > "+pathToXML+"smbTID-"+timestampStartCapture+".pdml")
	#os.system("tshark -r "+dumpFile+" \"smb.uid\" -T pdml > /tmp/smbUID-"+timestampStartCapture+".pdml")

pathToDumps=os.getcwd()+"/captureDumps/" # Defines where raw capture dumps are stored.
pathToXML=os.getcwd()+"/xmlDumps/" # Defines where PDML files will be stored.

checkLogCount(pathToDumps)
