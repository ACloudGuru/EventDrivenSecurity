
#Libs & Includes
import json, gzip, base64, sets, urllib2, boto3, os
from StringIO import StringIO
from netaddr import IPNetwork, IPAddress
#Global AWS Connnection Objects
ec2 = boto3.resource('ec2')
sns = boto3.client('sns')
## Global Vars
debug = bool(os.getenv('DEBUG', False)) # ENV parse - with False default
allowaws = bool(os.getenv('ALLOWAWS', True)) # ENV parse - with True default
snsarn = os.getenv('SNSARN', 'no-notification') # EnV parse - with text default

exceptions = [ {"cidr": "0.0.0.0/0", "port": "123"} ] ## Excluding NTP from suspect traffic

def getInstanceForEniId(eniId):
	try:
		network_interface = ec2.NetworkInterface(eniId)
		return network_interface.attachment['InstanceId']
	except:
		return False

def parseEvent(event):
	data = str(event['awslogs']['data']) # get CloudWatch logs
	logs = gzip.GzipFile(fileobj=StringIO(data.decode('base64', 'strict'))).read() # decode and uncompress CloudWatch logs
	return json.loads(logs) # convert the log data from JSON into a dictionary

def checkForException( dstaddr, dstport ):
	for exception in exceptions:
		if  (( IPAddress(dstaddr) in IPNetwork(exception['cidr']) ) and ( dstport == exception['port'] )):
			print("LOG: Allowed within exception cidr {} and port {}".format( exception['cidr'], exception['port']))
			return True
	return False

def addAWSExceptions():
	print("LOG: Adding AWS endpoints to exceptions list.")
	data = urllib2.urlopen('https://ip-ranges.amazonaws.com/ip-ranges.json') # retrieve the AWS created list of CIDR's for its services
	ipRanges = json.load(data)

	for range in ipRanges['prefixes']:
		if range['service'] == 'AMAZON':
			for port in ["80", "443"]:
				part = {}
				part['cidr'] = range['ip_prefix']
				part['port'] = port
				exceptions.append(part)

def killInstance( instanceId ):

	print("LOG: Killing instance {}".format( instanceId ))
	
	try:
		instance = ec2.Instance(instanceId)
	except:
		print("ERROR: Unable to find instance to kill. {}".format(instanceId))
		return False

	#Stop instance
	print("LOG: Sending stop message to instance. {}".format(instanceId))
	response = instance.stop(
	    Force=True
	)


	#Snapshot volumes
	volume_iterator = instance.volumes.all()
	for volume in volume_iterator:
		snapshot = snapShotInstance( volume.id, instanceId )
		if snapshot:
			print("LOG: Snapshot for instance {} volume {} snapshot {}".format( instanceId, volume.id, snapshot ))
		else:
			print("WARNING: Unable to snapshot for instance {} volume {}".format( instanceId, volume.id ))

	#Terminate instance
	print("LOG: Sending terminate message to instance. {}".format(instanceId))
	try:
		response = instance.terminate()
	except:
		print("ERROR: Unable to terminate instance to kill. {}".format(instanceId))
		return False
		
	sendNotification( instanceId, snapshot )

def snapShotInstance( volumeId, instanceId ):
	try:
		volume = ec2.Volume(volumeId)
	except:
		print("ERROR: Unable to find volume {} to snapshot".format(volumeId))
		return False
	snapshot = volume.create_snapshot(Description="Snapshot for instance {} made by the instanceKiller.".format(instanceId))
	return snapshot.id
	

def sendNotification( instanceId, snapshotId ):
	if snsarn == 'no-notification': print ("LOG: No SNS Topic Set - No notification"); return
	try:
		response = sns.publish(
			TopicArn=snsarn,
			Message="Instance {} has been terminated.  Snapshot {} created.".format( instanceId, snapshotId  ),
			Subject='InstanceKiller has terminated an instance'
		)
		print("LOG: SNS Notification sent.")
	except:
		print("ERROR: Unable to send SNS notification.")	

def lambda_handler(event, context):
	events = parseEvent(event) # get 'nice' :-) JSON for the event
	if debug: print(event); print(events) # print some debug things
	if allowaws: addAWSExceptions() # add AWS CIDR if appropriate
	if debug: print(exceptions) # print entire exceptions list

	killList = set()
	unknownInterfaces = []

	for record in events['logEvents']: # likley to be several flow lines in each 'event' delivery, itterate through
		try:
			extractedFields = record['extractedFields']
		except:
			raise Exception("ERROR: Could not find 'extractedFields' is the CloudWatch feed set correctly?")
			return False
		
		instanceId = getInstanceForEniId(extractedFields['interface_id']) ## find the Instance associated with an ENI
		if instanceId:
			print("LOG: Instance:{}\t Interface:{}\t SrcAddr:{}\t DstAddr:{}\t DstPort:{}\t".format( 
				instanceId,
				extractedFields['interface_id'],
				extractedFields['srcaddr'],
				extractedFields['dstaddr'],
				extractedFields['dstport']
			))
			if checkForException( extractedFields['dstaddr'], extractedFields['dstport'] ):
				print("LOG: OK")
				True
			else:
				print("LOG: ALERT!! Disallowed traffic {}:{} by instance {}".format( extractedFields['dstaddr'], extractedFields['dstport'],  instanceId ))
				killList.add(instanceId)
		else:
			unknownInterfaces.append(extractedFields['interface_id']) ## Cant find instance for interface .. might be an ELB..for example.

	print("LOG: There are {} instances on the kill list!".format( len(killList) ))
	
	if len(unknownInterfaces):
		print("LOG: Found {} interfaces not attached to instances (probably an ELB..probably).".format( len(unknownInterfaces) ))
		print("LOG: Interfaces without instances:{}".format(unknownInterfaces))
	
	killed = 0
	
	for instanceId in killList:
		if killInstance( instanceId ):
			killed = killed + 1

	return ("Killed {} instances.".format( killed ))
	