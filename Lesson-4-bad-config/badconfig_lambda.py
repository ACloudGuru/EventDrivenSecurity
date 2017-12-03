# AWS Config Rule Settings:

# Trigger type = Configuration changes
# Resources = EC2:SecurityGroup, EC2:Instance

# Key: port1, Value: [portNumber] e.g. 80 and or
# Key: port2, Value: [portRange]  e.g. 0-1024

import boto3
import json
import sets

APPLICABLE_RESOURCES = ["AWS::EC2::SecurityGroup", "AWS::EC2::Instance"]

# Given a SecurityGroup, find the related Instances...
def instancesForSecurityGroupId( secGroupId ):
	ec2 = boto3.client('ec2')
	return ec2.describe_instances(
		Filters=[{'Name': 'instance.group-id',
			      'Values': [secGroupId]}]
	)

# Given an instance find its security groups...
def secGroupsForInstanceId( instanceId ):
	ec2 = boto3.resource('ec2')
	instance = ec2.Instance(instanceId)
	return instance.security_groups

# Given a trigger security group, determine all the unique sec groups
# that need to be evaluated, and determine the relationships to instances.
def determineEvaluationScopeFromTriggerSecGroup( triggerSecGroup ):
	instancesToEvaluate = {}
	secGroupsToCheck = set()
	for reservation in instancesForSecurityGroupId(triggerSecGroup).get('Reservations'):
		for instance in reservation['Instances']:
			instancesToEvaluate[instance['InstanceId']] = []
			for group in secGroupsForInstanceId( instance['InstanceId'] ):
				instancesToEvaluate[instance['InstanceId']].append(group['GroupId'])
				secGroupsToCheck.add( group['GroupId'] )
	return { 'instancesToEvaluate' : instancesToEvaluate, 
			 'secGroupsToCheck' : secGroupsToCheck }

# Determine the exposed ports from the ip permissions of a security group
def find_exposed_ports(ip_permissions):
	exposed_ports = []
	for permission in ip_permissions or []:
		for ip in permission["IpRanges"]:
			if "0.0.0.0/0" in ip['CidrIp']:
				exposed_ports.extend(range(permission["FromPort"],
										   permission["ToPort"]+1))
	return exposed_ports

def expand_range(ports):
    if "-" in ports:
        return range(int(ports.split("-")[0]), int(ports.split("-")[1])+1)
    else:
        return [int(ports)]

def find_violation(exposed_ports, forbidden_ports):
	for forbidden in forbidden_ports:
		ports = expand_range(forbidden_ports[forbidden])
		for port in ports:
			if port in exposed_ports:
				return True

	return False

def getViolationGroups( secGroupSet, forbiddenPorts ):
	violations = []
	for secGroup in secGroupSet:
		ec2 = boto3.resource('ec2')
		security_group = ec2.SecurityGroup(secGroup)
		exposed_ports = find_exposed_ports( security_group.ip_permissions ) 
		if find_violation( exposed_ports, forbiddenPorts):
			violations.append(secGroup)

	return violations

def evaluate_compliance(configuration_item, rule_parameters):
	
	violationInstances = {}
	
	if configuration_item["resourceType"] == "AWS::EC2::SecurityGroup":
		if ( configuration_item["configuration"] ):
			triggerSecGroupId = configuration_item["configuration"]["groupId"]
			scope = determineEvaluationScopeFromTriggerSecGroup( triggerSecGroupId )
		else:
			return False
			
	elif configuration_item["resourceType"] == "AWS::EC2::Instance":
		instanceId = configuration_item["configuration"]["instanceId"]
		groups = secGroupsForInstanceId( instanceId )
		groupSet = set()
		for group in groups:
			groupSet.add( group['GroupId'] )
		scope = { "secGroupsToCheck" : groupSet,
				  "instancesToEvaluate" : { instanceId : groupSet } }
	else:
		return False
	
	instancesToEvaluate = scope['instancesToEvaluate']	
	violationGroups = getViolationGroups( scope['secGroupsToCheck'], rule_parameters )

	for instance in instancesToEvaluate:
		violationInstances[instance] = []
		for group in violationGroups:
			if group in instancesToEvaluate[instance]:
				violationInstances[instance].append(group)

	return violationInstances

def lambda_handler(event, context):

	#print( json.dumps(event) )

	invoking_event = json.loads(event["invokingEvent"])
	configuration_item = invoking_event["configurationItem"]
	rule_parameters = json.loads(event["ruleParameters"])

	result_token = "No token found."
	if "resultToken" in event:
		result_token = event["resultToken"]

	outputEvaluation = []

	evaluations = evaluate_compliance(configuration_item, rule_parameters)
	
	if evaluations:
		for evaluation in evaluations:	
			if (len( evaluations[evaluation] )):
				outputEvaluation.append ({
					"ComplianceResourceType": "AWS::EC2::Instance",
					"ComplianceResourceId": evaluation,
					"ComplianceType": "NON_COMPLIANT",
					"Annotation": "Instance has non compliant groups {}".format( ','.join(evaluations[evaluation]) ),
					"OrderingTimestamp": configuration_item["configurationItemCaptureTime"]
				})
			else:
				outputEvaluation.append ({
					"ComplianceResourceType": "AWS::EC2::Instance",
					"ComplianceResourceId": evaluation,
					"ComplianceType": "COMPLIANT",
					"Annotation": "This resource is compliant with the rule.",
					"OrderingTimestamp": configuration_item["configurationItemCaptureTime"]
				})
	
	else:
		outputEvaluation.append ({
			"ComplianceResourceType": configuration_item["resourceType"],
			"ComplianceResourceId": configuration_item["resourceId"],
			"ComplianceType": "NOT_APPLICABLE",
			"Annotation": "The rule doesn't apply to resources of type {} or this resource {} has been deleted.".format( configuration_item["resourceType"], configuration_item["resourceId"] ),
			"OrderingTimestamp": configuration_item["configurationItemCaptureTime"]
		})
	
	print (json.dumps(outputEvaluation))

	config = boto3.client("config")
	result = config.put_evaluations(
		Evaluations=outputEvaluation,
		ResultToken=result_token
	)