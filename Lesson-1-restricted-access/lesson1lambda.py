import boto3
iam = boto3.resource('iam')
# import json ## uncomment this, if you are wanting to enable debug.

denyPolicyArn = 'POLICYARN::REPLACEME'
iamAdminGroup = 'iamadmins'

def lambda_handler( event, context ):
	# print("Event data:")
	# print( json.dumps( event, sort_keys=True, indent=4, separators=(',', ': ') ) ) ## you will need import json above also.

	if event["detail"]["userIdentity"]["type"] != 'IAMUser': # Test if the user type is IAM:
		print('User is not an IAMUser. Done.')
		return
	else:
		userName = event["detail"]["userIdentity"]["userName"] # Get the userName of the user:
		print("userName is {}".format(userName))

		# Loop through the user's group memberships
		user = iam.User(userName)
		group_iterator = user.groups.all()

		# If the user is a member of the 'admin' group all is good.
		for group in group_iterator:
			if group.name == iamAdminGroup:
				print("User {} is a member of the iamadmins group '{}'. Done.".format( userName, iamAdminGroup ))
				return

		# The user is not a member of the 'iamadmins' group...they shouldn't be doing this so.....
		# Revoke users access to IAM
		print ("User '{}' is not a member of the iamadmins group '{}'".format( userName, iamAdminGroup ))
		revokeIamAccess(userName)

# Attach the 'revoke' customer managed policy to the user.
def revokeIamAccess(userName):

	policy = iam.Policy(denyPolicyArn)

	try:
		print("Attaching revoke policy '{}' to user '{}'.".format( denyPolicyArn, userName ))
		policy.attach_user( UserName=userName )
	except Exception as e:
		print("{}".format(e) )
		revokeIamAccessInline( userName )
