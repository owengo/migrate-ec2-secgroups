#!/usr/bin/python
# -*- coding: utf8 -*-

import os
import logging
import argparse
import sys

import boto.ec2
import boto.exception
import boto.vpc

logging.basicConfig(format='%(asctime)s %(pathname)s:%(lineno)s [%(levelname)s] %(message)s', level=logging.INFO)


def migrate_groups(origin, dest, groups, aws_key, aws_secret, aws_security_token):
	from_conn = boto.vpc.connect_to_region(origin, aws_access_key_id=aws_key, aws_secret_access_key=aws_secret, security_token = aws_security_token)
	to_conn = boto.vpc.connect_to_region(dest, aws_access_key_id=aws_key, aws_secret_access_key=aws_secret, security_token = aws_security_token)

	# test connections
	try:
		from_conn.describe_account_attributes()
	except Exception as e:
		logging.error('please make sure that you set your EC2 credentials and that they are correct')
		sys.exit(0)

	try:
		to_conn.describe_account_attributes()
	except Exception as e:
		logging.error('please make sure that you set your EC2 credentials and that they are correct')
		sys.exit(0)

	to_vpcs = to_conn.get_all_vpcs()
	if (len(to_vpcs) != 1):
	  print "There are %s vpc!" % to_vpcs.count()
	  sys.exit(1)

	dest_vpc = to_vpcs.pop(0)
	print "Dest vpc is %s " % dest_vpc

	from_groups = from_conn.get_all_security_groups()
	to_groups = [ group.name for group in to_conn.get_all_security_groups() ]
	dry_run = None
	for from_group in from_groups:
		if from_group.name in groups:
			if from_group.name in to_groups:
				logging.warn("security group with name '%s' already exists on region '%s'" % (from_group.name, dest))
				continue
			else:
			        print "Copying %s" % from_group.name
				try:
				       if origin == dest:
				           raise BotoClientError('Unable to copy to the same Region')
				       print "Creating on %s" % dest
				       sg = to_conn.create_security_group(
				           from_group.name,
				           from_group.description,
				           vpc_id=dest_vpc.id
				       )
				       source_groups = []
				       print "Creating rules"
				       for rule in from_group.rules:
				           print "Rule: %s" % rule
				           for grant in rule.grants:
				               grant_nom = grant.name or grant.group_id
				               if grant_nom:
				                   print "Grant_nom: %s" % grant_nom
				                   if grant_nom not in source_groups:
				                       source_groups.append(grant_nom)
				                       #sg.authorize(None, None, None, None, grant, dry_run=dry_run)
				               else:
				                   print "Grant_nom is none?"
				                   sg.authorize(rule.ip_protocol, rule.from_port, rule.to_port, grant.cidr_ip, dry_run=dry_run)


				except Exception as e:
					logging.error("error trying to migrate group '%s' from '%s' to '%s' %s" % (from_group.name, origin, dest, e))
					continue
				logging.info("migrated group '%s' from '%s' to '%s' successfully!" % (from_group.name, origin, dest))


if __name__ == '__main__':
	
	AWS_KEY = ''
	AWS_SECRET = ''
	AWS_SECURITY_TOKEN = None

	parser = argparse.ArgumentParser(description='example: migrate.py us-west-2 eu-west-1 default prod-security ...')
	parser.add_argument('origin', help='EC2 region to export FROM')
	parser.add_argument('dest', help='EC2 region to import TO')
	parser.add_argument('groups', nargs='+', help='EC2 security groups\' names')
	parser.add_argument('--key', nargs='?', help='AWS_KEY')
	parser.add_argument('--secret', nargs='?', help='AWS_SECRET')
	args = parser.parse_args()

	from_region = args.origin
	to_region = args.dest
	groups = args.groups

	# 1st check - command line arguments
	if args.key and args.secret:
		AWS_KEY = args.key
		AWS_SECRET = args.secret

	# 2nd check - aws_credentials.cfg
	if not AWS_KEY or not AWS_SECRET:
		props_dict = {}
		for line in open('aws_credentials.cfg', 'r').readlines():
			line = line.strip()
			prop, value = line.split('=')
			props_dict[prop] = value

		if 'AWS_KEY' in props_dict and 'AWS_SECRET' in props_dict:
			AWS_KEY = props_dict['AWS_KEY']
			AWS_SECRET = props_dict['AWS_SECRET']

	# 3rd check - environment variables
	if not AWS_KEY or not AWS_SECRET:
		print "reading env"
		if 'AWS_ACCESS_KEY_ID' in os.environ and 'AWS_SECRET_ACCESS_KEY' in os.environ:
			AWS_KEY = os.environ['AWS_ACCESS_KEY_ID']
			AWS_SECRET = os.environ['AWS_SECRET_ACCESS_KEY']
			AWS_SECURITY_TOKEN = os.environ['AWS_SECURITY_TOKEN']
	
	migrate_groups(origin=from_region, dest=to_region, groups=groups, aws_key=AWS_KEY, aws_secret=AWS_SECRET, aws_security_token=AWS_SECURITY_TOKEN)
