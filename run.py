#apt install python-pip -y
#apt install ipython -y
#pip install godaddypy
#pip install boto3

from godaddypy import Client, Account
import requests
import json
import boto3
import time
import argparse

# Create ACM client
access_key = 'DQDQFQQEQRR'
secret_key = 'DQDQWDQRFFQQDF/Q7'
region_singapore = 'ap-southeast-1'
region_us_east = 'us-east-1'

domain_url = "lagalaxy-vip.com"
domain_name = "lagalaxy-vip"

godaddy_public_key  ="QDQDQRQWRR"
godaddy_secret_key = "DQEWQE!RWWRWEQWQE"

lb_names = ['incap-sdccz02', 'incap-wmgbq03']

"""
	Start of API 
"""
def f_godaddy_update_dns(domain_url, cname_name, cname_value):
	global access_key
	global secret_key
	global region_singapore
	global region_us_east
	global godaddy_public_key
	global godaddy_secret_key
	try:
		default_cloudfront_url = "d3gzd6wua0nt7d.cloudfront.net"

		# Authenticate with the GoDaddy API using your API key and secret
		my_acct = Account(api_key=godaddy_public_key, api_secret=godaddy_secret_key)
		client = Client(my_acct)

		# Retrieve the existing CNAME records for your domain
		records = client.get_records(domain_url, 'CNAME')
		# # Modify the records as necessary
		client.add_record(domain_url, {'data':cname_value,'name':cname_name,'ttl':600, 'type':'CNAME'})
		for record in records:
			if str(record['name']) == 'ssl1':
				client.delete_records(domain_url, name='ssl1')
				client.delete_records(domain_url, name='ssl2')
				client.add_record(domain_url, {'data':cname_value,'name':cname_name,'ttl':600, 'type':'CNAME'})
				print "Replaced Success Domain: %s" % (str(domain_url))
				return True

	except Exception as e:
		if ("duplicate_record" in str(e).lower()):
			print "%s" % e
			return True

		if ("response data" in str(e).lower()):
			print "Error creating SSL certificates: %s" % e
			return False

def f_aws_create_certificate(region, domain_url):
	global access_key
	global secret_key
	global region_singapore
	global region_us_east
	global godaddy_public_key
	global godaddy_secret_key
    # Create Elastic Load Balancingv2 client
    acm = boto3.client('acm', aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region)

    # Define certificate parameters
    certificate_params = {
        'DomainName': domain_url,
        'SubjectAlternativeNames': ['*.'+domain_url],
        'ValidationMethod': 'DNS',
        'Tags': [
            {
                'Key': 'Name',
                'Value': domain_url
            }
        ]
    }

    try:
        # Request certificate in us-east-1 region
        response = acm.request_certificate(**certificate_params)
        # Check if certificate request was successful
        if response['CertificateArn']:
            print "Certificate creation successful - Domain: %s, Region: %s" % (str(domain_url), str(region))
            return True
        else:
            print "Certificate creation failed - Domain: %s, Region: %s" % (str(domain_url), str(region))
            return False
    except:
        print('An error occurred while creating certificate for domain %s.' % format(domain))
        return False

def f_aws_get_certificate(domain_url):
	global access_key
	global secret_key
	global region_singapore
	global region_us_east
	global godaddy_public_key
	global godaddy_secret_key
	client = boto3.client('acm', aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region_us_east)
	# List certificates and find the one with the matching domain name
	response = client.list_certificates()
	certificates = []
	while True:
		for cert in response['CertificateSummaryList']:
			if cert['DomainName'] == domain_url:
				cert_arn = cert['CertificateArn']
				cert_details = client.describe_certificate(CertificateArn=cert_arn)
				cname_records = cert_details['Certificate']['DomainValidationOptions'][0]['ResourceRecord']
				certificates.append({'arn': cert_arn, 'cname_name': cname_records['Name'], 'cname_value': cname_records['Value'], 'status': cert_details['Certificate']['Status']})

		if 'NextToken' not in response:
			break

		response = client.list_certificates(NextToken=response['NextToken'])

	return certificates

def f_aws_create_ec2(domain_name):
	global access_key
	global secret_key
	global region_singapore
	global region_us_east
	global godaddy_public_key
	global godaddy_secret_key
    # Create EC2 client
    ec2 = boto3.client('ec2', aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region_singapore)

    # Define EC2 instance parameters
    instance_params = {
        'ImageId': 'ami-073674c5cd389cf30',
        'InstanceType': 't2.medium',
        'KeyName': 'fattbet',
        'MinCount': 1,
        'MaxCount': 1,
        'NetworkInterfaces': [{
            'DeviceIndex': 0,
            'SubnetId': 'subnet-0c1a5282c17b86bd1',
            'Groups': ['sg-0c4cbd5df4800c8d5']
        }]
    }

    # Launch EC2 instance
    response = ec2.run_instances(**instance_params)

    # Get instance ID
    instance_id = response['Instances'][0]['InstanceId']

    # Wait for instance to start running
    print('Instance ' + instance_id + ' is starting...')
    while True:
        response = ec2.describe_instances(InstanceIds=[instance_id])
        instance_state = response['Reservations'][0]['Instances'][0]['State']['Name']
        if instance_state == 'running':
            print('Instance ' + instance_id + ' is running!')
            break
        print('Instance is still starting...')
        time.sleep(10)

    # Set instance name
    instance_name = 'web-'+domain_name
    tag_response = ec2.create_tags(Resources=[instance_id], Tags=[{'Key': 'Name', 'Value': instance_name}])
    print('Instance name set to: ' + instance_name)
    return instance_id

def f_aws_create_target_group(instance_id, domain_name):
	global access_key
	global secret_key
	global region_singapore
	global region_us_east
	global godaddy_public_key
	global godaddy_secret_key
	# Create Elastic Load Balancingv2 client
	elbv2 = boto3.client('elbv2', aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region_singapore)

	try:
		# Define target group parameters
		tg_params = {
			'Name': 'TGLB-Web-'+domain_name,
			'Protocol': 'HTTPS',
			'Port': 443,
			'VpcId': 'vpc-0d5f378990a88055d',
			'TargetType': 'instance',
			'HealthCheckProtocol': 'HTTP',
			'HealthCheckPath': '/',
			'HealthCheckPort': '80',
			'HealthCheckIntervalSeconds': 30,
			'HealthCheckTimeoutSeconds': 5,
			'HealthyThresholdCount': 5,
			'UnhealthyThresholdCount': 2,
			'Matcher': {
			'HttpCode': '200'
			}
		}

		# Create target group
		response = elbv2.create_target_group(**tg_params)

		# Get ARN of new target group
		tg_arn = response['TargetGroups'][0]['TargetGroupArn']

		# Register instances with target group
		instances = [
		{
		'Id': instance_id
		}
		]
		register_response = elbv2.register_targets(TargetGroupArn=tg_arn, Targets=instances)
		return True
	except Exception as e:
		return False

def f_aws_get_ec2_instance_ips(instance_id):
	global access_key
	global secret_key
	global region_singapore
	global region_us_east
	global godaddy_public_key
	global godaddy_secret_key
	# connect to EC2 using boto library
	conn = boto3.client('ec2', aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region_singapore)

	# Get information about the instance
	response = conn.describe_instances(InstanceIds=[instance_id])

	# Extract the IP addresses from the response
	internal_ip = response['Reservations'][0]['Instances'][0]['PrivateIpAddress']
	external_ip = response['Reservations'][0]['Instances'][0]['PublicIpAddress']

	# Print the IP addresses
	print('Internal IP:', internal_ip)
	print('External IP:', external_ip)
	result = [{
		'internal_ip': str(internal_ip),
		'external_ip': str(external_ip)
	}]
	return result

def f_aws_add_domain_load_balancer(certificate_arn, listener_arn, target_group_arn, instance_id):
	global access_key
	global secret_key
	global region_singapore
	global region_us_east
	global godaddy_public_key
	global godaddy_secret_key
	# Initialize the client for Elastic Load Balancing
	conn = boto3.client('elbv2', aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region_singapore)

	# Add the domain name to the certificate
	response = conn.add_listener_certificates(
	ListenerArn=listener_arn,
	Certificates=[
			{
				'CertificateArn': certificate_arn,
			},
		],
	)

	# Add the domain name to the load balancer
	response = conn.register_targets(
		TargetGroupArn=target_group_arn,
			Targets=[
			{
				'Id': instance_id,
				'Port': 443,
			},
		],
	)

	print('Domain added successfully.')
	return True

def f_aws_count_load_balancer_certificate():
	global access_key
	global secret_key
	global region_singapore
	global region_us_east
	global domain_url
	global domain_name
	global godaddy_public_key
	global godaddy_secret_key
	global lb_names

	result_arr = []
	conn = boto3.client('elbv2', aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region_singapore)
	response = conn.describe_load_balancers()
	load_balancers = response['LoadBalancers']
	

	for lb in load_balancers:
		if lb['LoadBalancerName'] in lb_names:
			lb_arn = lb['LoadBalancerArn']
			# Load Balancer ARN
			# Replace your_listener_arn with the actual ARN of your listener			
			response = conn.describe_listeners(LoadBalancerArn=lb_arn)
			total_cert_count = 0
			for listener in response['Listeners']:
				if listener['Protocol'] == 'HTTPS':
					listener_arn = listener['ListenerArn']
					lb_arn = listener['LoadBalancerArn'] 
					responseCert = conn.describe_listener_certificates(ListenerArn=listener_arn)
					cert_count = len(responseCert['Certificates'])
					total_cert_count += cert_count
					result = { 
						"name": lb['LoadBalancerName'], 
						"count": total_cert_count, 
						"ListenerArn": listener_arn,
						"LoadBalancerArn": lb_arn
					}
					result_arr.append(result)

	return result_arr

def f_aws_get_lowest_load_balancer():
	lbl_list = f_aws_count_load_balancer_certificate()
	lowest_count_item = min(lbl_list, key=lambda x: x['count'])
	if (lowest_count_item['count'] < 50):
		return lowest_count_item

	print lowest_count_item
	return False

def f_aws_get_target_group_arn(domain_name):
	try:
		# Create Elastic Load Balancingv2 client
		conn = boto3.client('elbv2', aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region_singapore)

		target_group = "TGLB-Web-"+domain_name
		response = conn.describe_target_groups(Names=[target_group])
		your_target_group_arn = response['TargetGroups'][0]['TargetGroupArn']
		return your_target_group_arn
	except Exception as e:
		print "There are no Target Group Created for %s" % str(domain_name)

def f_aws_rds_inbound_rules(domain_name, external_ip):
	global access_key
	global secret_key
	global region_singapore
	global region_us_east
	global godaddy_public_key
	global godaddy_secret_key
	# Initialize the client for Amazon RDS
	conn = boto3.client('rds', aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region_singapore)
	response = conn.describe_db_security_groups(
		DBSecurityGroupName=security_group_id
	)
	print response
	# Define the parameters for the inbound rule
	protocol = 'tcp'
	port = 3306
	security_group_id = 'sg-0357b9219ab0fb6c3'
	security_group_name = 'pro-RDS-MAIN-02'
	description = 'web-'+domain_name
	ip_range = external_ip+'/32 #'+description
	response = conn.authorize_db_security_group_ingress(
		CIDRIP=ip_range,
		EC2SecurityGroupName=security_group_name,
		EC2SecurityGroupId=security_group_id,
		EC2SecurityGroupOwnerId='275428848088'
	)
	print('Inbound rule added successfully.')

def f_aws_create_distribution(lb_type, domain_url):
	global access_key
	global secret_key
	global region_singapore
	global region_us_east
	global godaddy_public_key
	global godaddy_secret_key
	conn = boto3.client('cloudfront', aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region_us_east)
	distribution_config_tmp = {
	        "CallerReference": "<DOMAIN_HERE>",
	        "Aliases": {
	            "Quantity": 2,
	            "Items": [
	                "*.<DOMAIN_HERE>",
	                "<DOMAIN_HERE>"
	            ]
	        },
	        "DefaultRootObject": "",
	        "Origins": {
	            "Quantity": 2,
	            "Items": [
	                {
	                    "Id": "<distribution_id>",
	                    "DomainName": "<distribution_domain_name>",
	                    "OriginPath": "",
	                    "CustomHeaders": {
	                        "Quantity": 1,
	                        "Items": [
	                            {
	                                "HeaderName": "randomme",
	                                "HeaderValue": "9zpar@f"
	                            }
	                        ]
	                    },
	                    "CustomOriginConfig": {
	                        "HTTPPort": 80,
	                        "HTTPSPort": 443,
	                        "OriginProtocolPolicy": "https-only",
	                        "OriginSslProtocols": {
	                            "Quantity": 3,
	                            "Items": [
	                                "TLSv1",
	                                "TLSv1.1",
	                                "TLSv1.2"
	                            ]
	                        },
	                        "OriginReadTimeout": 30,
	                        "OriginKeepaliveTimeout": 5
	                    }
	                },
	                {
	                    "Id": "S3-tu1x5g-wlwebs/v1_antibot/royalebet55",
	                    "DomainName": "tu1x5g-wlwebs.s3.amazonaws.com",
	                    "OriginPath": "/v1_antibot/royalebet55",
	                    "CustomHeaders": {
	                        "Quantity": 0
	                    },
	                    "S3OriginConfig": {
	                        "OriginAccessIdentity": "origin-access-identity/cloudfront/E2IMPX83IVNP1E"
	                    }
	                }
	            ]
	        },
	        "OriginGroups": {
	            "Quantity": 0
	        },
	        "DefaultCacheBehavior": {
	            "TargetOriginId": "<distribution_id>",
	            "ForwardedValues": {
	                "QueryString": True,
	                "Cookies": {
	                    "Forward": "all"
	                },
	                "Headers": {
	                    "Quantity": 1,
	                    "Items": [
	                        "*"
	                    ]
	                },
	                "QueryStringCacheKeys": {
	                    "Quantity": 0
	                }
	            },
	            "TrustedSigners": {
	                "Enabled": False,
	                "Quantity": 0
	            },
	            "ViewerProtocolPolicy": "redirect-to-https",
	            "MinTTL": 0,
	            "AllowedMethods": {
	                "Quantity": 7,
	                "Items": [
	                    "HEAD",
	                    "DELETE",
	                    "POST",
	                    "GET",
	                    "OPTIONS",
	                    "PUT",
	                    "PATCH"
	                ],
	                "CachedMethods": {
	                    "Quantity": 2,
	                    "Items": [
	                        "HEAD",
	                        "GET"
	                    ]
	                }
	            },
	            "SmoothStreaming": False,
	            "DefaultTTL": 86400,
	            "MaxTTL": 31536000,
	            "Compress": True,
	            "LambdaFunctionAssociations": {
	                "Quantity": 0
	            },
	            "FieldLevelEncryptionId": ""
	        },
	        "CacheBehaviors": {
	            "Quantity": 4,
	            "Items": [
	                {
	                    "PathPattern": "/security/*",
	                    "TargetOriginId": "S3-tu1x5g-wlwebs/v1_antibot/royalebet55",
	                    "ForwardedValues": {
	                        "QueryString": True,
	                        "Cookies": {
	                            "Forward": "all"
	                        },
	                        "Headers": {
	                            "Quantity": 0
	                        },
	                        "QueryStringCacheKeys": {
	                            "Quantity": 0
	                        }
	                    },
	                    "TrustedSigners": {
	                        "Enabled": False,
	                        "Quantity": 0
	                    },
	                    "ViewerProtocolPolicy": "allow-all",
	                    "MinTTL": 0,
	                    "AllowedMethods": {
	                        "Quantity": 2,
	                        "Items": [
	                            "HEAD",
	                            "GET"
	                        ],
	                        "CachedMethods": {
	                            "Quantity": 2,
	                            "Items": [
	                                "HEAD",
	                                "GET"
	                            ]
	                        }
	                    },
	                    "SmoothStreaming": False,
	                    "DefaultTTL": 0,
	                    "MaxTTL": 0,
	                    "Compress": True,
	                    "LambdaFunctionAssociations": {
	                        "Quantity": 0
	                    },
	                    "FieldLevelEncryptionId": ""
	                },
	                {
	                    "PathPattern": "*assets/*",
	                    "TargetOriginId": "<distribution_id>",
	                    "ForwardedValues": {
	                        "QueryString": False,
	                        "Cookies": {
	                            "Forward": "none"
	                        },
	                        "Headers": {
	                            "Quantity": 1,
	                            "Items": [
	                                "Host"
	                            ]
	                        },
	                        "QueryStringCacheKeys": {
	                            "Quantity": 0
	                        }
	                    },
	                    "TrustedSigners": {
	                        "Enabled": False,
	                        "Quantity": 0
	                    },
	                    "ViewerProtocolPolicy": "redirect-to-https",
	                    "MinTTL": 7200,
	                    "AllowedMethods": {
	                        "Quantity": 7,
	                        "Items": [
	                            "HEAD",
	                            "DELETE",
	                            "POST",
	                            "GET",
	                            "OPTIONS",
	                            "PUT",
	                            "PATCH"
	                        ],
	                        "CachedMethods": {
	                            "Quantity": 2,
	                            "Items": [
	                                "HEAD",
	                                "GET"
	                            ]
	                        }
	                    },
	                    "SmoothStreaming": False,
	                    "DefaultTTL": 86400,
	                    "MaxTTL": 604800,
	                    "Compress": True,
	                    "LambdaFunctionAssociations": {
	                        "Quantity": 0
	                    },
	                    "FieldLevelEncryptionId": ""
	                },
	                {
	                    "PathPattern": "*theme/*",
	                    "TargetOriginId": "<distribution_id>",
	                    "ForwardedValues": {
	                        "QueryString": False,
	                        "Cookies": {
	                            "Forward": "none"
	                        },
	                        "Headers": {
	                            "Quantity": 1,
	                            "Items": [
	                                "Host"
	                            ]
	                        },
	                        "QueryStringCacheKeys": {
	                            "Quantity": 0
	                        }
	                    },
	                    "TrustedSigners": {
	                        "Enabled": False,
	                        "Quantity": 0
	                    },
	                    "ViewerProtocolPolicy": "redirect-to-https",
	                    "MinTTL": 7200,
	                    "AllowedMethods": {
	                        "Quantity": 7,
	                        "Items": [
	                            "HEAD",
	                            "DELETE",
	                            "POST",
	                            "GET",
	                            "OPTIONS",
	                            "PUT",
	                            "PATCH"
	                        ],
	                        "CachedMethods": {
	                            "Quantity": 2,
	                            "Items": [
	                                "HEAD",
	                                "GET"
	                            ]
	                        }
	                    },
	                    "SmoothStreaming": False,
	                    "DefaultTTL": 86400,
	                    "MaxTTL": 604800,
	                    "Compress": True,
	                    "LambdaFunctionAssociations": {
	                        "Quantity": 0
	                    },
	                    "FieldLevelEncryptionId": ""
	                },
	                {
	                    "PathPattern": "*LA911/*",
	                    "TargetOriginId": "<distribution_id>",
	                    "ForwardedValues": {
	                        "QueryString": False,
	                        "Cookies": {
	                            "Forward": "none"
	                        },
	                        "Headers": {
	                            "Quantity": 1,
	                            "Items": [
	                                "Host"
	                            ]
	                        },
	                        "QueryStringCacheKeys": {
	                            "Quantity": 0
	                        }
	                    },
	                    "TrustedSigners": {
	                        "Enabled": False,
	                        "Quantity": 0
	                    },
	                    "ViewerProtocolPolicy": "redirect-to-https",
	                    "MinTTL": 7200,
	                    "AllowedMethods": {
	                        "Quantity": 7,
	                        "Items": [
	                            "HEAD",
	                            "DELETE",
	                            "POST",
	                            "GET",
	                            "OPTIONS",
	                            "PUT",
	                            "PATCH"
	                        ],
	                        "CachedMethods": {
	                            "Quantity": 2,
	                            "Items": [
	                                "HEAD",
	                                "GET"
	                            ]
	                        }
	                    },
	                    "SmoothStreaming": False,
	                    "DefaultTTL": 86400,
	                    "MaxTTL": 604800,
	                    "Compress": True,
	                    "LambdaFunctionAssociations": {
	                        "Quantity": 0
	                    },
	                    "FieldLevelEncryptionId": ""
	                }
	            ]
	        },
	        "CustomErrorResponses": {
	            "Quantity": 1,
	            "Items": [
	                {
	                    "ErrorCode": 403,
	                    "ResponsePagePath": "/security/<RESTRICT_FILE_HERE>.html",
	                    "ResponseCode": "200",
	                    "ErrorCachingMinTTL": 300
	                }
	            ]
	        },
	        "Comment": "<DOMAIN_HERE>",
	        "Logging": {
	            "Enabled": False,
	            "IncludeCookies": False,
	            "Bucket": "",
	            "Prefix": ""
	        },
	        "PriceClass": "PriceClass_200",
	        "Enabled": True,
	        "ViewerCertificate": {
	            "ACMCertificateArn": "<SSL_ARN_HERE>",
	            "SSLSupportMethod": "sni-only",
	            "MinimumProtocolVersion": "TLSv1.1_2016",
	            "Certificate": "SSL_ARN_HERE",
	            "CertificateSource": "acm"
	        },
	        "Restrictions": {
	            "GeoRestriction": {
	                "RestrictionType": "none",
	                "Quantity": 0
	            }
	        },
	        "WebACLId": "arn:aws:wafv2:us-east-1:275428848088:global/webacl/WebSecACL-CloudFront/53d9a9ca-87a4-4776-89f1-1230c6dc3a73",
	        "HttpVersion": "http2",
	        "IsIPV6Enabled": False
	}
	lb_type_list = {
		"incap-sdccz02" : {
			"distribution_id": "ELB-incap-sdccz02-707376118",
			"distribution_domain_name": "incap-sdccz02-707376118.ap-southeast-1.elb.amazonaws.com"
		},
		"incap-wmgbq03" : {
			"distribution_id": "ELB-incap-wmgbq03-1840528531",
			"distribution_domain_name": "incap-wmgbq03-1840528531.ap-southeast-1.elb.amazonaws.com"
		}
	}

	str_distribution_config = json.dumps(distribution_config_tmp)
	str_distribution_config = str_distribution_config.replace("<DOMAIN_HERE>", domain_url)
	str_distribution_config = str_distribution_config.replace("<RESTRICT_FILE_HERE>", "restrict_lagalaxy")
	str_distribution_config = str_distribution_config.replace("<SSL_ARN_HERE>", f_aws_get_certificate(domain_url)[0]['arn'])
	str_distribution_config = str_distribution_config.replace("<distribution_id>", lb_type_list[lb_type]['distribution_id'])
	str_distribution_config = str_distribution_config.replace("<distribution_domain_name>",  lb_type_list[lb_type]['distribution_domain_name'])
	distribution_config = json.loads(str_distribution_config)
	response = conn.create_distribution(
		DistributionConfig=distribution_config
	)

	print(response['Distribution']['DomainName'])

def f_aws_attach_cloudfront(domain_url, cloudfront_url):
	global access_key
	global secret_key
	global region_singapore
	global region_us_east
	global godaddy_public_key
	global godaddy_secret_key
	default_cloudfront_url = "d3gzd6wua0nt7d.cloudfront.net"

	# Authenticate with the GoDaddy API using your API key and secret
	my_acct = Account(api_key=godaddy_public_key, api_secret=godaddy_secret_key)
	client = Client(my_acct)

	# Retrieve the existing CNAME records for your domain
	records = client.get_records(domain_url, 'CNAME')
	# # Modify the records as necessary
	for record in records:
		if str(record['data']) == default_cloudfront_url:
			print "%s = From: %s, To: %s" % (str(record['name']), str(record['data']), str(cloudfront_url))
			# Update the CNAME record for the www subdomain
			record['data'] = cloudfront_url
			client.update_record(domain_url, record)

"""
	End of API 
"""
