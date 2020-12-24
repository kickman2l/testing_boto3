import boto3


# VARS DEFINITION
trusted_list_filename = 'trusted_list'
threats_list_filename = 'threat_list'


# GET ONLY US REGIONS
def get_us_aws_regions():
    ec2 = boto3.client('ec2')
    response = ec2.describe_regions()
    regions_list = []
    for region in response['Regions']:
        if 'us-' in region['RegionName']:
            regions_list.append(region['RegionName'])
    return regions_list


# ENABLE GUARD DUTY FOR US REGIONS
def enable_guard_duty(regions_list):
    for reg in regions_list:
        guard_duty = boto3.client('guardduty', region_name=reg)
        guard_duty.create_detector(Enable=True)


# DISABLE GUARD DUTY FOR US REGIONS
def disable_guard_duty(regions_list):
    for reg in regions_list:
        guard_duty = boto3.client('guardduty', region_name=reg)
        detector_ids = guard_duty.list_detectors()['DetectorIds']
        for detector_id in detector_ids:
            guard_duty.delete_detector(DetectorId=detector_id)


# GET DETECTOR IDS IN REGIONS
def get_detectors_ids_in_regions(regions_list):
    detector_ids = dict()
    for reg in regions_list:
        guard_duty = boto3.client('guardduty', region_name=reg)
        detector_ids[reg] = guard_duty.list_detectors()['DetectorIds']
    return detector_ids


# CREATE IP SETS FOR DETECTORS IN SPECIFIED REGIONS
def create_ip_sets(detector_ids_data):
    for region in detector_ids_data:
        guard_duty = boto3.client('guardduty', region_name=region)
        for detector_id in detector_ids_data[region]:
            guard_duty.create_ip_set(
                DetectorId=detector_id,
                Name='Trusted',
                Format='TXT',
                Location='s3://dg-tests/' + trusted_list_filename,
                Activate=True
            )


# CREATE THREAT LIST FOR DETECTORS IN SPECIFIED REGIONS
def create_threat_sets(detector_ids_data):
    for region in detector_ids_data:
        guard_duty = boto3.client('guardduty', region_name=region)
        for detector_id in detector_ids_data[region]:
            guard_duty.create_threat_intel_set(
                DetectorId=detector_id,
                Name='Threat',
                Format='TXT',
                Location='s3://dg-tests/' + threats_list_filename,
                Activate=True
            )


# CHECK IS THREAD AND TRUSTED LISTS EXISTS


# disable_guard_duty(get_us_aws_regions())
# enable_guard_duty(get_us_aws_regions())
data = get_detectors_ids_in_regions(get_us_aws_regions())
# create_ip_sets(data)
create_threat_sets(data)