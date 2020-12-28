""" docstring

"""
import boto3
from main import TRUSTED_LIST_NAME
from main import THREAT_LIST_NAME


# Get available us regions
def get_us_aws_regions():
    ec2 = boto3.client('ec2')
    response = ec2.describe_regions()
    regions_list = []
    for region in response['Regions']:
        if 'us-' in region['RegionName']:
            regions_list.append(region['RegionName'])
    return regions_list


# Enable guard duty in available regions
def enable_guard_duty(regions_list):
    for reg in regions_list:
        guard_duty = boto3.client('guardduty', region_name=reg)
        guard_duty.create_detector(Enable=True)


# Disable guard duty in available regions
def disable_guard_duty(regions_list):
    for reg in regions_list:
        guard_duty = boto3.client('guardduty', region_name=reg)
        detector_ids = guard_duty.list_detectors()['DetectorIds']
        for detector_id in detector_ids:
            guard_duty.delete_detector(DetectorId=detector_id)


# Get detector id's
def get_detectors_ids_in_regions(regions_list):
    detector_ids = dict()
    for reg in regions_list:
        guard_duty = boto3.client('guardduty', region_name=reg)
        detector_ids[reg] = guard_duty.list_detectors()['DetectorIds']
    return detector_ids


# Create ip sets in regions
def create_ip_sets(detector_ids_data, bucket_name):
    for region in detector_ids_data:
        guard_duty = boto3.client('guardduty', region_name=region)
        for detector_id in detector_ids_data[region]:
            guard_duty.create_ip_set(
                DetectorId=detector_id,
                Name=TRUSTED_LIST_NAME,
                Format='TXT',
                Location='s3://' + bucket_name + '/' + TRUSTED_LIST_NAME,
                Activate=True
            )


# Create threat sets in regions
def create_threat_sets(detector_ids_data, bucket_name):
    for region in detector_ids_data:
        guard_duty = boto3.client('guardduty', region_name=region)
        for detector_id in detector_ids_data[region]:
            guard_duty.create_threat_intel_set(
                DetectorId=detector_id,
                Name=THREAT_LIST_NAME,
                Format='TXT',
                Location='s3://' + bucket_name + '/' + THREAT_LIST_NAME,
                Activate=True
            )
