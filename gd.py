""" Guard Duty. """
import boto3
from cst import TRUSTED_LIST_NAME, THREAT_LIST_NAME, print_err


def get_us_aws_regions():
    """ Get available us regions. """
    try:
        resp = boto3.client('ec2').describe_regions()
        return [reg['RegionName'] for reg in resp['Regions'] if 'us-' in reg['RegionName']]
    except BaseException as err:
        print_err(err)


def enable(regions_list):
    """ Enable guard duty in available regions. """
    try:
        for reg in regions_list:
            guard_duty = boto3.client('guardduty', region_name=reg)
            guard_duty.create_detector(Enable=True)
    except BaseException as err:
        print_err(err)


def disable(regions_list):
    """ Disable guard duty in available regions. """
    try:
        for reg in regions_list:
            guard_duty = boto3.client('guardduty', region_name=reg)
            detector_ids = guard_duty.list_detectors()['DetectorIds']
            for detector_id in detector_ids:
                guard_duty.delete_detector(DetectorId=detector_id)
    except BaseException as err:
        print_err(err)


def get_detectors_ids(regions_list):
    """ Get detector id's. """
    try:
        detector_ids = {}
        for reg in regions_list:
            guard_duty = boto3.client('guardduty', region_name=reg)
            detector_ids[reg] = guard_duty.list_detectors()['DetectorIds']
        return detector_ids
    except BaseException as err:
        print_err(err)


def create_ip_sets(detector_ids_data, bucket_name):
    """ Create ip sets in regions. """
    try:
        for region in detector_ids_data:
            guard_duty = boto3.client('guardduty', region_name=region)
            for detector_id in detector_ids_data[region]:
                guard_duty.create_ip_set(
                    DetectorId=detector_id,
                    Name=TRUSTED_LIST_NAME,
                    Format='TXT',
                    Location=f"s3://{bucket_name}/{TRUSTED_LIST_NAME}",
                    Activate=True
                )
    except BaseException as err:
        print_err(err)


def create_threat_sets(detector_ids_data, bucket_name):
    """ Create threat sets in regions. """
    try:
        for region in detector_ids_data:
            guard_duty = boto3.client('guardduty', region_name=region)
            for detector_id in detector_ids_data[region]:
                guard_duty.create_threat_intel_set(
                    DetectorId=detector_id,
                    Name=THREAT_LIST_NAME,
                    Format='TXT',
                    Location=f"s3://{bucket_name}/{THREAT_LIST_NAME}",
                    Activate=True
                )
    except BaseException as err:
        print_err(err)
