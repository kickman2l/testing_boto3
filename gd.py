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
                delete_rules(reg, detector_id)
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
            if not detector_ids[reg]:
                print_err("No active detectors found. Enable Guard Duty first.")
                return False
        return detector_ids
    except BaseException as err:
        print_err(err)


def create_ip_sets(detector_ids_data, bucket_name):
    """ Create ip sets in regions. """
    try:
        for region in detector_ids_data:
            guard_duty = boto3.client('guardduty', region_name=region)
            for detector_id in detector_ids_data[region]:
                ip_set_id = check_ip_set_exist(region, detector_id)
                if ip_set_id:
                    guard_duty.update_ip_set(
                        DetectorId=detector_id,
                        IpSetId=ip_set_id,
                        Name=TRUSTED_LIST_NAME,
                        Location=f"s3://{bucket_name}/{TRUSTED_LIST_NAME}",
                        Activate=True
                    )
                else:
                    guard_duty.create_ip_set(
                        DetectorId=detector_id,
                        Name=TRUSTED_LIST_NAME,
                        Format='TXT',
                        Location=f"s3://{bucket_name}/{TRUSTED_LIST_NAME}",
                        Activate=True
                    )
    except BaseException as err:
        print_err(err)


def check_ip_set_exist(region, detector_id):
    """ Check is ip_set exist in region """
    try:
        guard_duty = boto3.client('guardduty', region_name=region)
        ip_set_in_region = guard_duty.list_ip_sets(DetectorId=detector_id)
        if ip_set_in_region['IpSetIds']:
            for ip_set in ip_set_in_region['IpSetIds']:
                res = guard_duty.get_ip_set(DetectorId=detector_id, IpSetId=ip_set)
                if TRUSTED_LIST_NAME == res['Name']:
                    return ip_set
        return False
    except BaseException as err:
        print_err(err)


def check_threat_set_exist(region, detector_id):
    """ Check is threat_set exist in region """
    try:
        guard_duty = boto3.client('guardduty', region_name=region)
        threat_set_in_region = guard_duty.list_threat_intel_sets(DetectorId=detector_id)
        if threat_set_in_region['ThreatIntelSetIds']:
            for threat_set in threat_set_in_region['ThreatIntelSetIds']:
                res = guard_duty.get_threat_intel_set(
                    DetectorId=detector_id,
                    ThreatIntelSetId=threat_set
                )
                if THREAT_LIST_NAME == res['Name']:
                    return threat_set
        return False
    except BaseException as err:
        print_err(err)


def create_threat_sets(detector_ids_data, bucket_name):
    """ Create threat sets in regions. """
    try:
        for region in detector_ids_data:
            guard_duty = boto3.client('guardduty', region_name=region)
            for detector_id in detector_ids_data[region]:
                threat_set_id = check_threat_set_exist(region, detector_id)
                if threat_set_id:
                    guard_duty.update_threat_intel_set(
                        DetectorId=detector_id,
                        ThreatIntelSetId=threat_set_id,
                        Name=THREAT_LIST_NAME,
                        Location=f"s3://{bucket_name}/{THREAT_LIST_NAME}",
                        Activate=True
                    )
                else:
                    guard_duty.create_threat_intel_set(
                        DetectorId=detector_id,
                        Name=THREAT_LIST_NAME,
                        Format='TXT',
                        Location=f"s3://{bucket_name}/{THREAT_LIST_NAME}",
                        Activate=True
                    )
    except BaseException as err:
        print_err(err)


def delete_rules(region, detector_id):
    """ Delete IP set list"""
    try:
        ip_set = check_ip_set_exist(region, detector_id)
        threat_set = check_threat_set_exist(region, detector_id)
        client = boto3.client('guardduty', region_name=region)
        if ip_set:
            client.delete_ip_set(
                DetectorId=detector_id,
                IpSetId=ip_set
            )
        if threat_set:
            client.delete_threat_intel_set(
                DetectorId=detector_id,
                ThreatIntelSetId=threat_set
            )
    except BaseException as err:
        print_err(err)
