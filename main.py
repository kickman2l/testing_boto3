import boto3


# Vars definition
trusted_list_filename = 'trusted_list'
threats_list_filename = 'threat_list'


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
                Name=trusted_list_filename,
                Format='TXT',
                Location='s3://' + bucket_name + '/' + trusted_list_filename,
                Activate=True
            )


# Create threat sets in regions
def create_threat_sets(detector_ids_data, bucket_name):
    for region in detector_ids_data:
        guard_duty = boto3.client('guardduty', region_name=region)
        for detector_id in detector_ids_data[region]:
            guard_duty.create_threat_intel_set(
                DetectorId=detector_id,
                Name=threats_list_filename,
                Format='TXT',
                Location='s3://' + bucket_name + '/' + threats_list_filename,
                Activate=True
            )


# Check threat and trusted lists exists
def check_treat_trusted_files(bucket_name):
    s3 = boto3.resource('s3')
    bucket = s3.Bucket(bucket_name)
    files_in_bucket = []
    for file in bucket.objects.all():
        files_in_bucket.append(file.key)
    if trusted_list_filename and threats_list_filename in files_in_bucket:
        return True
    else:
        return False


# Menu for script
def get_menu_choice():
    def print_menu():
        print(30 * '-', 'menu', 30 * '-')
        print('1. Enable guard duty for US regions.')
        print('2. Disable guard duty for US regions.')
        print('3. Add trusted and threat IP lists to guard duty.')
        print('4. Remove trusted and threat IP lists to guard duty.')
        print('5. Create trusted and threat files on S3.')
        print('6. Delete trusted and threat files on S3.')
        print('7. Edit trusted file.')
        print('8. Edit threat file.')
        print('9. Exit from the script.')
        print(66 * '-')

    loop = True

    while loop:
        print_menu()
        choice = input('Enter your choice [1-9]: ')

        if choice == '1':
            enable_guard_duty(get_us_aws_regions())
        elif choice == '2':
            disable_guard_duty(get_us_aws_regions())
        elif choice == '3':
            choice = ''
            while len(choice) == 0:
                choice = input('Enter S3 Bucket name:')
            if check_treat_trusted_files(choice):
                detectors_in_regions = get_detectors_ids_in_regions(get_us_aws_regions())
                create_ip_sets(detectors_in_regions, choice)
                create_threat_sets(detectors_in_regions, choice)
            else:
                print('Treat and trusted files not exists. Check S3.')
        elif choice == '4':
            print('Exit')
            loop = False  # This will make the while loop to end
        else:
            # Any inputs other than values 1-4 we print an error message
            input('Wrong menu selection. Press any key and try again.')


get_menu_choice()
