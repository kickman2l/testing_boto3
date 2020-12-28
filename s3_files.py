import boto3
import os
import fileinput
from main import TRUSTED_LIST_NAME
from main import THREAT_LIST_NAME


# Check threat and trusted lists exists
def check_treat_trusted_files(bucket_name):
    s3 = boto3.resource('s3')
    bucket = s3.Bucket(bucket_name)
    files_in_bucket = []
    for file in bucket.objects.all():
        files_in_bucket.append(file.key)
    if TRUSTED_LIST_NAME and THREAT_LIST_NAME in files_in_bucket:
        return True
    else:
        return False


# Check file exists on bucket
def check_is_file_exists(bucket_name, filename):
    s3 = boto3.resource('s3')
    bucket = s3.Bucket(bucket_name)
    files_in_bucket = []
    for file in bucket.objects.all():
        files_in_bucket.append(file.key)
    if filename in files_in_bucket:
        return True
    else:
        return False


# Delete trusted and threat files from S3
def delete_tt_files_from_s3(bucket):
    s3 = boto3.resource('s3')
    s3.Object(bucket, TRUSTED_LIST_NAME).delete()
    s3.Object(bucket, THREAT_LIST_NAME).delete()


# Create tmp directory
def add_new_tt_files_to_s3(bucket):
    path = os.getcwd() + "/tmp/"
    os.mkdir(path)
    if not os.path.exists(path + TRUSTED_LIST_NAME):
        with open(path + TRUSTED_LIST_NAME, 'w'):
            pass
    if not os.path.exists(path + THREAT_LIST_NAME):
        with open(path + THREAT_LIST_NAME, 'w'):
            pass
    s3_client = boto3.client('s3')
    s3_client.upload_file(os.path.abspath(path + TRUSTED_LIST_NAME), bucket, TRUSTED_LIST_NAME)
    s3_client.upload_file(os.path.abspath(path + THREAT_LIST_NAME), bucket, THREAT_LIST_NAME)


# Cleanup tmp directory
def cleanup_tmp_dir():
    path = os.getcwd() + '/tmp/'
    if os.path.isdir(path):
        for i in os.listdir(path):
            os.remove(path + i)
        os.rmdir(path)


# Create tmp directory
def create_tmp_dir():
    path = os.getcwd() + '/tmp/'
    if not os.path.isdir(path):
        os.mkdir(path)


# Download file from s3 bucket.
def download_file_from_s3(bucket, filename):
    path = os.getcwd() + '/tmp/' + filename
    s3 = boto3.client('s3')
    s3.download_file(bucket, filename, path)


# Add string to file
def add_rule_to_file(filename, data):
    path = os.getcwd() + '/tmp/' + filename
    with open(path, 'a') as file:
        file.write(data+"\n")


# Remove rule from file
def remove_rule_from_file(filename,rule):
    print("qwe123 remove")


# Replace rule in file
def replace_rule_in_file(filename, num, new_val):
    path = os.getcwd() + '/tmp/' + filename
    with open(path, 'r') as file:
        data = file.readlines()
    value_to_replace = data[int(num)]
    with fileinput.FileInput(path, inplace=True) as file:
        for line in file:
            print(line.replace(value_to_replace, new_val + '\n'), end='')


# List rules in file
def list_rules_in_file(filename):
    count = 0
    path = os.getcwd() + '/tmp/' + filename
    with open(path, 'r') as file:
        for line in file:
            print('[' + str(count) + ']  ' + line)
            count += 1


# Upload edited file to s3
def upload_tt_file(bucket_name, filename):
    path = os.getcwd() + '/tmp/' + filename
    s3_client = boto3.client('s3')
    s3_client.upload_file(os.path.abspath(path), bucket_name, filename)
