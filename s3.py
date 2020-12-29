""" S3 actions. """
import fileinput
import os
import boto3
from cst import TRUSTED_LIST_NAME, THREAT_LIST_NAME, print_err


def check_threat_trusted_files(bucket_name):
    """ Check threat and trusted lists exists. """
    try:
        bucket = boto3.resource('s3').Bucket(bucket_name)
        if TRUSTED_LIST_NAME and THREAT_LIST_NAME in [f.key for f in bucket.objects.all()]:
            return True
        return False
    except BaseException as err:
        print_err(err)


def check_is_file_exists(bucket_name, filename):
    """ Check file exists on bucket. """
    try:
        bucket = boto3.resource('s3').Bucket(bucket_name)
        if filename in [f.key for f in bucket.objects.all()]:
            return True
        return False
    except BaseException as err:
        print_err(err)


def delete_tt_files_from_s3(bucket):
    """ Delete trusted and threat files from S3. """
    try:
        s3_bucket = boto3.resource('s3')
        s3_bucket.Object(bucket, TRUSTED_LIST_NAME).delete()
        s3_bucket.Object(bucket, THREAT_LIST_NAME).delete()
        return True
    except BaseException as err:
        print_err(err)


def add_new_tt_files_to_s3(bucket):
    """ Create tmp directory. """
    try:
        path = f"{os.getcwd()}/tmp/"
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
        return True
    except BaseException as err:
        print_err(err)


def cleanup_tmp_dir():
    """ Cleanup tmp directory. """
    try:
        path = f"{os.getcwd()}/tmp/"
        if os.path.isdir(path):
            for i in os.listdir(path):
                os.remove(path + i)
            os.rmdir(path)
    except BaseException as err:
        print_err(err)


def create_tmp_dir():
    """ Create tmp directory. """
    try:
        path = f"{os.getcwd()}/tmp/"
        if not os.path.isdir(path):
            os.mkdir(path)
    except BaseException as err:
        print_err(err)


def download_file_from_s3(bucket, filename):
    """ Download file from s3 bucket. """
    try:
        path = f"{os.getcwd()}/tmp/{filename}"
        boto3.client('s3').download_file(bucket, filename, path)
    except BaseException as err:
        print_err(err)


def add_rule_to_file(filename, data):
    """ Add string to file. """
    try:
        path = f"{os.getcwd()}/tmp/{filename}"
        with open(path, 'a') as file:
            file.write(data + "\n")
    except BaseException as err:
        print_err(err)


def remove_rule_from_file(filename, num):
    """ Remove rule from file. """
    try:
        path = f"{os.getcwd()}/tmp/{filename}"
        with open(path, 'r') as file:
            data = file.readlines()
        data.pop(int(num))
        with open(path, 'w') as file:
            for line in data:
                file.write(line)
    except BaseException as err:
        print_err(err)


def check_rules_in_file_exists(filename):
    """ Replace rule in file. """
    try:
        path = f"{os.getcwd()}/tmp/{filename}"
        with open(path, 'r') as file:
            data = file.readlines()
            if data:
                return True
        return False
    except BaseException as err:
        print_err(err)


def replace_rule_in_file(filename, num, new_val):
    """ Replace rule in file. """
    try:
        path = f"{os.getcwd()}/tmp/{filename}"
        with open(path, 'r') as file:
            data = file.readlines()
        value_to_replace = data[int(num)]
        with fileinput.FileInput(path, inplace=True) as file:
            for line in file:
                print(line.replace(value_to_replace, new_val + '\n'), end='')
    except BaseException as err:
        print_err(err)


def list_rules_in_file(filename):
    """ List rules in file. """
    count = 0
    path = os.getcwd() + '/tmp/' + filename
    with open(path, 'r') as file:
        for line in file:
            print('[' + str(count) + ']  ' + line)
            count += 1


def upload_tt_file(bucket_name, filename):
    """ Upload edited file to s3. """
    path = os.getcwd() + '/tmp/' + filename
    s3_client = boto3.client('s3')
    s3_client.upload_file(os.path.abspath(path), bucket_name, filename)
