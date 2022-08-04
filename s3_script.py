import boto3
from datetime import datetime, timezone

REGION_NAME = 'eu-west-3'
SECS_IN_DAY = 86400
#login
s3 = boto3.resource(
    service_name='s3',
    region_name='eu-west-3',
    aws_access_key_id='ASIAQON5W62NMFAGDRX5',
    aws_secret_access_key='BeuQX+jbpJav/wAbYKJ2h3Ribfbx+O+SLLiY6SaD'
)

BUCKETS = ['04-prod-bb-chat-2868b1d6c06b', '04-prod-bb-email-b3b3503572be', '04-prod-smtp-archive-02269a7c9af5',
            '04-prod-trchat-ef96c2c80017']

# bucket_name = '04-prod-bb-chat-2868b1d6c06b'

#list buckets
s3 = boto3.resource('s3')
buckets = s3.buckets.all()
for bucket in buckets:
    print(bucket)

# bucket = s3.Bucket(bucket_name)
# bucket.meta.client.list_objects_v2(Bucket=bucket_name, Delimeter='/')



# s3.llist_objects_v2()
# s3.list_objects_v2()


# client = boto3.client('s3', region_name=REGION_NAME)
# response = client.list_objects_v2(Bucket=bucket_name)
# last_object = sorted(response['Contents'], key=lambda item: item['LastModified'])[-1]


# print(last_object)
# print(last_object['LastModified'])
# print(response)
# sorted(response['Contents'])


def get_last_modified_file(bucket_name):
    client = boto3.client('s3', region_name=REGION_NAME)
    response = client.list_objects_v2(Bucket=bucket_name)
    last_object = sorted(response['Contents'], key=lambda item: item['LastModified'])[-1]
    return last_object

def is_uploaded_today(last_object):
    last_modified_datetime = last_object['LastModified']
    print(last_modified_datetime)
    current_date = datetime.now(timezone.utc)
    ts = (current_date - last_modified_datetime).total_seconds()
    if ts < SECS_IN_DAY:
        return True
    else:
        return False

def get_date_from_key(name):
    pass


def main():
    print(" ========== S3 Bucket Dashboard ======")
    print(" ========== Bucket Name,            Last Modified,        'Pass' ======")
    for bucket in BUCKETS:
        try:
            last_file = get_last_modified_file(bucket)
            last_file_datetime = last_file['LastModified'].strftime("%m/%d/%Y: %H:%M:%S")
            was_last_file_today = str(is_uploaded_today(last_file))
        except KeyError:
            continue
        print(bucket + '  |  ' +  last_file_datetime     +    '   |   ' +  was_last_file_today)

if __name__ == '__main__':
    main()