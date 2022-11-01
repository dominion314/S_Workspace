#https://www.youtube.com/watch?v=PZDKUUgUhAc
#This script will copy a file from one s3 bucket to another. 
import boto3

session = boto3.Session(
aws_access_key_id = 'ASIAUGBMBWZXBMAYUPON',
aws_secret_access_key='zXfQ7IFs0TYW0fMQt6Fhshs9QlIOJlaheCRQSY2T'
)

s3 = session.resource('s3')

#s3 = session.resource('s3') #You can use this instead of lines 3-8 if you sign in via AWS SSO.
copy_source = {
    'Bucket': '0101-prod-eleveo-archive-8bd50eb414be', #Source bucket
    'Filename' : 'Voice/Eleveo/2022/10/30/342_2022-10-30_15-45-00.909/Tasks/208/Eleveo/2022-10-28..2022-10-29/B446503D80165541EDAF80097188E7F4.mp3' # Need to modify to pull last 5 files
}

bucket = s3.Bucket('0101-prod-transcription') #Destination bucket
bucket.copy(copy_source, '23/') # Filename and directory you want the data to be copied to

