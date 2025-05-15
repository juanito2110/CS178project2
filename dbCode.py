#import pymysql
#import pymysql.cursors
import creds
import boto3
import bcrypt

#Create DynamoDB session and reference the users table
dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
user_table = dynamodb.Table('user')

def create_user(name, username, password):
  hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
  user_table.put_item(Item={
    'name': name,
    'username': username,
    'password': hashed_pw,
  })

def get_user(username):
  response = user_table.get_item(Key={'username': username})
  return response.get('Item')

def update_user_profile(username, name, favouriteGenre):
  user_table.update_item(
    Key={'username': username},
    UpdateExpression='SET name = :fn, favouriteGenre = :fGenre',
    ExpressionAttributeValues={
      ':fn': name,
      ':fGenre': favouriteGenre
    }
  )

def check_password(username, password):
  user = get_user(username)
  if not user:
    return False
  return bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8'))
