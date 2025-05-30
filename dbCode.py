#import pymysql
#import pymysql.cursors
import creds
import boto3
import bcrypt
import uuid
from datetime import datetime

#Create DynamoDB session and reference the users table
dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
table = dynamodb.Table('StudyGroups')

def create_user(name, username, password):
    user_id = str(uuid.uuid4())
    hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    table.put_item(
        Item={
            'PK': f'USER#{user_id}',
            'SK': f'METADATA#{user_id}',
            'username': username,
            'name': name,
            'password': hashed_pw,
            'join_date': datetime.now().isoformat(),
            'item_type': 'user'  # Changed from 'type' to 'item_type' to avoid conflicts
        }
    )
    return user_id

def get_user(username):
    response = table.query(
        IndexName='UsernameIndex',
        KeyConditionExpression='username = :username',
        FilterExpression='#item_type = :user_type',  # Use placeholder for reserved word
        ExpressionAttributeNames={
            '#item_type': 'item_type'  # Maps to the actual attribute name
        },
        ExpressionAttributeValues={
            ':username': username,
            ':user_type': 'user'
        }
    )
    items = response.get('Items', [])
    return items[0] if items else None

def update_user_profile(username, name, favouriteGenre):
    user = get_user(username)
    if not user:
        return False
    
    table.update_item(
        Key={
            'PK': user['PK'],
            'SK': user['SK']
        },
        UpdateExpression='SET #name = :name, favouriteGenre = :genre',
        ExpressionAttributeNames={'#name': 'name'},
        ExpressionAttributeValues={
            ':name': name,
            ':genre': favouriteGenre
        }
    )
    return True

def check_password(username, password):
    user = get_user(username)
    if not user:
        return False
    return bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8'))

def create_study_group(admin_user_id, name, location, description, meeting_time):
    group_id = str(uuid.uuid4())
    
    # Add group metadata
    table.put_item(
        Item={
            'PK': f'GROUP#{group_id}',
            'SK': f'METADATA#{group_id}',
            'name': name,
            'location': location,
            'description': description,
            'meeting_time': meeting_time,
            'admin_user_id': admin_user_id,
            'created_at': datetime.now().isoformat()
        }
    )
    
    # Add creator as admin member (with explicit role)
    table.put_item(
        Item={
            'PK': f'GROUP#{group_id}',
            'SK': f'MEMBER#{admin_user_id}',
            'join_date': datetime.now().isoformat(),
            'role': 'admin',  # Explicitly set role
            'user_id': admin_user_id  # Additional identifier
        }
    )
    
    # Add reverse lookup
    table.put_item(
        Item={
            'PK': f'USER#{admin_user_id}',
            'SK': f'GROUP#{group_id}',
            'group_name': name,
            'role': 'admin'  # Store role in reverse lookup too
        }
    )
    
    return group_id

def add_member_to_group(group_id, user_id, role='member'):
    table.put_item(
        Item={
            'PK': f'GROUP#{group_id}',
            'SK': f'MEMBER#{user_id}',
            'join_date': datetime.now().isoformat(),
            'role': role
        }
    )
    
    # Optional reverse lookup without group_name
    table.put_item(
        Item={
            'PK': f'USER#{user_id}',
            'SK': f'GROUP#{group_id}'
        }
    )

def get_all_groups():
    response = table.scan(
        FilterExpression='begins_with(PK, :pk) AND begins_with(SK, :sk)',
        ExpressionAttributeValues={
            ':pk': 'GROUP#',
            ':sk': 'METADATA#'
        }
    )
    return response.get('Items', [])

def get_group_members(group_id):
    response = table.query(
        KeyConditionExpression='PK = :pk AND begins_with(SK, :sk)',
        ExpressionAttributeValues={
            ':pk': f'GROUP#{group_id}',
            ':sk': 'MEMBER#'
        }
    )
    return response.get('Items', [])

def remove_group_member(group_id, user_id, requester_user_id):
    # Verify requester is admin
    admin_check = table.get_item(
        Key={
            'PK': f'GROUP#{group_id}',
            'SK': f'MEMBER#{requester_user_id}'
        }
    )
    
    if admin_check.get('Item', {}).get('role') != 'admin':
        return False
    
    # Remove member
    table.delete_item(
        Key={
            'PK': f'GROUP#{group_id}',
            'SK': f'MEMBER#{user_id}'
        }
    )
    
    # Optional: Remove reverse lookup
    table.delete_item(
        Key={
            'PK': f'USER#{user_id}',
            'SK': f'GROUP#{group_id}'
        }
    )
    
    return True

def get_meeting_status(meeting_time):
    """Determine if meeting is upcoming, today, or past"""
    # Implement your logic here based on meeting_time
    # This is a placeholder - you'll need to parse the meeting_time
    return 'upcoming'

def get_next_meeting(meeting_time):
    """Return formatted next meeting time"""
    # Implement your parsing logic here
    return meeting_time  # or formatted version
