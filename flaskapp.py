from flask import Flask
from flask import render_template, request, redirect, url_for, session, flash
import creds
import json
from dbCode import *
from functools import wraps

app = Flask(__name__)

app.secret_key = '4ef54da3a383945d62d05217ea6a43f40e18323e9753b4edf06e4e1c850ef7c5'

@app.template_filter('is_member')
def is_member_filter(group_pk, user_groups):
    return any(group['PK'] == group_pk for group in user_groups)  

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form.get('name')
        username = request.form.get('username')
        password = request.form.get('password')

        if get_user(username):
            flash("Username already exists. Try another one.", "danger")
            return redirect(url_for('signup'))

        create_user(name, username, password)

        return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = get_user(username)
        if user and check_password(username, password):
            session['user_id'] = user['PK'].split('#')[1]  # Extract UUID from PK
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid username or password", "danger")
            return redirect(url_for('login'))

    return render_template('login.html')

"""@app.route('/index')
@login_required
def index():
  if 'user_id' not in session:
        return redirect(url_for('login'))
  
  return render_template('index.html')"""

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

#Study groups functionality
@app.route('/create_group', methods=['GET', 'POST'])
@login_required
def create_group():
    if request.method == 'POST':
        # Get form data directly from request.form
        name = request.form.get('name', '').strip()
        location = request.form.get('location', '').strip()
        description = request.form.get('description', '').strip()
        meeting_time = request.form.get('meeting_time', '').strip()
        
        # Simple validation
        if not all([name, location, description, meeting_time]):
            flash('Please fill all required fields', 'danger')
            return redirect(url_for('create_group'))
        
        try:
            group_id = create_study_group(
                admin_user_id=session['user_id'],
                name=name,
                location=location,
                description=description,
                meeting_time=meeting_time
            )
            flash(f'Group "{name}" created successfully!', 'success')
            return redirect(url_for('view_group', group_id=group_id))
        except Exception as e:
            flash('Error creating group. Please try again.', 'danger')
            app.logger.error(f"Group creation error: {str(e)}")
            return redirect(url_for('create_group'))
    
    # For GET requests, just render the template without form object
    return render_template('create_group.html')

@app.route('/dashboard')
@login_required
def dashboard():
    # Get all groups
    all_groups = []
    try:
        response = table.scan(
            FilterExpression='begins_with(PK, :pk) AND begins_with(SK, :sk)',
            ExpressionAttributeValues={
                ':pk': 'GROUP#',
                ':sk': 'METADATA#'
            }
        )
        all_groups = response.get('Items', [])
    except Exception as e:
        flash('Error loading groups', 'danger')
        app.logger.error(f"Error loading groups: {str(e)}")

    # Get groups where current user is member
    user_groups = []
    try:
        response = table.query(
            KeyConditionExpression='PK = :pk AND begins_with(SK, :sk)',
            ExpressionAttributeValues={
                ':pk': f'USER#{session["user_id"]}',
                ':sk': 'GROUP#'
            }
        )
        user_groups = [item['SK'].split('#')[1] for item in response.get('Items', [])]
    except Exception as e:
        flash('Error loading your groups', 'danger')
        app.logger.error(f"Error loading user groups: {str(e)}")

    return render_template('dashboard.html',
                         all_groups=all_groups,
                         user_groups=user_groups)

@app.route('/group/<group_id>')
@login_required
def view_group(group_id):
    # Get group details
    group = table.get_item(
        Key={
            'PK': f'GROUP#{group_id}',
            'SK': f'METADATA#{group_id}'
        }
    ).get('Item')
    
    if not group:
        flash('Group not found', 'danger')
        return redirect(url_for('dashboard'))

    # Get all members
    members = table.query(
        KeyConditionExpression='PK = :pk AND begins_with(SK, :sk)',
        ExpressionAttributeValues={
            ':pk': f'GROUP#{group_id}',
            ':sk': 'MEMBER#'
        }
    ).get('Items', [])

    # Fetch usernames for all members
    members_with_names = []
    for member in members:
        user_id = member['SK'].split('#')[1]
        # Get user details from USER table
        user = table.get_item(
            Key={
                'PK': f'USER#{user_id}',
                'SK': f'METADATA#{user_id}'
            }
        ).get('Item', {})
        
        members_with_names.append({
            **member,
            'username': user.get('username', user_id),  # Fallback to ID if no username
            'name': user.get('name', 'Unknown')         # Optional: include real name
        })

    # Check current user's status
    current_user_id = session['user_id']
    current_member = next(
        (m for m in members if m['SK'] == f'MEMBER#{current_user_id}'),
        None
    )
    
    is_admin = current_member and current_member.get('role') == 'admin'
    is_creator = group.get('admin_user_id') == current_user_id
    is_member = current_member is not None or is_creator

    return render_template('view_group.html',
                         group=group,
                         members=members_with_names,  # Updated members list
                         is_admin=is_admin,
                         is_member=is_member,
                         is_creator=is_creator)

@app.route('/join_group/<group_id>')
@login_required
def join_group(group_id):
    user_id = session['user_id']
    
    # Check if user is already a member or admin
    existing_membership = table.get_item(
        Key={
            'PK': f'GROUP#{group_id}',
            'SK': f'MEMBER#{user_id}'
        }
    ).get('Item')
    
    if existing_membership:
        if existing_membership.get('role') == 'admin':
            flash('You are the admin of this group', 'info')
        else:
            flash('You are already a member of this group', 'info')
        return redirect(url_for('view_group', group_id=group_id))
    
    try:
        # Add as regular member
        table.put_item(
            Item={
                'PK': f'GROUP#{group_id}',
                'SK': f'MEMBER#{user_id}',
                'join_date': datetime.now().isoformat(),
                'role': 'member'
            }
        )
        
        # Add reverse lookup
        table.put_item(
            Item={
                'PK': f'USER#{user_id}',
                'SK': f'GROUP#{group_id}',
                'group_name': 'New Group'  # You might want to fetch the actual name
            }
        )
        
        flash('Successfully joined the group!', 'success')
    except Exception as e:
        flash('Error joining group', 'danger')
        app.logger.error(f"Join group error: {str(e)}")
    
    return redirect(url_for('view_group', group_id=group_id))

@app.route('/leave_group/<group_id>')
@login_required
def leave_group(group_id):
    user_id = session['user_id']
    
    # Prevent admins from accidentally leaving
    membership = table.get_item(
        Key={
            'PK': f'GROUP#{group_id}',
            'SK': f'MEMBER#{user_id}'
        }
    ).get('Item')
    
    if membership and membership.get('role') == 'admin':
        flash('Admins cannot leave the group. Transfer admin rights first.', 'danger')
        return redirect(url_for('view_group', group_id=group_id))
    
    try:
        # Remove from group members
        table.delete_item(
            Key={
                'PK': f'GROUP#{group_id}',
                'SK': f'MEMBER#{user_id}'
            }
        )
        
        # Remove reverse lookup
        table.delete_item(
            Key={
                'PK': f'USER#{user_id}',
                'SK': f'GROUP#{group_id}'
            }
        )
        
        flash('You have left the group', 'success')
    except Exception as e:
        flash('Error leaving group', 'danger')
        app.logger.error(f"Leave group error: {str(e)}")
    
    return redirect(url_for('dashboard'))

@app.route('/remove_member/<group_id>/<user_id>')
@login_required
def remove_member(group_id, user_id):
    success = remove_group_member(group_id, user_id, session['user_id'])
    if success:
        flash('Member removed successfully', 'success')
    else:
        flash('You are not authorized to remove members', 'danger')
    return redirect(url_for('view_group', group_id=group_id))

if __name__ == '__main__':
    app.run(host= '0.0.0.0', port= '5000', debug=True)