ADMIN_EMAIL = "admin@gmail.com"  # Changed from ADMIN_USERNAME
ADMIN_PASSWORD = "admin"
ADMIN_NAME = "Administrator"

import os
import re
from flask import Flask, render_template, request, redirect, url_for, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from geopy.geocoders import Nominatim
import folium
from folium.plugins import MarkerCluster
import json
from threading import Lock
import time
from datetime import datetime
from flask_mail import Mail, Message
import secrets
from itsdangerous import URLSafeTimedSerializer
from flask_wtf.csrf import CSRFProtect
from flask import flash  # Add this with your other Flask imports
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_mail import Mail, Message
from pathlib import Path




BASE_DIR = Path(__file__).parent
DATABASE_PATH = BASE_DIR / 'instance' / 'family_tracker.db'

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///family_tracker.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['LOCATION_UPDATE_INTERVAL'] = 300  # 5 minutes in seconds




# Flask-Mail Configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # Use your SMTP server
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'areebameerkhan@gmail.com'  # Your email
app.config['MAIL_PASSWORD'] = 'dyks ymxm unmh svpm'  # Your email password

#app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
#app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = 'areebameerkhan@gmail.com'



#app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DATABASE_PATH}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False





mail = Mail(app)

# Password reset token generator
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])





@app.context_processor
def inject_now():
    return {'now': datetime.utcnow()}

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


csrf = CSRFProtect(app)

# Database Models
# In your models (replace the existing User, Family, Location classes)
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)  # This is our identifier
    password_hash = db.Column(db.String(128))
    name = db.Column(db.String(100))
    dob = db.Column(db.Date)  # Add date of birth field
    family_id = db.Column(db.Integer, db.ForeignKey('family.id'))
    locations = db.relationship('Location', backref='user', lazy=True)
    last_active = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)
    reset_token = db.Column(db.String(120), unique=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.email}>'

class Family(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    join_code = db.Column(db.String(10), unique=True, nullable=False)
    members = db.relationship('User', backref='family', lazy=True)

class Location(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)
    address = db.Column(db.String(200))
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    source = db.Column(db.String(20))  # 'gps', 'network', 'manual'



def create_admin_account():
    with app.app_context():
        admin = User.query.filter_by(email=ADMIN_EMAIL).first()
        if not admin:
            admin = User(
                email=ADMIN_EMAIL,
                name=ADMIN_NAME,
                dob=datetime(1990, 1, 1).date(),  # Default admin DOB
                is_active=True
            )
            admin.set_password(ADMIN_PASSWORD)
            db.session.add(admin)
            db.session.commit()
            print("Admin account created successfully")

# Initialize database
def initialize_database():
    with app.app_context():
        # Create the instance directory if it doesn't exist
        instance_path = BASE_DIR / 'instance'
        instance_path.mkdir(exist_ok=True)
        
        # Create tables if they don't exist
        db.create_all()
        
        # Create admin account if it doesn't exist
        create_admin_account()





@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Helper functions
def get_address_from_coords(lat, lng):
    geolocator = Nominatim(user_agent="family_tracker")
    try:
        location = geolocator.reverse(f"{lat}, {lng}")
        return location.address if location else "Unknown location"
    except:
        return "Unknown location"

def generate_join_code():
    import random
    import string
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))

def create_family_map(locations):
    if not locations:
        return None
    
    # Create map centered on the first location
    family_map = folium.Map(
        location=[locations[0]['latitude'], locations[0]['longitude']],
        zoom_start=12
    )
    
    marker_cluster = MarkerCluster().add_to(family_map)
    
    for loc in locations:
        status = "Online" if loc['is_active'] else f"Last seen: {loc['last_active']}"
        popup_text = f"<b>{loc['name']}</b><br>{loc['address']}<br>{status}"
        icon_color = 'green' if loc['is_active'] else 'gray'
        
        folium.Marker(
            [loc['latitude'], loc['longitude']],
            popup=popup_text,
            tooltip=loc['name'],
            icon=folium.Icon(color=icon_color, icon='user')
        ).add_to(marker_cluster)
    
    return family_map._repr_html_()

# Background location updater
location_lock = Lock()

def update_user_location(user_id, lat, lng, source='gps'):
    with location_lock:
        address = get_address_from_coords(lat, lng)
        
        new_location = Location(
            user_id=user_id,
            latitude=lat,
            longitude=lng,
            address=address,
            source=source
        )
        db.session.add(new_location)
        
        user = User.query.get(user_id)
        user.last_active = datetime.utcnow()
        user.is_active = True
        db.session.commit()

# Routes
@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form['email']
        name = request.form['name']
        password = request.form['password']
        dob_str = request.form['dob']  # Get DOB from form
        
        try:
            dob = datetime.strptime(dob_str, '%Y-%m-%d').date()  # Convert string to date
        except ValueError:
            return render_template('register.html', error='Invalid date format. Use YYYY-MM-DD')
        
        # Validate email format
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            return render_template('register.html', error='Invalid email address')
        
        # Check if email already exists
        if User.query.filter_by(email=email).first():
            return render_template('register.html', error='Email already registered')
        
        # Create new user
        user = User(email=email, name=name, dob=dob)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        login_user(user)
        return redirect(url_for('dashboard'))
    
    return render_template('register.html')






@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        
        if user and user.check_password(password):
            user.is_active = True
            user.last_active = datetime.utcnow()
            db.session.commit()
            login_user(user)
            
            if user.email == ADMIN_EMAIL:  # Changed from username check
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('dashboard'))
        
        return render_template('login.html', error='Invalid email or password')
    
    return render_template('login.html')



    

@app.route('/logout')
@login_required
def logout():
    user = current_user
    user.is_active = False
    db.session.commit()
    logout_user()
    return redirect(url_for('home'))




@app.route('/admin')
@login_required
def admin_dashboard():
    if current_user.email != ADMIN_EMAIL:
        abort(403)
    
    all_users = User.query.all()
    all_families = Family.query.all()
    
    user_data = []
    for user in all_users:
        last_location = Location.query.filter_by(user_id=user.id)\
                            .order_by(Location.timestamp.desc())\
                            .first()
        
        user_data.append({
            'id': user.id,
            'email': user.email,  # This is the key field
            'name': user.name,
            'family': user.family.name if user.family else "No Family",
            'is_active': user.is_active,
            'last_active': user.last_active.strftime('%Y-%m-%d %H:%M:%S') if user.last_active else 'Never',
            'last_location': f"{last_location.latitude}, {last_location.longitude}" if last_location else 'Unknown',
            'location_time': last_location.timestamp.strftime('%Y-%m-%d %H:%M:%S') if last_location else 'Never'
        })
    
    family_data = []
    for family in all_families:
        family_data.append({
            'id': family.id,
            'name': family.name,
            'join_code': family.join_code,
            'member_count': len(family.members)
        })
    
    return render_template('admin.html',
                         users=user_data,
                         families=family_data,
                         user_count=len(user_data),
                         family_count=len(family_data))









@app.route('/dashboard')
@login_required
def dashboard():
    # Update user's active status
    current_time = datetime.utcnow()
    current_user.is_active = True
    current_user.last_active = current_time
    db.session.commit()
    
    family_members = []
    family_locations = []
    
    if current_user.family:
        family_members = User.query.filter_by(family_id=current_user.family_id).all()
        
        # Get latest location for each family member
        for member in family_members:
            latest_location = Location.query.filter_by(user_id=member.id)\
                                  .order_by(Location.timestamp.desc())\
                                  .first()
            if latest_location:
                time_diff = current_time - (member.last_active or datetime.min)
                is_active = member.is_active and time_diff < timedelta(minutes=10)
                
                family_locations.append({
                    'user_id': member.id,
                    'email': member.email,  # Changed from username to email
                    'name': member.name,
                    'latitude': latest_location.latitude,
                    'longitude': latest_location.longitude,
                    'address': latest_location.address,
                    'timestamp': latest_location.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                    'last_active': member.last_active.strftime('%Y-%m-%d %H:%M:%S') if member.last_active else 'Never',
                    'is_active': is_active,
                    'time_diff_seconds': time_diff.total_seconds()
                })
    
    map_html = create_family_map(family_locations) if family_locations else None
    
    return render_template('dashboard.html', 
                         family=current_user.family,
                         family_members=family_members,
                         family_locations=family_locations,
                         map_html=map_html,
                         current_time=current_time,
                         timedelta=timedelta)









@app.route('/create_family', methods=['POST'])
@login_required
def create_family():
    if current_user.family:
        return redirect(url_for('dashboard'))
    
    family_name = request.form['family_name']
    join_code = generate_join_code()
    
    family = Family(name=family_name, join_code=join_code)
    db.session.add(family)
    db.session.commit()
    
    current_user.family = family
    db.session.commit()
    
    return redirect(url_for('dashboard'))

@app.route('/join_family', methods=['POST'])
@login_required
def join_family():
    if current_user.family:
        return redirect(url_for('dashboard'))
    
    join_code = request.form['join_code']
    family = Family.query.filter_by(join_code=join_code).first()
    
    if not family:
        return render_template('dashboard.html', error='Invalid join code')
    
    current_user.family = family
    db.session.commit()
    
    return redirect(url_for('dashboard'))

@app.route('/update_location', methods=['POST'])
@login_required
def update_location():
    data = request.get_json()
    lat = data.get('latitude')
    lng = data.get('longitude')
    source = data.get('source', 'gps')
    
    if not lat or not lng:
        return jsonify({'status': 'error', 'message': 'Missing coordinates'}), 400
    
    update_user_location(current_user.id, lat, lng, source)
    
    return jsonify({
        'status': 'success',
        'message': 'Location updated'
    })

@app.route('/get_locations')
@login_required
def get_locations():
    if not current_user.family:
        return jsonify({'status': 'error', 'message': 'Not in a family'}), 400
    
    family_members = User.query.filter_by(family_id=current_user.family_id).all()
    locations = []
    
    for member in family_members:
        latest_location = Location.query.filter_by(user_id=member.id)\
                              .order_by(Location.timestamp.desc())\
                              .first()
        if latest_location:
            is_active = member.is_active and \
                      (datetime.utcnow() - member.last_active) < timedelta(minutes=10)
            
            locations.append({
                'user_id': member.id,
                'username': member.username,
                'name': member.name,
                'latitude': latest_location.latitude,
                'longitude': latest_location.longitude,
                'address': latest_location.address,
                'timestamp': latest_location.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                'last_active': member.last_active.strftime('%Y-%m-%d %H:%M:%S') if member.last_active else '',
                'is_active': is_active
            })
    
    return jsonify({'status': 'success', 'locations': locations})

@app.route('/background_location', methods=['POST'])
@login_required
def background_location():
    data = request.get_json()
    lat = data.get('latitude')
    lng = data.get('longitude')
    
    if lat and lng:
        update_user_location(current_user.id, lat, lng, source='background')
    
    return jsonify({'status': 'success'})



@app.route('/admin/search', methods=['GET'])
@login_required
def admin_search():
    if current_user.email != ADMIN_EMAIL:
        abort(403)
    
    search_query = request.args.get('q', '').strip()
    
    user_data = []
    family_data = []
    
    if search_query:
        search_pattern = f"%{search_query}%"
        
        # Search in both email and name fields
        matched_users = db.session.query(User).filter(
            db.or_(
                User.email.ilike(search_pattern),
                User.name.ilike(search_pattern)
            )
        ).order_by(User.email).all()
        
        for user in matched_users:
            last_location = Location.query.filter_by(user_id=user.id)\
                                .order_by(Location.timestamp.desc())\
                                .first()
            
            user_data.append({
                'id': user.id,
                'email': user.email,
                'name': user.name,
                'family': user.family.name if user.family else "No Family",
                'is_active': user.is_active,
                'last_active': user.last_active.strftime('%Y-%m-%d %H:%M:%S') if user.last_active else 'Never',
                'last_location': f"{last_location.latitude}, {last_location.longitude}" if last_location else 'Unknown',
                'location_time': last_location.timestamp.strftime('%Y-%m-%d %H:%M:%S') if last_location else 'Never'
            })
    else:
        return redirect(url_for('admin_dashboard'))
    
    return render_template('admin.html',
                        users=user_data,
                        families=family_data,
                        user_count=len(user_data),
                        family_count=len(family_data),
                        search_query=search_query)









@csrf.exempt  # Only if you're using CSRFProtect and want to exempt this route
@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if current_user.email != ADMIN_EMAIL:
        abort(403)
    
    user_to_delete = User.query.get_or_404(user_id)
    
    # Prevent admin from deleting themselves
    if user_to_delete.email == ADMIN_EMAIL:
        flash('Cannot delete the admin account', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    try:
        # Get the family before deleting the user
        family = user_to_delete.family
        
        # Delete all locations associated with the user first
        Location.query.filter_by(user_id=user_id).delete()
        
        # Then delete the user
        db.session.delete(user_to_delete)
        
        # Check if this was the last member of the family
        if family and len(family.members) == 0:  # After deletion, check if family is empty
            db.session.delete(family)
            flash('User and their family deleted successfully', 'success')
        else:
            flash('User deleted successfully', 'success')
            
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting user: {str(e)}', 'danger')
    
    return redirect(url_for('admin_dashboard'))



@app.route('/debug_users')
@login_required
def debug_users():
    if current_user.email != ADMIN_EMAIL:  # Changed from username check
        abort(403)
    
    # Rest of the debug code remains the same...
    
    all_users = User.query.all()
    debug_info = []
    for user in all_users:
        debug_info.append({
            'id': user.id,
            'username': user.username,
            'exists': True
        })
    
    return jsonify({
        'total_users': len(all_users),
        'users': debug_info
    })








@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        if not email:
            flash('Please enter your email address', 'danger')
            return redirect(url_for('forgot_password'))
        
        user = User.query.filter_by(email=email).first()
        
        # Always show success message, even if email doesn't exist (security best practice)
        if user:
            try:
                # Generate secure token
                token = serializer.dumps(user.email, salt='password-reset')
                user.reset_token = token
                db.session.commit()
                
                # Create reset email
                reset_url = url_for('reset_password', token=token, _external=True)
                msg = Message(
                    'Password Reset Request',
                    recipients=[user.email],
                    sender=app.config['MAIL_DEFAULT_SENDER']
                )
                msg.body = f'''Hello {user.name},
                
You requested a password reset for your account.
Click this link to reset your password:
{reset_url}

This link will expire in 1 hour.

If you didn't request this, please ignore this email.
'''
                # Send email
                mail.send(msg)
                
            except Exception as e:
                db.session.rollback()
                app.logger.error(f"Failed to send reset email to {email}: {str(e)}")
        
        # Show success message regardless of whether email exists (security measure)
        flash('If an account exists with this email, you will receive a password reset link shortly.', 'success')
        return redirect(url_for('login'))
    
    return render_template('forgot_password.html')





@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    try:
        email = serializer.loads(token, salt='password-reset', max_age=3600)  # 1 hour expiration
        user = User.query.filter_by(email=email, reset_token=token).first()
        
        if not user:
            flash('Invalid or expired reset link', 'danger')
            return redirect(url_for('forgot_password'))
        
        if request.method == 'POST':
            new_password = request.form.get('password')
            confirm_password = request.form.get('confirm_password')
            
            if new_password != confirm_password:
                flash('Passwords do not match', 'danger')
                return redirect(request.url)
            
            user.set_password(new_password)
            user.reset_token = None
            db.session.commit()
            
            flash('Your password has been updated successfully', 'success')
            return redirect(url_for('login'))
        
        return render_template('reset_password.html', token=token)
    
    except:
        flash('Invalid or expired reset link', 'danger')
        return redirect(url_for('forgot_password'))


@app.before_request
def before_request():
    if current_user.is_authenticated:
        current_user.last_active = datetime.utcnow()
        db.session.commit()


if __name__ == '__main__':
    initialize_database()
    app.run(debug=True)