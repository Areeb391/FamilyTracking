import os
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

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///family_tracker.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['LOCATION_UPDATE_INTERVAL'] = 300  # 5 minutes in seconds


@app.context_processor
def inject_now():
    return {'now': datetime.utcnow()}

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Database Models
# In your models (replace the existing User, Family, Location classes)
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    name = db.Column(db.String(100))
    family_id = db.Column(db.Integer, db.ForeignKey('family.id'))
    locations = db.relationship('Location', backref='user', lazy=True)
    last_active = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)

    # Add these methods to your User class
    def set_password(self, password):
        """Create hashed password."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Check hashed password."""
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'

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

# Initialize database
with app.app_context():
    db.create_all()

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
        username = request.form['username']
        name = request.form['name']
        password = request.form['password']
        
        if User.query.filter_by(username=username).first():
            return render_template('register.html', error='Username already exists')
        
        user = User(username=username, name=name)
        user.set_password(password)  # This will now work
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
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            user.is_active = True
            user.last_active = datetime.utcnow()
            db.session.commit()
            login_user(user)
            return redirect(url_for('dashboard'))
        
        return render_template('login.html', error='Invalid username or password')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    user = current_user
    user.is_active = False
    db.session.commit()
    logout_user()
    return redirect(url_for('home'))

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
                    'username': member.username,
                    'name': member.name,
                    'latitude': latest_location.latitude,
                    'longitude': latest_location.longitude,
                    'address': latest_location.address,
                    'timestamp': latest_location.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                    'last_active': member.last_active.strftime('%Y-%m-%d %H:%M:%S') if member.last_active else 'Never',
                    'is_active': is_active,
                    'time_diff_seconds': time_diff.total_seconds()  # For template comparison
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

@app.before_request
def before_request():
    if current_user.is_authenticated:
        current_user.last_active = datetime.utcnow()
        db.session.commit()

if __name__ == '__main__':
    app.run(debug=True)