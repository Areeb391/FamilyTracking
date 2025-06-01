import os
from flask import Flask, render_template, request, redirect, url_for, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from geopy.geocoders import Nominatim
import folium
from folium.plugins import MarkerCluster
import json

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///family_tracker.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    name = db.Column(db.String(100))
    family_id = db.Column(db.Integer, db.ForeignKey('family.id'))
    locations = db.relationship('Location', backref='user', lazy=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

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

# Initialize database
with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Helper functions
def get_address_from_coords(lat, lng):
    geolocator = Nominatim(user_agent="family_tracker")
    location = geolocator.reverse(f"{lat}, {lng}")
    return location.address if location else "Unknown location"

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
        popup_text = f"{loc['username']}<br>{loc['address']}<br>{loc['timestamp']}"
        folium.Marker(
            [loc['latitude'], loc['longitude']],
            popup=popup_text,
            tooltip=loc['username']
        ).add_to(marker_cluster)
    
    return family_map._repr_html_()

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
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('dashboard'))
        
        return render_template('login.html', error='Invalid username or password')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
def dashboard():
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
                family_locations.append({
                    'username': member.username,
                    'name': member.name,
                    'latitude': latest_location.latitude,
                    'longitude': latest_location.longitude,
                    'address': latest_location.address,
                    'timestamp': latest_location.timestamp.strftime('%Y-%m-%d %H:%M:%S')
                })
    
    map_html = create_family_map(family_locations) if family_locations else None
    
    return render_template('dashboard.html', 
                         family=current_user.family,
                         family_members=family_members,
                         family_locations=family_locations,
                         map_html=map_html)

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
    
    if not lat or not lng:
        return jsonify({'status': 'error', 'message': 'Missing coordinates'}), 400
    
    address = get_address_from_coords(lat, lng)
    
    new_location = Location(
        user_id=current_user.id,
        latitude=lat,
        longitude=lng,
        address=address
    )
    db.session.add(new_location)
    db.session.commit()
    
    return jsonify({
        'status': 'success',
        'message': 'Location updated',
        'address': address,
        'timestamp': new_location.timestamp.strftime('%Y-%m-%d %H:%M:%S')
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
            locations.append({
                'username': member.username,
                'name': member.name,
                'latitude': latest_location.latitude,
                'longitude': latest_location.longitude,
                'address': latest_location.address,
                'timestamp': latest_location.timestamp.strftime('%Y-%m-%d %H:%M:%S')
            })
    
    return jsonify({'status': 'success', 'locations': locations})

if __name__ == '__main__':
    app.run(debug=True)