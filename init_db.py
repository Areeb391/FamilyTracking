from app import app, create_admin_account, db

with app.app_context():
    db.drop_all()
    db.create_all()
    create_admin_account()
    print("Database tables created successfully!")