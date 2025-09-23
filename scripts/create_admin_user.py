#!/usr/bin/env python3
"""
Script to create the initial admin user for the security platform
"""

import sys
import os
import getpass
from datetime import datetime

# Add the app directory to Python path
script_dir = os.path.dirname(__file__)

# Check if we're running in Docker container (where app is in /app)
if os.path.exists('/app/app'):
    # Running in Docker container
    sys.path.insert(0, '/app')
else:
    # Running from host - add backend directory
    backend_dir = os.path.join(os.path.dirname(script_dir), 'backend')
    sys.path.insert(0, backend_dir)

from app.db.session import SessionLocal, engine
from app.db.models_auth import User, UserRole, Base
from app.core.security import get_password_hash, validate_password_strength

def create_admin_user():
    """Create initial admin user"""
    # Create tables if they don't exist
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()

    try:
        # Check if any admin users already exist
        existing_admin = db.query(User).filter(User.role == UserRole.ADMIN).first()

        if existing_admin:
            print(f"Admin user already exists: {existing_admin.username}")
            try:
                response = input("Do you want to create another admin user? (y/N): ")
                if response.lower() != 'y':
                    return False
            except (EOFError, KeyboardInterrupt):
                # Handle non-interactive environments (like Docker containers)
                print("\nRunning in non-interactive mode. Use --force to create another admin user.")
                return False

        print("Creating initial admin user for NetworkMapper Security Platform")
        print("=" * 60)

        # Get user details
        try:
            while True:
                username = input("Enter admin username: ").strip()
                if not username:
                    print("Username cannot be empty!")
                    continue

                # Check if username exists
                if db.query(User).filter(User.username == username).first():
                    print("Username already exists! Please choose a different one.")
                    continue

                break

            email = input("Enter admin email (optional): ").strip() or None
            if email:
                # Validate email format if provided
                if '@' not in email:
                    print("Warning: Invalid email format, setting to None")
                    email = None
                # Check if email exists
                elif db.query(User).filter(User.email == email).first():
                    print("Email already exists! Setting to None")
                    email = None

            full_name = input("Enter full name (optional): ").strip() or None
        except (EOFError, KeyboardInterrupt):
            print("\nInteractive input not available. Exiting...")
            return False

        # Get password with validation
        try:
            while True:
                password = getpass.getpass("Enter admin password: ")
                password_confirm = getpass.getpass("Confirm password: ")

                if password != password_confirm:
                    print("Passwords don't match! Please try again.")
                    continue

                # Validate password strength
                validation = validate_password_strength(password)
                if not validation["valid"]:
                    print("Password validation failed:")
                    for error in validation["errors"]:
                        print(f"  - {error}")
                    continue

                break
        except (EOFError, KeyboardInterrupt):
            print("\nPassword input not available. Exiting...")
            return False

        # Create admin user
        admin_user = User(
            username=username,
            email=email,
            full_name=full_name,
            hashed_password=get_password_hash(password),
            role=UserRole.ADMIN,
            is_active=True,
            is_verified=True
        )

        db.add(admin_user)
        db.commit()
        db.refresh(admin_user)

        print("\n" + "=" * 60)
        print("✅ Admin user created successfully!")
        print(f"   Username: {admin_user.username}")
        print(f"   Email: {admin_user.email}")
        print(f"   Role: {admin_user.role}")
        print(f"   Created: {admin_user.created_at}")
        print("=" * 60)
        print("\nYou can now log in to the NetworkMapper Security Platform with these credentials.")

        return True

    except Exception as e:
        print(f"Error creating admin user: {e}")
        db.rollback()
        return False
    finally:
        db.close()


def create_sample_users():
    """Create sample users for testing different roles"""
    db = SessionLocal()

    try:
        print("\nCreating sample users for testing...")

        sample_users = [
            {
                "username": "analyst1",
                "email": None,
                "full_name": "Security Analyst",
                "role": UserRole.ANALYST,
                "password": "AnalystPassword123!"
            },
            {
                "username": "viewer1",
                "email": None,
                "full_name": "Security Viewer",
                "role": UserRole.VIEWER,
                "password": "ViewerPassword123!"
            },
            {
                "username": "auditor1",
                "email": None,
                "full_name": "Security Auditor",
                "role": UserRole.AUDITOR,
                "password": "AuditorPassword123!"
            }
        ]

        for user_data in sample_users:
            # Check if user already exists
            if db.query(User).filter(User.username == user_data["username"]).first():
                print(f"  User {user_data['username']} already exists, skipping...")
                continue

            user = User(
                username=user_data["username"],
                email=user_data["email"],
                full_name=user_data["full_name"],
                hashed_password=get_password_hash(user_data["password"]),
                role=user_data["role"],
                is_active=True,
                is_verified=True
            )

            db.add(user)
            print(f"  ✅ Created {user_data['role']} user: {user_data['username']}")

        db.commit()
        print("\nSample users created successfully!")
        print("\nTest credentials:")
        for user_data in sample_users:
            print(f"  {user_data['username']} / {user_data['password']} ({user_data['role']})")

    except Exception as e:
        print(f"Error creating sample users: {e}")
        db.rollback()
    finally:
        db.close()


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--samples":
        create_sample_users()
    else:
        success = create_admin_user()

        if success:
            response = input("\nWould you like to create sample users for testing? (y/N): ")
            if response.lower() == 'y':
                create_sample_users()