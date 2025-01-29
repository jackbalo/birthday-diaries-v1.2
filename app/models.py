from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Column, String, Boolean, Integer, ForeignKey, Index, Date, DateTime
from sqlalchemy.orm import relationship,backref
from datetime import datetime
from flask_login import UserMixin


db = SQLAlchemy()

class Users(db.Model, UserMixin):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(80), nullable=False)
    username = Column(String(80), nullable=False)
    email = Column(String(150), nullable=False, unique=True)
    phone = Column(String(20), nullable=True)
    dob = Column(String(20), nullable=True)
    hash = Column(String(200), nullable=True)
    password_set = Column(Boolean, default=False)
    google_id = Column(String(200), nullable=True, unique=True)
    confirmed = Column(Boolean, default=False)
    confirmed_on = Column(DateTime, nullable=True)
    totp_secret = Column(String, nullable=True, unique=True)
    last_otp_sent = Column(DateTime, nullable=True)

    __tableargs__ =  Index('username', username)


class Birthdays(db.Model):
    __tablename__ = 'birthdays'
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(80), nullable=False)
    birthdates = Column(Date, nullable=False)
    age = Column(Integer, nullable=False)
    email = Column(String(150), nullable=True)
    phone = Column(String(20), nullable=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    user = relationship('Users', backref=backref('birthdays',lazy=True, cascade="all, delete-orphan"))


class AuditLogs(db.Model):
    __tablename__ = 'audit_logs'
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    action = Column(String(80), nullable=False, unique=True)
    timestamp = Column(DateTime, nullable=False, default=(datetime.utcnow))
    user = relationship('Users', backref=backref('audit_logs',lazy=True, cascade="all, delete-orphan"))
    
