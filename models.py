from flask_sqlalchemy import SQLAlchemy
import datetime
from sqlalchemy.dialects.postgresql import JSONB

tz = datetime.timezone.utc

db = SQLAlchemy()

class Session(db.Model):
    __tablename__ = 'sessions'
    id = db.Column(db.String(1024), primary_key=True)
    iss =  db.Column(db.String(1024), nullable=False)
    token_endpoint = db.Column(db.String(1024), nullable=True)
    launch_token = db.Column(db.String(2048), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.datetime.now(tz=tz))
    endpoint_data = db.Column(JSONB)

    
    def __repr__(self):
        return f'<Session {self.iss}>'
        
