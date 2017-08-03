from sqlalchemy import Column, ForeignKey, Integer, String,Date,DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
import datetime
from sqlalchemy.sql import func
import bcrypt
 
Base = declarative_base()


class User(Base):
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)
    password = Column(String(250))
    phone_number = Column(String(250))
    picture = Column(String(250))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())




class Category(Base):
    __tablename__ = 'category'
   
    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)
    items = relationship('Item', backref='cat', lazy='dynamic')
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    @property
    def serialize(self):
       """Return object data in easily serializeable format"""
       return {
           'name': self.name,
           'id': self.id,
       }


class Item(Base):
    __tablename__ = 'item'

    name = Column(String(80), nullable=False)
    id = Column(Integer, primary_key=True)
    description = Column(String(250))
    price = Column(String(8))
    category_id = Column(Integer,ForeignKey('category.id'))
    category = relationship(Category)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    # @property
    # def serialize(self):
    #    """Return object data in easily serializeable format"""
    #    return {
    #        'name': self.name,
    #        'description': self.description,
    #        'id': self.id,
    #        'price': self.price,
    #        'category_id' : self.category_id,
    #        'user_id'  : self.user_id,
    #        'created_at' : self.created_at,
    #        'updated_at' : self.updated_at
    #    }

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
            'name': self.name,
            'description': self.description,
            'id': self.id,
            'price': self.price,
            'category_id' : self.category_id,
            'user_id'  : self.user_id,
            'created_at' : self.created_at,
            'updated_at' : self.updated_at
        }

engine = create_engine('sqlite:///catalog.db')
 

Base.metadata.create_all(engine)
