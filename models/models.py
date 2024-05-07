import datetime

from sqlalchemy import Column, Integer, String, DateTime, Boolean, DOUBLE, ForeignKey
from database.database import Base
from sqlalchemy.orm import relationship


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String(50), nullable=False)
    email = Column(String(100), unique=True, nullable=False)
    password = Column(String(100), nullable=False)

    carts = relationship("Cart", back_populates="user")


class TokenTable(Base):
    __tablename__ = "token"
    user_id = Column(Integer)
    access_toke = Column(String(450), primary_key=True)
    refresh_toke = Column(String(450), nullable=False)
    status = Column(Boolean)
    created_date = Column(DateTime, default=datetime.datetime.now)


class Shoe(Base):
    __tablename__ = "shoe"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(50), nullable=False)
    price = Column(DOUBLE, nullable=False)
    category = Column(String(50), nullable=False)
    description = Column(String(500), nullable=False)
    imageUrl = Column(String(500), nullable=False)


class Cart(Base):
    __tablename__ = "cart"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.id'))  # Foreign key relationship to the users table id
    user = relationship("User", back_populates="carts")
    items = relationship("CartItem", back_populates="cart")  # Add this line to establish the relationship with CartItem


class CartItem(Base):
    __tablename__ = "cart_items"

    id = Column(Integer, primary_key=True, autoincrement=True)
    cart_id = Column(Integer, ForeignKey('cart.id'))  # Foreign key relationship to the carts table
    item_id = Column(Integer, ForeignKey('shoe.id'))  # Foreign key relationship to the shoes table
    quantity = Column(Integer, nullable=False)

    cart = relationship("Cart", back_populates="items")  # Establishing the bidirectional relationship with Cart
    shoe = relationship("Shoe")  # Establishing the relationship with the Shoe model
