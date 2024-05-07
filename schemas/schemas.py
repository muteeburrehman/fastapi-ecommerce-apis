import decimal

from pydantic import BaseModel
from typing import List
import datetime


class UserCreate(BaseModel):
    username: str
    email: str
    password: str


class requestdetails(BaseModel):
    email: str
    password: str


class TokenSchema(BaseModel):
    access_token: str
    refresh_token: str


class changepassword(BaseModel):
    email: str
    old_password: str
    new_password: str


class TokenCreate(BaseModel):
    user_id: str
    access_token: str
    refresh_token: str
    status: bool
    created_date: datetime.datetime


class ShoesSchema(BaseModel):
    name: str
    price: float
    category: str
    description: str
    imageUrl: str


class ShoeCreate(BaseModel):
    name: str
    price: float
    category: str
    description: str
    imageUrl: str


class ShoeUpdate(BaseModel):
    name: str
    price: float
    category: str
    description: str
    imageUrl: str


class Shoe(BaseModel):
    name: str
    price: float
    category: str
    description: str
    imageUrl: str


class CartItemSchema(BaseModel):
    item_id: int
    quantity: int


class CartSchema(BaseModel):
    user_id: int
    items: List[CartItemSchema]

    class Config:
        from_attributes = True  # Use from_attributes instead of orm_mode
