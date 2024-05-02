import uvicorn
from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
from functools import wraps
import jwt
from datetime import datetime

from typing import List

from fastapi import status

from models import models
from schemas import schemas
from models.models import Base, User, TokenTable

from utils.utils import create_access_token, create_refresh_token, verify_password, get_hashed_password
from authentication.auth_bearer import JWTBearer


from database.database import get_db, engine
from jose import jwt
from fastapi.middleware.cors import CORSMiddleware
app = FastAPI()

# Allow requests from all origins, methods, and headers
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)

ALGORITHM = "HS256"
JWT_SECRET_KEY = "narscbjim@$@&^@&%^&RFghgjvbdsha"  # should be kept secret


@app.post("/register")
async def register_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    existing_user = db.query(models.User).filter_by(email=user.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    encrypted_password = get_hashed_password(user.password)
    user = User(username=user.username, email=user.email, password=encrypted_password)
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"message": "User created successfully"}


@app.post('/login', response_model=schemas.TokenSchema)
def login(request: schemas.requestdetails, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == request.email).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Incorrect email")
    hashed_pass = user.password
    if not verify_password(request.password, hashed_pass):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect password"
        )

    access = create_access_token(user.id)
    refresh = create_refresh_token(user.id)

    token_db = models.TokenTable(user_id=user.id, access_token=access, refresh_token=refresh, status=True)
    db.add(token_db)
    db.commit()
    db.refresh(token_db)
    return {
        "access_token": access,
        "refresh_token": refresh,
    }


@app.get('/getusers')
def getusers(dependencies=Depends(JWTBearer()), session: Session = Depends(get_db)):
    user = session.query(models.User).all()
    return user


# *************** SHOE APIS *****************
@app.post('/shoes/', response_model=schemas.ShoesSchema, status_code=status.HTTP_201_CREATED)
def create_shoe(shoe: schemas.ShoeCreate, db: Session = Depends(get_db)):
    db_shoe = models.Shoe(
        name=shoe.name,
        price=shoe.price,
        category=shoe.category,
        description=shoe.description,
        imageUrl=shoe.imageUrl  # Assuming image is a property of Shoe
    )
    db.add(db_shoe)
    db.commit()
    db.refresh(db_shoe)

    # Return a dictionary representation of the created shoe
    return db_shoe.__dict__


@app.get('/shoes/', response_model=List[schemas.ShoesSchema])
def get_all_shoes(db: Session = Depends(get_db)):
    shoes = db.query(models.Shoe).all()
    return [shoe.__dict__ for shoe in shoes]



@app.get('/shoes/{shoe_id}', response_model=schemas.ShoesSchema)
def get_shoe(shoe_id: int, db: Session = Depends(get_db)):
    shoe = db.query(models.Shoe).filter(models.Shoe.id == shoe_id).first()
    if not shoe:
        raise HTTPException(status_code=404, detail="Shoe not found")
    return shoe.__dict__


@app.put('/shoes/{shoe_id}', response_model=schemas.ShoesSchema)
def update_shoe(shoe_id: int, shoe: schemas.ShoeUpdate, db: Session = Depends(get_db)):
    db_shoe = db.query(models.Shoe).filter(models.Shoe.id == shoe_id).first()
    if not db_shoe:
        raise HTTPException(status_code=404, detail="Shoe not found")

    # Update the shoe attributes
    for attr, value in shoe.dict().items():
        setattr(db_shoe, attr, value)

    db.commit()
    db.refresh(db_shoe)
    return db_shoe.__dict__


@app.delete('/shoes/{shoe_id}', response_model=schemas.ShoesSchema)
def delete_shoe(shoe_id: int, db: Session = Depends(get_db)):
    db_shoe = db.query(models.Shoe).filter(models.Shoe.id == shoe_id).first()
    if not db_shoe:
        raise HTTPException(status_code=404, detail="Shoe not found")

    db.delete(db_shoe)
    db.commit()
    return db_shoe.__dict__


@app.post('/change-password')
def change_password(request: schemas.changepassword, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == request.email).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User not found")

    if not verify_password(request.old_password, user.password):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid old password")

    encrypted_password = get_hashed_password(request.new_password)
    user.password = encrypted_password
    db.commit()

    return {"message": "Password changed successfully"}


@app.post('/logout')
def logout(dependencies=Depends(JWTBearer()), db: Session = Depends(get_db)):
    token = dependencies
    payload = jwt.decode(token, JWT_SECRET_KEY, ALGORITHM)
    user_id = payload['sub']
    token_record = db.query(models.TokenTable).all()
    info = []
    for record in token_record:
        print("record", record)
        if (datetime.utcnow() - record.created_date).days > 1:
            info.append(record.user_id)
    if info:
        existing_token = db.query(models.TokenTable).where(TokenTable.user_id.in_(info)).delete()
        db.commit()

    existing_token = db.query(models.TokenTable).filter(models.TokenTable.user_id == user_id,
                                                        models.TokenTable.access_token == token).first()
    if existing_token:
        existing_token.status = False
        db.add(existing_token)
        db.commit()
        db.refresh(existing_token)
    return {"message": "Logout Successfully"}


def token_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):

        payload = jwt.decode(kwargs['dependencies'], JWT_SECRET_KEY, ALGORITHM)
        user_id = payload['sub']
        data = kwargs['session'].query(models.TokenTable).filter_by(user_id=user_id, access_toke=kwargs['dependencies'],
                                                                    status=True).first()
        if data:
            return func(kwargs['dependencies'], kwargs['session'])

        else:
            return {'msg': "Token blocked"}

    return wrapper


if __name__ == '__main__':
    Base.metadata.create_all(bind=engine)
    uvicorn.run(app, host='0.0.0.0', port=8000)
