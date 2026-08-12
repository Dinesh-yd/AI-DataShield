from sqlalchemy.orm import Session

from app.models.entities import User


def get_or_create_user(db: Session, email: str, name: str = "Demo User") -> User:
    user = db.query(User).filter(User.email == email).first()
    if user:
        return user
    user = User(email=email, name=name)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user
