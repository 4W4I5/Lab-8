from pydantic import BaseModel, EmailStr, Field, constr
from sqlmodel import Field, Session, SQLModel, create_engine, select


# CSRF Configuration
class CsrfSettings(BaseModel):
    secret_key: str = "Kaakaww!"  # Replace with a secure secret key


# Data class to hold data on students
class Student(SQLModel, table=True):
    SerialNo: int = Field(default=None, primary_key=True)
    Fname: str = Field(min_length=1, max_length=50)
    Lname: str = Field(min_length=1, max_length=50)
    Email: str = Field(index=True)
    Phone: str = Field(default=None, regex=r"^\+?1?\d{9,15}$"
    )  # Applying regex validation with Field
    PasswordHash: str
