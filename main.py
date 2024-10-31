"""
1) Secure Input handling: Typed data types + Parametric SQL + Regex Validation
2) Parameterized SQL Queries: Done above + Using SQLModel which is enforces data types
3.1) CSRF: Implemented
3.1) Session Cookies: Implemented
4) Secure Error Handling: Implemented routes for 404, 500, etc.
5) Secure Password Storage: Done above + Hashing with bcrypt
"""

import os
import random
import string
import time
from typing import Annotated

from bcrypt import gensalt, hashpw
from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi_csrf_protect import CsrfProtect
from fastapi_csrf_protect.exceptions import CsrfProtectError
from pydantic import BaseModel, EmailStr
from sqlmodel import Field, Session, SQLModel, create_engine, select
from starlette.middleware.sessions import SessionMiddleware
from starlette.responses import PlainTextResponse


# CSRF Configuration
class CsrfSettings(BaseModel):
    secret_key: str = os.environ.get(
        "SECRET_KEY", "secretkey"
    )  # Replace with a secure secret key
    cookie_same_site: str = "none"


# Data class to hold data on students
class Student(SQLModel, table=True):
    SerialNo: int = Field(default=None, primary_key=True)
    Fname: str = Field(min_length=1, max_length=50)
    Lname: str = Field(min_length=1, max_length=50)
    Email: str = Field(index=True)
    Phone: str = Field(
        default=None, regex=r"^\+?1?\d{9,15}$"
    )  # Applying regex validation with Field
    PasswordHash: str


@CsrfProtect.load_config
def get_csrf_config():
    return CsrfSettings()


# DB Setup
sqlite_file_name = "./awais_database.db"
sqlite_url = f"sqlite:///{sqlite_file_name}"
connect_args = {"check_same_thread": False}
engine = create_engine(sqlite_url, connect_args=connect_args)


def create_db_and_tables():
    SQLModel.metadata.create_all(engine)


def get_session():
    with Session(engine) as session:
        yield session


SessionDep = Annotated[Session, Depends(get_session)]

app = FastAPI()


def generate_secret_key(length=32):
    """Generate a random string of letters and digits for the secret key."""
    chars = string.ascii_letters + string.digits
    return "".join(random.choice(chars) for _ in range(length))


def rotate_secret_key():
    """Rotate the secret key."""
    new_secret_key = generate_secret_key()
    os.environ["SECRET_KEY"] = new_secret_key


def schedule_key_rotation(interval_seconds):
    """Schedule secret key rotation at regular intervals."""
    while True:
        rotate_secret_key()
        print("Secret key rotated.")
        time.sleep(interval_seconds)


# Middleware for session management
app.add_middleware(SessionMiddleware, secret_key="supersecretkey")


@app.exception_handler(CsrfProtectError)
def csrf_protect_exception_handler(request: Request, exc: CsrfProtectError):
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.message})


@app.exception_handler(404)
async def not_found_handler(request: Request, exc: HTTPException):
    return PlainTextResponse("Custom 404: Resource not found", status_code=404)


@app.exception_handler(500)
async def internal_error_handler(request: Request, exc: HTTPException):
    return PlainTextResponse("Custom 500: Internal server error", status_code=500)


@app.get("/csrftoken/")
async def get_csrf_token(csrf_protect: CsrfProtect = Depends()):
    # response = JSONResponse(status_code=200, content={"csrf_token": "cookie"})
    # csrf_protect.set_csrf_cookie(csrf_protect.generate_csrf_tokens(response))
    csrf_token, _ = csrf_protect.generate_csrf_tokens()
    return {"csrf_token": csrf_token}


@app.on_event("startup")
def on_startup():
    create_db_and_tables()


@app.post("/add_student")
async def add_student(
    request: Request,
    session: SessionDep,
    csrf_protect: CsrfProtect = Depends(),
    fname: str = Form(...),
    lname: str = Form(...),
    email: EmailStr = Form(...),
    phone: str = Form(...),
    password: str = Form(...),
):
    try:
        await csrf_protect.validate_csrf(request)
        print("CSRF Token is valid")
    except CsrfProtectError as e:
        return JSONResponse(status_code=e.status_code, content={"detail": e.message})

    print(f"[SRVR]: Adding Student {fname} {lname}, {email}, {phone}, {password}")

    # Hash the password before storing
    hashed_password = hashpw(password.encode("utf-8"), gensalt()).decode("utf-8")

    new_student = Student(
        Fname=fname, Lname=lname, Email=email, Phone=phone, PasswordHash=hashed_password
    )

    session.add(new_student)
    session.commit()
    session.refresh(new_student)
    print(f"Added Student: {new_student}")

    response = RedirectResponse(url="/", status_code=302)
    # print the cookie that is being unset
    print(
        f"Unsetting CSRF Cookie: {csrf_protect.get_csrf_from_headers(request.headers)}"
    )
    csrf_protect.unset_csrf_cookie(response)

    return response


@app.post("/delete_student/{serial_no}")
async def delete_student(
    request: Request,
    serial_no: int,
    session: SessionDep,
    csrf_protect: CsrfProtect = Depends(),
):
    try:
        await csrf_protect.validate_csrf(request)
    except CsrfProtectError as e:
        return JSONResponse(status_code=e.status_code, content={"detail": e.message})

    student_to_delete = session.get(Student, serial_no)
    if not student_to_delete:
        raise HTTPException(status_code=404, detail="Student not found")

    session.delete(student_to_delete)
    session.commit()

    response = RedirectResponse(url="/", status_code=302)
    print(
        f"Unsetting CSRF Cookie: {csrf_protect.get_csrf_from_headers(request.headers)}"
    )
    csrf_protect.unset_csrf_cookie(response)
    return response


@app.post("/update/{serial_no}")
async def update_student(
    serial_no: int,
    request: Request,
    session: SessionDep,
    csrf_protect: CsrfProtect = Depends(),
    fname: str = Form(...),
    lname: str = Form(...),
    email: EmailStr = Form(...),  # Use EmailStr for validation
):
    try:
        await csrf_protect.validate_csrf(request)
    except CsrfProtectError as e:
        return JSONResponse(status_code=e.status_code, content={"detail": e.message})

    student_to_update = session.get(Student, serial_no)
    if not student_to_update:
        raise HTTPException(status_code=404, detail="Student not found")

    # Update student details
    student_to_update.Fname = fname
    student_to_update.Lname = lname
    student_to_update.Email = email
    session.commit()

    response = RedirectResponse(url="/", status_code=302)
    csrf_protect.unset_csrf_cookie(response)
    return response


@app.get("/update/{serial_no}")
async def edit_student(
    serial_no: int,
    request: Request,
    session: SessionDep,
    csrf_protect: CsrfProtect = Depends(),
):
    student_to_edit = session.get(Student, serial_no)
    if not student_to_edit:
        raise HTTPException(status_code=404, detail="Student not found")

    csrf_token, signed_token = csrf_protect.generate_csrf_tokens()

    templates = Jinja2Templates(directory="./templates")
    response = templates.TemplateResponse(
        "update.html",
        {"request": request, "student": student_to_edit, "csrf_token": csrf_token},
    )
    csrf_protect.set_csrf_cookie(signed_token, response)
    print(f"Set New CSRF Token: {csrf_token[0:4]}...{csrf_token[-4:]}")
    print(f"Set New Signed Token: {signed_token[0:4]}...{signed_token[-4:]}")
    return response


@app.get("/")
async def root(
    request: Request, session: SessionDep, csrf_protect: CsrfProtect = Depends()
):
    try:
        csrf_token, signed_token = csrf_protect.generate_csrf_tokens()
    except CsrfProtectError as e:
        return JSONResponse(status_code=e.status_code, content={"detail": e.message})
    statement = select(Student).offset(0).limit(100)
    allStudents = session.exec(statement).all()
    templates = Jinja2Templates(directory="templates")
    response = templates.TemplateResponse(
        "index.html",
        {"request": request, "students": allStudents, "csrf_token": csrf_token},
    )
    csrf_protect.set_csrf_cookie(signed_token, response)
    print(f"Set New CSRF Token: {csrf_token[0:4]}...{csrf_token[-4:]}")
    print(f"Set New Signed Token: {signed_token[0:4]}...{signed_token[-4:]}")
    return response


@app.get("/Awais")
async def retMyName():
    return {"message": "Welcome to Awais's Home Page"}
