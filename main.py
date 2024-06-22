import logging
from fastapi import FastAPI, Form, HTTPException, status, Request, Depends, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from jinja2 import Template
import google.generativeai as genai
from passlib.context import CryptContext
from datetime import datetime, timedelta
import jwt

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Define FastAPI app
app = FastAPI()

# Configure API key (replace with your actual API key)
genai.configure(api_key="AIzaSyDWzjjATnfEphQQ60UTYTJxulyQYzd2dcg")
model = genai.GenerativeModel('gemini-1.5-flash')

# Secret key to sign the JWT tokens (generate a secure random key in production)
SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Simulated user database (replace with a real database in production)
fake_users_db = {}

class User(BaseModel):
    username: str

class UserInDB(User):
    hashed_password: str

class GeneratePostResponse(BaseModel):
    content: str

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)

def authenticate_user(fake_db, username: str, password: str):
    user = get_user(fake_db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=60)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(request: Request):
    
    try:
        username = request.cookies.get("access_token")
        username=username.split()[1]
        user = get_user(fake_users_db, username=username)
        return user

    except:
        credentials_exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
        raise credentials_exception


def generate_post(headline: str, keywords: list[str]):
    """
    Generates a blog post using Gemini API.
    """
    prompt = f"Generate a blog post with the Headline: {headline} and Keywords: {', '.join(keywords)}"
    response = model.generate_content(prompt)
    return format_generated_text(response.text)

def format_generated_text(text: str) -> str:
    """
    Formats the generated text with HTML tags to make it more readable.
    """
    # Replace markdown headings and list items with HTML tags
    text = text.replace("## ", "<h2>").replace("##", "</h2>")
    text = text.replace("* ", "<li>").replace("*", "</li>")
    
    # Split the text into paragraphs by double line breaks
    paragraphs = text.split("\n\n")
    
    # Wrap each paragraph in <p> tags and join them
    formatted_text = "<br>".join([f"<p>{para.strip()}</p>" for para in paragraphs if para.strip()])
    
    return formatted_text



# Templates
login_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
</head>
<body class="bg-gray-100 flex items-center justify-center min-h-screen">
    <div class="bg-white p-16 rounded-lg shadow-lg w-full max-w-md">
        <h2 class="text-xl font-semibold mb-4">Login</h2>
        <form method="POST" action="/login" class="space-y-4">
            <div>
                <label for="username" class="block text-sm font-medium text-gray-700">Username:</label>
                <input type="text" id="username" name="username" class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm">
            </div>
            <div>
                <label for="password" class="block text-sm font-medium text-gray-700">Password:</label>
                <input type="password" id="password" name="password" class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm">
            </div>
            <div>
                <button type="submit" class="w-full inline-flex justify-center py-2 px-4 border border-transparent shadow-sm text-sm font-medium rounded-md text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500">Login</button>
            </div>
        </form>
        <p class="mt-4 text-sm text-gray-600">Don't have an account? <a href="/register" class="text-indigo-600 hover:underline">Register</a></p>
    </div>
</body>
</html>
"""

register_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register</title>
    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
</head>
<body class="bg-gray-100 flex items-center justify-center min-h-screen">
    <div class="bg-white p-16 rounded-lg shadow-lg w-full max-w-md">
        <h2 class="text-xl font-semibold mb-4">Register</h2>
        <form method="POST" action="/register" class="space-y-4">
            <div>
                <label for="username" class="block text-sm font-medium text-gray-700">Username:</label>
                <input type="text" id="username" name="username" class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm">
            </div>
            <div>
                <label for="password" class="block text-sm font-medium text-gray-700">Password:</label>
                <input type="password" id="password" name="password" class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm">
            </div>
            <div>
                <button type="submit" class="w-full inline-flex justify-center py-2 px-4 border border-transparent shadow-sm text-sm font-medium rounded-md text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500">Register</button>
            </div>
        </form>
        <p class="mt-4 text-sm text-gray-600">Already have an account? <a href="/login" class="text-indigo-600 hover:underline">Login</a></p>
    </div>
</body>
</html>
"""

home_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Blog Post Generator</title>
    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
</head>
<body class="bg-gray-100 flex items-center justify-center min-h-screen">
    <div class="bg-white p-16 rounded-lg shadow-lg w-full max-w-2xl">
        <h1 class="text-2xl font-bold mb-4">Blog Post Generator</h1>
        {% if user %}
            <p class="mb-4">Welcome, {{ user.username }}! <a href="/logout" class="text-blue-500 hover:underline">Logout</a></p>
            <form method="POST" action="/generate-post" class="space-y-4">
                <div>
                    <label for="headline" class="block text-sm font-medium text-gray-700">Headline:</label>
                    <input type="text" id="headline" name="headline" class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm">
                </div>
                <div>
                    <label for="keywords" class="block text-sm font-medium text-gray-700">Keywords (comma separated):</label>
                    <input type="text" id="keywords" name="keywords" class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm">
                </div>
                <div>
                    <button type="submit" class="w-full inline-flex justify-center py-2 px-4 border border-transparent shadow-sm text-sm font-medium rounded-md text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500">Generate Post</button>
                </div>
            </form>
            {% if content %}
                <div class="mt-8">
                    <h2 class="text-xl font-bold mb-2">Generated Blog Post</h2>
                    <div class="prose">{{ content|safe }}</div>
                </div>
            {% endif %}
        {% else %}
            <p class="text-lg text-gray-600">Please <a href="/login" class="text-indigo-600 hover:underline">login</a> or <a href="/register" class="text-indigo-600 hover:underline">register</a> to continue.</p>
        {% endif %}
    </div>
</body>
</html>
"""

error_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Error</title>
    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
</head>
<body class="bg-gray-100 flex items-center justify-center min-h-screen">
    <div class="bg-white p-6 rounded-lg shadow-lg w-full max-w-lg text-center">
        <h1 class="text-3xl font-bold mb-4 text-red-600">Error</h1>
        <p class="text-lg text-gray-700 mb-4">{{ message }}</p>
        <div>
            <a href="/login" class="text-indigo-600 hover:underline">Go to Login</a>
        </div>
    </div>
</body>
</html>
"""


@app.post("/register", status_code=status.HTTP_201_CREATED)
async def register(response: Response, username: str = Form(...), password: str = Form(...)):
    try:
        if username in fake_users_db:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username already registered"
            )
        hashed_password = get_password_hash(password.strip())
        fake_users_db[username] = {"username": username.strip(), "hashed_password": hashed_password}
        access_token = create_access_token(data={"sub": username})
        response = RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    
        response.set_cookie(key="access_token", value=f"Bearer {username} {access_token}", httponly=True)
        logger.info(f"User registered: {username}")
        return response
    except Exception as e:
        logger.error(f"Error during registration: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Server Error")

@app.post("/login")
async def login(response: Response, form_data: OAuth2PasswordRequestForm = Depends(), username: str = Form(...), password: str = Form(...)):
    try:
        user = authenticate_user(fake_users_db, form_data.username, form_data.password)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user.username}, expires_delta=access_token_expires
        )
        response = RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
        response.set_cookie(key="access_token", value=f"Bearer {username} {access_token}", httponly=True)
        logger.info(f"User logged in now: {username}")


        return response
    except Exception as e:
        logger.error(f"Error during login: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Server Error")

@app.get("/logout")
async def logout(response: Response):
    response = RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    response.delete_cookie(key="access_token")
    logger.info("User logged out")
    return response

@app.get("/", response_class=HTMLResponse)
async def render_home(request: Request, current_user: User = Depends(get_current_user)):
    logger.info(f"{current_user}")
    return HTMLResponse(content=Template(home_template).render(user=current_user))

    
    

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return HTMLResponse(content=Template(login_template).render())

@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    return HTMLResponse(content=Template(register_template).render())

# Exception handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    if exc.status_code == status.HTTP_401_UNAUTHORIZED:
        message = "Invalid credentials. Please try again."
    elif exc.status_code == status.HTTP_404_NOT_FOUND:
        message = "The requested resource was not found."
    elif exc.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR:
        message = "Invalid credentials. Please try again."
    else:
        message = "An unexpected error occurred."
    
    return HTMLResponse(content=Template(error_template).render(message=message), status_code=exc.status_code)

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    message = "An internal server error occurred. Please try again later."
    return HTMLResponse(content=Template(error_template).render(message=message), status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

# Custom 404 Not Found handler
@app.exception_handler(404)
async def not_found_exception_handler(request: Request, exc: HTTPException):
    message = "The requested resource was not found."
    return HTMLResponse(content=Template(error_template).render(message=message), status_code=exc.status_code)


@app.post("/generate-post", response_class=HTMLResponse)
async def generate_post_and_render(request: Request, headline: str = Form(...), keywords: str = Form(...), current_user: User = Depends(get_current_user)):
    if current_user is None:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    try:
        keywords_list = [kw.strip() for kw in keywords.split(',')]
        generated_text = generate_post(headline, keywords_list)
        context = {
            "content": generated_text,
            "user": current_user
        }
        return HTMLResponse(content=Template(home_template).render(**context))
    except Exception as e:
        logger.error(f"Error during post generation: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Server Error")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="debug")
