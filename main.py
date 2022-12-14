# from urllib import response
from fastapi import FastAPI, Query, Cookie, Header, Depends, HTTPException, status, Response
from fastapi.responses import JSONResponse
from typing import List, Optional # required for python <3.10
from pydantic import BaseModel, Field # for creating schemas that are accepted
import time
import datetime
from uuid import  uuid4
from fastapi.middleware.cors import CORSMiddleware # that pesky CORS
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm, APIKeyHeader, HTTPBearer
from jose import JWTError, jwt
from jose.exceptions import ExpiredSignatureError
import random
from passlib.context import CryptContext
from databases import Database
import uvicorn
import os
from pymongo import MongoClient
from enum import Enum


app = FastAPI()

USER_DATABASE_URL = 'mysql://'+ os.getenv('MYSQL_USER', 'main-worker') + ':' + os.getenv('MYSQL_PASSWORD') + '@localhost:3306/orderbooktechanal' #mysql://<username>:<password>@<host>:<port>/<db_name>
user_database = Database(USER_DATABASE_URL)

mongoDBserver = os.getenv('MONGODB_ENDPOINT','182.16.0.3:27017')
mongoDBdatabase = os.getenv("MONGODB_DATABASE", 'orderbook&trades')
client = None
DBConn = None

# Used for fastAPI self-documentaion purposes of available securities
class Security(str, Enum):
	BTC: "bitcoin"
	ETH: "ethereum"
	XRP: "ripple"
	# list any other securities that you plan to make available


@app.on_event("startup")
async def startup():
	print('conecting to users database...')
	try:
		await user_database.connect()
	except Exception as e:
		print(f'Could not connect to database.\n{e}')
	print('Successfully connected to users database.')
	try:
		client = MongoClient(mongoDBserver, username=os.getenv('WORKER_USERNAME', 'mainworker'), password=os.getenv('WORKER_PASSWORD'), authSource=mongoDBdatabase, authMechanism='SCRAM-SHA-256')
		DBConn = client[mongoDBdatabase]
	except Exception as e:
		print(f'Error connecting to mongoDB server\nError:\n{e.__class__}')
	print('Successfully connected to data database')
@app.on_event("shutdown")
async def shutdown():
	await user_database.disconnect()
	await client.close()

# ----------CORS-----------
# where requests can originate from
origins = [ 'http://localhost:8000','https://localhost:8000'] if os.getenv('FQDOMAIN') is None else ['http://'+os.getenv('FQDOMAIN'), 'https://'+os.getenv('FQDOMAIN')]
app.add_middleware(
	CORSMiddleware,
	allow_origins=origins,
	allow_credentials=True,
	allow_methods=["*"],
	allow_headers=["*"],
)

@app.get("/data/{security}", status_code=201)
async def getOrderbookHisotryUsingDateTime( security: Security,
		startTime: Optional[datetime.datetime] = Query(datetime.datetime.now().replace(tzinfo=datetime.timezone.utc),
														title='Start date/time of period for request data ', 
														example="2019-04-01T00:00:00.000Z", 
														description="ISO 8601 formatted data period start"), # timestamp constrained to jan1,2022 and right now
		endTime: Optional[datetime.datetime]  = Query(datetime.datetime.now().replace(tzinfo=datetime.timezone.utc),
														title='End date/time of period for requested data', 
														example="2019-04-01T00:00:00.000-05:00", 
														description="ISO 8601 formatted data period end")):
	orderbookDBconnection = DBConn['orderbook&trades']
	orderbookDBconnection.find({ "$and": [
								{"symbol":{"$eq":security.value}} , 
								{"DateTime":{
									"$gte": startTime, 
									"$lte": endTime
									}}
								]}); 
	return {"startTime": startTime, 'endTime': endTime}

# we can alsio do orderbook using date time (ISO 8601)
@app.get("/data/{security}/{timeDelta}", status_code=201)
async def getOrderbookHisotryUsingDateTime( security: Security,
											timeDelta: Optional[datetime.timedelta] = Query(..., 
																							title="Data period time delta",
																							decscription=" Length of period (in seconds), relative to right now, for requested data")):
	orderbookDBconnection = DBConn['orderbook&trades']
	orderbookDBconnection.find({ "$and": [
								{"symbol":{"$eq":security.value}} , 
								{"DateTime":{
									"$gte": datetime.datetime.now().replace(tzinfo=datetime.timezone.utc)- datetime.timedelta(seconds=timeDelta) , 
									"$lte": datetime.datetime.now().replace(tzinfo=datetime.timezone.utc)
									}}
								]}) 
	return {'startTime':datetime.datetime.now() - datetime.timedelta(seconds=timeDelta), 'endTime': datetime.datetime.now()}


@app.get("/data/{security}",  status_code=201)
async def getOrderHistory( security: Security,
		startTime: int = Query(int(time.time()) - 2880, 
								title='Period start', 
								description='Start Unix timestamp for orderbook data, defaults to 48 hours ago, must be between jan 1st 2022 and now', 
								gt=1641013200, le=int(time.time()) ), # timestamp constrained between jan1,2022 and right now
		endTime: Optional[int] = Query(int(time.time()), 
										title='Period end', 
										description='End Unix timestamp for  orderbook data, defaults to now, must be between jan 1st 2022 and now', 
										gt=1641013200, le=int(time.time()))):#  if we decide to use string we can use:  min_length=9, max_length=11
	orderbookDBconnection = DBConn['orderbook&trades']
	orderbookDBconnection.find({ "$and": [
								{"symbol":{"$eq":security.value}} , 
								{"DateTime":{
									"$gte": startTime, 
									"$lte": endTime
									}}
								]},
								{}) 
	return {"startTime": startTime, 'endTime': endTime}


#-------------------------------------Full JWT implementation
SECRET_KEY = os.getenv('SECRET_KEY',"44dd261c7263490a38edfe289e54a0e6b52f7363af5e19fe446495a8f1a32aaf") # openssl rand -hex 32
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
ACCESS_TOKEN_ISSUER =  os.getenv('FQDOMAIN', '127.0.0.1:8000')
ACCESS_TOKEN_AUDIENCE = 'WALLSTREETBETSAPESSITTINGATBLOOMBERGTERMINALS'
LONGLASTING_REFRESH_TOKEN_EXPIRE_HOURS = 720

credentials_exception = HTTPException(
	status_code=status.HTTP_401_UNAUTHORIZED,
	detail="Could not validate credentials",
	headers={"WWW-Authenticate": "Bearer"},
)

internal_server_error_exception = HTTPException(
	status_code=500,
	detail="Internal server error",
	headers={"WWW-Authenticate": "Bearer"},
)

incorrect_credentials_exception = HTTPException(
	status_code=status.HTTP_401_UNAUTHORIZED,
	detail="Incorrect username or password",
	headers={"WWW-Authenticate": "Bearer"},
)


# response model of get_token endpoint
class Token(BaseModel):
	access_token: str
	token_type: str

class TokenData(BaseModel):
	username: str = None
	issuer: str = None
	issued_at: datetime.datetime = None
	audience: str = None
	unique_identifier: str = None
	expires: datetime.datetime = None

class Register(BaseModel):
	username: Optional[str] = None
	email: str
	password: str


class User(BaseModel):
	username: str
	email: Optional[str] = None
	active: Optional[bool] = 1

class DBUser(User):
	userID: Optional[str]
	password: str
	salt: Optional[str]
	firstName: Optional[str] = None
	lastName: Optional[str] = None
	subscriptionlevel: Optional[int] = 2
	session: Optional[str]

class Register_result(BaseModel):
	Success: bool
	Credentials: Optional[User]
	Reason: Optional[str]

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
password_salt_generator_context = CryptContext(schemes=["md5_crypt"])
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
# http_bearer_scheme = HTTPBearer(bearerFormat=)

def verify_password(plain_password, hashed_password):
	return pwd_context.verify(plain_password, hashed_password)
def get_password_hash(password):
	return pwd_context.hash(password)

async def get_user_data(**kwargs):
	# user can be looked up by either username or email, username can be differenrt from email so we need to check email in username and email feild/column
	query = f"SELECT * from Users where " + ('username=\"'+kwargs['username']+'\" or email=\"'+kwargs['username']+'\"' if 'username' in kwargs else '')+(' or ' if 'username' and 'email' in kwargs else '')+('email=\"'+kwargs['email']+'\"' if 'email' in kwargs else '')
	try:
		user = await user_database.fetch_all(query=query)
		if len(user) > 1:
			raise internal_server_error_exception
		elif len(user) == 0:
			return None
		else:
			return DBUser(**user[0])
	except:
		raise

async def register_user(user_details: DBUser):
	salt = (password_salt_generator_context.hash(str(random.uniform(0,100))))[-16:] # a random float between 0,100 gives a lot more "randomness" to our salt as we are hashing a 18 digit number which has 2^18 possibilities, then taske last 16 characters
	query = f"INSERT INTO Users (userID, username, password, salt, email, firstName, lastName, subscriptionlevel, active) VALUES \
			('{uuid4()}', '{user_details.username}','{get_password_hash(user_details.password + salt)}', '{salt}', '{user_details.email}', \
			'{user_details.firstName}', '{user_details.lastName }', '{user_details.subscriptionlevel}', 1 )" # if user_details.firstname else 'N/A'  - if user_details.lastname else 'N/A'
	try:
		inserted = await user_database.execute(query=query)
		if inserted != 1:
			raise internal_server_error_exception
	except Exception as e:
		if e is not internal_server_error_exception:
			print(f"Mysql insert error: {e}")
		raise internal_server_error_exception
	return User(username= user_details.username, email=user_details.email)

async def get_current_user(token: str = Depends(oauth2_scheme)):
	try:
		payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM], audience=ACCESS_TOKEN_AUDIENCE, options={"verify_signature": True, "verify_aud": True, "exp": True})
		username: str = payload.get("usr")
		if username is None:
			raise credentials_exception
		token_data = TokenData(username=username, issuer=payload.get('iss'), issued_at=payload.get("iat"), audience=payload.get('aud'), unique_identifier=payload.get('jti'), expires=payload.get('exp'))
	except JWTError as e:
		print(f'jwterror: {e}')
		raise credentials_exception
	user = await get_user_data( username=token_data.username )
	return user

async def get_current_active_user(current_user: User = Depends(get_current_user)):
	if not current_user.active:
		raise HTTPException(status_code=400, detail="Inactive user")
	return current_user

# ---- verify refresh token --
def verifyrefresh_getaccesstoken(token: str, token_audience: Optional[str] = ACCESS_TOKEN_AUDIENCE):
	try:
		payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM], audience='access_token_endpoint', options={"verify_signature": True, "verify_aud": True, "exp": True})
	except:
		raise credentials_exception
	to_encode = {"usr": payload.get('usr'), 'iss': ACCESS_TOKEN_ISSUER, 'iat': datetime.datetime.utcnow(), 'aud': token_audience, 'jti': payload.get('jti'), 'exp':datetime.datetime.utcnow() + datetime.timedelta(seconds=30) }
	return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


# ---- token creation -------
async def authenticate_user(username: str, password: str):
	try:
		userData = await get_user_data(username=username)
		if not userData:
			raise incorrect_credentials_exception
	except:
		raise
	if not verify_password(password+userData.salt, userData.password):
		return False
	return userData

def create_access_token(user: User, expires_delta: Optional[datetime.timedelta] = None, token_audience: Optional[str] = ACCESS_TOKEN_AUDIENCE):
	to_encode = {"usr": user.username, 'iss': ACCESS_TOKEN_ISSUER, 'iat': datetime.datetime.utcnow(), 'aud': token_audience, 'jti': str(uuid4()) } # fucking Jose breaks down for fucking rerason
	if expires_delta:
		expire = datetime.datetime.utcnow() + expires_delta
	else:
		expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=15)
	to_encode.update({"exp": expire})
	encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
	return encoded_jwt
# -------------------------
#--------- Original/Simple JWT (for refrence) ---------------
@app.post("/token", response_model=Token, summary="Get JWT token for use with some endpoints")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
	user = await authenticate_user(form_data.username, form_data.password)
	if not user:
		raise incorrect_credentials_exception
	access_token_expires = datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
	access_token = create_access_token( user=user ,expires_delta=access_token_expires )
	return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me/", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
	return current_user

@app.get("/users/me/items/")
async def read_own_items(current_user: User = Depends(get_current_active_user)):
	return [{"item_id": "Foo", "owner": current_user.username}]
# --------------------------------------
# -----------NEW security schema -------
# JWT issues: if stored as cookie : vulnerable to CSRF , if stored in local storage vlernable to XSS - (httpOnly cookie is only vulnerable to CSRF, regular cookie is susceptible to both)
# 1) login: get refresh token, this will be used to get an access token anytime any operation is requested by user
# this works because although an attacker may send a request on your behalf via CSRF because they have your cookie it will only return an access token which only you can see/read and therefore use
# this access token is then used to perform the action but is extremely short lived in case it has been comprimised by XSS it is only valid liong enough to perform the requested action
# this will not protect against social engineerring XSS attacks but will prevent using stored credentials
#-----login endpoint for long term "refresh" token
@app.post("/login", summary="Login for long lasting JWT cookie")
async def login(response: Response, form_data: OAuth2PasswordRequestForm = Depends()):
	user = await authenticate_user(form_data.username, form_data.password)
	if not user:
		raise incorrect_credentials_exception
	access_token_expires = datetime.timedelta(hours=LONGLASTING_REFRESH_TOKEN_EXPIRE_HOURS)
	access_token = create_access_token( user=user , expires_delta=access_token_expires, token_audience='access_token_endpoint' )
	content = {'Success':True }
	response = JSONResponse(content=content)
	response.set_cookie(key='auth_token', value=access_token, secure=True, httponly=True, max_age=2678400, path='/get_access') # secure httponly cookie that only works on /get_acces enpoint and is valid for 31 days # , path='/get_access'
	# thereturn = Register_result(Success=True, Credentials=User(username=user.username, email=user.email, active=user.active))
	return response
#----"Access" JWToken endpoint - validates long term and creates short term ----
@app.get('/get_access', response_model=Token, summary="Short lived access token used for calls")
async def get_access_token(auth_token: str = Cookie(None)): #Optional[str]
	try:
		print(f'cookie: {auth_token}')
	except:
		print('couldnt print cookie')
	if not auth_token:
		print('no cookie')
		raise credentials_exception
	access_token = verifyrefresh_getaccesstoken(auth_token)
	return {"access_token": access_token, "token_type": "bearer"}
#---test endpont for the short term JWToken----
@app.get('/test')
async def access_token_test(access_token: Optional[str] = Header(None)):
	if not access_token:
		print('no header')
		raise credentials_exception
	try:
		jwt.decode(access_token, SECRET_KEY, algorithms=[ALGORITHM], audience=ACCESS_TOKEN_AUDIENCE, options={"verify_signature": True, "verify_aud": True, "exp": True})
	except Exception as e:
		if e is ExpiredSignatureError:
			print('expired')
		raise credentials_exception
	return {'Success': True}



@app.post('/register/', response_model=Register_result)
async def register(registerCredentials: Register): #,  auth: str = Cookie(None), creds: str = Header(None)
	# user_details = DBUser(**registerCredentials)
	username = registerCredentials.username if registerCredentials.username else  registerCredentials.email
	user_details = DBUser(username=username, email=registerCredentials.email, password=registerCredentials.password)
	if not await get_user_data(username = user_details.username, email = user_details.email):
		credentials = await register_user(user_details)
	else:
		return Register_result(Success=False, Reason="Username/Email already exists")
	return {"Success":True, 'Credentials': credentials}

if __name__ == "__main__":
	# run using : uvicorn main:app --reload
	# autocreates documentation : http://127.0.0.1:8000/docs or http://127.0.0.1:8000/redoc the generated OpenAPI fgenerated schema: http://127.0.0.1:8000/openapi.json
	uvicorn.run(app, host="0.0.0.0", port=8000)