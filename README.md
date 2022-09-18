# Orderbook Techical Analysis - REST API

This is the REST API component/submodule of the [Orderbook Technical Analysis project](https://github.com/RT-Tap/OrderbookTechAnalysis-Integration) whose purpose is described in the first section of the [OrderbookTechAnalysis-Integration](https://github.com/RT-Tap/OrderbookTechAnalysis-Integration) repo. Implemented via [FastAPI](https://fastapi.tiangolo.com/) so its basically production ready. It is meant to be run as a container, a component of a service which is created (and described) by the [OrderbookTechAnalysis-Intefration](https://github.com/RT-Tap/OrderbookTechAnalysis-Integration) repo.

As described below, the JWT implementation used here is attack resistant and although the rest of the repo may be of no use to you I think my JWT implementation may be of great value to some.  Overkill for this application but nice for refrence.

## Enviroment Variables need to run
- MYSQL_USER: mysql user name for users database
- MYSQL_PASSWORD: mysql user password for users database
- WORKER_USERNAME: Mongodb user name
- WORKER_PASSWORD: Mongodb user password
- FQDOMAIN: Domain this project is using, used for CORS policy and JWT signing  (defaults to 127.0.0.1:8000)
- SECRET_KEY: random 32 long string used for JWT signing/encryption - can be generated using:  `openssl rand -hex 32`

## Attack resistant JWT 
The implementation of JWTs used here is resistant to the 2 attack vectors they are vulnerable to, XSS and CSRF. 
- Assuming all traffic is HTTPS and disregarding any social engineering attacks (up to the user to defend against any social engineering).
### Implemenation:
1. User logs in, gets a long lived "refresh" JWT as a Secure HttpOnly cookie.
2. Anytime the user wants to make a request to the API the "refresh" JWT Cookie is sent to a specific API endpoint, validated, then another "access" JWT is issued as either a header or payload.
3. This "access" JWT is then used as the actual authentication token, again as either a header or payload, to access the various endpoints.
### Rational
The logic behind this is that HttpOnly Cookies are vulnerable to CSRF but not XSS, so although an attacker might send a request on your behalf during a CSRF attack they would not be able to intercept the resulting "access" token. This resulting "access" token is short lived, no more then 10 second lifespan, so if there is a XSS attack the chances of an attacker intercepting and then using the "access" token during that time is very slim.
Therefore as long as the user does not fall for phishing/fake login type screens that would steal their credentials they would be pretty safe.
This has not been verified but I was also not able to find anyone to refute this logic.

## Endpoints
### Orderbook/Price data
Self explanatory, provides the raw trade data that is used by the frontend.
- `/orderbook/` : provides 3 endpoints to access orderbook data 

### User login/data
Again self explanatory
- registration 
- login 
  - JWT tokens to manage login session.