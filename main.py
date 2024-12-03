from flask import Flask, request, jsonify
from google.cloud import datastore

import requests
import json

from six.moves.urllib.request import urlopen
from jose import jwt
from authlib.integrations.flask_client import OAuth

USERS = 'users'
COURSES = 'courses'

app = Flask(__name__)
app.secret_key = 'SECRET_KEY'

client = datastore.Client()

# All passwords: B1gGr33n
# a6 on osu email:
CLIENT_ID = 'XArPKk8wTWQskS11aKXcLcp9sY18pfp7'
CLIENT_SECRET = 'zCXWP1sVmYy4ChPJPNOys7jNRolnM_Tn4L_amg7Lj2kP_s6sMz7eGQyhy56c1G-v'
DOMAIN = 'dev-85b6vy6ndf5qpmsj.us.auth0.com'
# For example
# DOMAIN = '493-24-spring.us.auth0.com'
# Note: don't include the protocol in the value of the variable DOMAIN

ALGORITHMS = ["RS256"]

oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url="https://" + DOMAIN,
    access_token_url="https://" + DOMAIN + "/oauth/token",
    authorize_url="https://" + DOMAIN + "/authorize",
    client_kwargs={
        'scope': 'openid profile email',
    },
)

# This code is adapted from https://auth0.com/docs/quickstart/backend/python/01-authorization?_ga=2.46956069.349333901.1589042886-466012638.1589042885#create-the-jwt-validation-decorator

class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response

# Verify the JWT in the request's Authorization header
def verify_jwt(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        raise AuthError({"code": "no auth header",
                            "description":
                                "Authorization header is missing"}, 401)

    jsonurl = urlopen("https://"+ DOMAIN+"/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    if unverified_header["alg"] == "HS256":
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://"+ DOMAIN+"/"
            )
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                            "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                            "description":
                                "incorrect claims,"
                                " please check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header",
                            "description":
                                "Unable to parse authentication"
                                " token."}, 401)

        return payload
    else:
        raise AuthError({"code": "no_rsa_key",
                            "description":
                                "No RSA key in JWKS"}, 401)

def get_error_message(status_code):
    """Return a JSON error message for a given response status code."""
    error_messages = {
        400: {"Error": "The request body is invalid"},
        401: {"Error": "Unauthorized"},
        403: {"Error": "You don't have permission on this resource"},
        404: {"Error": "Not found"},
    }
    return error_messages.get(status_code, {"Error": "Unknown error code"})


@app.route('/')
def index():
    return "Please navigate to /businesses to use this API"

@app.route('/courses', methods=['POST'])
def create_course():
    try:
        #make sure role is admis
        payload = verify_jwt(request)
        if not payload:
            raise ValueError(401)

        owner_sub = payload['sub']

        query = client.query(kind=USERS)
        query.add_filter('sub', '=', owner_sub)
        results = query.fetch()

        for entity in results:
            role = entity.get('role')
            print(role)
            if role != 'admin':
                raise ValueError(403)

        #check required fields in request
        content = request.get_json()
        required_fields = ["subject", "number", "title", "term", "instructor_id"]

        if not content or any(field not in content for field in required_fields):
            raise ValueError(400)

        instructor_id = int(content['instructor_id']) #instructor to create course for

        #make sure given instructor id is valid
        query = client.query(kind=USERS)
        query.add_filter('role', '=', 'instructor')
        instructors = list(query.fetch())
        instructor_entity = next((entity for entity in instructors if entity.key.id == instructor_id), None)
        if instructor_entity is None:
            raise ValueError(400)

        #add the new course
        course_key = client.key(COURSES)
        course_entity = datastore.Entity(key=course_key)

        course_entity.update({
            "subject": content["subject"],
            "number": content["number"],
            "title": content["title"],
            "term": content["term"],
            "instructor_id": content["instructor_id"],
        })

        client.put(course_entity)

        base_url = request.host_url.rstrip('/')
        course_id = course_entity.key.id
        response = {
            "id": course_id,
            "subject": content["subject"],
            "number": content["number"],
            "title": content["title"],
            "term": content["term"],
            "instructor_id": content["instructor_id"],
            "self": f"{base_url}/courses/{course_id}"
        }

        return jsonify(response), 201


    except ValueError as e:
        status_code = int(str(e))
        return get_error_message(status_code), status_code
    except AuthError as e:
        _, status_code = e.args
        return get_error_message(status_code), status_code

# Decode the JWT supplied in the Authorization header
@app.route('/decode', methods=['GET'])
def decode_jwt():
    payload = verify_jwt(request)
    return payload


@app.route('/users/login', methods=['POST'])
def login_user():
    try:

        content = request.get_json()

        if not content or not all(key in content for key in ["username", "password"]):
            return {"Error": "The request body is invalid"}, 400

        username = content["username"]
        password = content["password"]


        body = {'grant_type':'password',
                'username':username,
                'password':password,
                'client_id':CLIENT_ID,
                'client_secret':CLIENT_SECRET
                }

        headers = { 'content-type': 'application/json' }
        url = 'https://' + DOMAIN + '/oauth/token'

        r = requests.post(url, json=body, headers=headers)

        if r.status_code != 200:
            return ({"Error": "Unauthorized"}), 401
        print(r.json())
        token = r.json().get('id_token')
        return jsonify({"token": token}), 200
    except Exception as e:
        return {"error": f"An error occurred: {str(e)}"}, 500
# # @app.route('/businesses/<int:business_id>', methods=['DELETE'])

# @app.route('users/:id', methods = ['GET'])
# def get_user():

@app.route('/users', methods = ['GET'])
def get_all_users():
    """Returns a list of all users if the provided JWT is of type admin"""
    try:
        payload = verify_jwt(request)
        if not payload:  # Handle missing or invalid JWT
            raise ValueError(401)

        owner_sub = payload['sub']

        query = client.query(kind=USERS)
        query.add_filter('sub', '=', owner_sub)
        results = query.fetch()

        for entity in results:
            role = entity.get('role')
            if role != 'admin':
                raise ValueError(403)

        users_query = client.query(kind=USERS)
        results = users_query.fetch()

        users = []

        for user in results:
            users.append({
                "id": user.id,  # Datastore automatically assigns an ID
                "role": user.get("role"),
                "sub": user.get("sub")
            })

        return jsonify(users), 200

    except ValueError as e:
        status_code = int(str(e))
        return get_error_message(status_code), status_code
    except AuthError as e:
        _, status_code = e.args
        return get_error_message(status_code), status_code


# @app.route('/businesses', methods=['GET'])
# def get_businesses():
#     """Retrieve businesses based on the JWT provided in the request."""
#     try:
#         payload = verify_jwt(request)  # Verifies and returns the JWT payload if valid
#         owner_sub = payload["sub"]  # The sub (subject) claim in the JWT

#         # Fetch businesses where the owner matches the 'sub' field
#         query = client.query(kind=BUSINESSES)
#         query.add_filter('owner_id', '=', owner_sub)
#         businesses = list(query.fetch())

#         # Build the response (all 9 properties for valid JWT)
#         result = []
#         for business in businesses:
#             result.append({
#                 "city": business.get("city"),
#                 "id": business.key.id,
#                 "inspection_score": business.get("inspection_score"),
#                 "name": business.get("name"),
#                 "owner_id": business.get("owner_id"),
#                 "self": f"http://127.0.0.1:8080/businesses/{business.key.id}",
#                 "state": business.get("state"),
#                 "street_address": business.get("street_address"),
#                 "zip_code": business.get("zip_code")
#             })

#         return jsonify(result), 200

#     except AuthError as e:
#         # If JWT is invalid or missing, get all businesses without filtering by owner
#         query = client.query(kind=BUSINESSES)
#         businesses = list(query.fetch())

#         # Build the response (exclude inspection_score for invalid JWT)
#         result = []
#         for business in businesses:
#             result.append({
#                 "city": business.get("city"),
#                 "id": business.key.id,
#                 "name": business.get("name"),
#                 "owner_id": business.get("owner_id"),
#                 "self": f"http://127.0.0.1:8080/businesses/{business.key.id}",
#                 "state": business.get("state"),
#                 "street_address": business.get("street_address"),
#                 "zip_code": business.get("zip_code")
#             })

#         return jsonify(result), 200

# #Delete a businesses
# @app.route('/businesses/<int:business_id>', methods=['DELETE'])
# def delete_business(business_id):
#     """Delete a business by ID if the JWT owner matches."""
#     try:
#         #JWT from request
#         payload = verify_jwt(request)
#         owner_sub = payload["sub"]

#         business_key = client.key(BUSINESSES, business_id)
#         business = client.get(key=business_key)

#         #Check if business exists
#         if not business:
#             return jsonify({"Error": "No business with this business_id exists"}), 403

#         # Check if the owner matches the JWT
#         if business.get("owner_id") != owner_sub:
#             return jsonify({"Error": "No business with this business_id exists"}), 403

#         # Delete the business
#         client.delete(business_key)
#         return '', 204

#     except AuthError as e:
#         # Handle missing or invalid JWT
#         return jsonify({"Error": e.error['description']}), 401


# #Create a businesses
# @app.route('/businesses', methods=['POST'])
# def create_business():
#     try:

#         content = request.get_json()
#         required_fields = ["name", "street_address", "city", "state", "zip_code", "inspection_score"]

#         if not content or any(field not in content for field in required_fields):
#             return jsonify({"Error": "The request body is missing at least one of the required attributes"}), 400

#         payload = verify_jwt(request)
#         if not payload:
#             return jsonify({"Error": "Unauthorized"}), 401

#         new_business = datastore.entity.Entity(key=client.key(BUSINESSES))
#         new_business.update({
#             "owner_id": payload["sub"],
#             "name": content["name"],
#             "street_address": content["street_address"],
#             "city": content["city"],
#             "state": content["state"],
#             "zip_code": content["zip_code"],
#             "inspection_score": content["inspection_score"]
#         })
#         client.put(new_business)

#         response = {
#             "id": new_business.key.id,
#             "owner_id": payload["sub"],
#             "name": content["name"],
#             "street_address": content["street_address"],
#             "city": content["city"],
#             "state": content["state"],
#             "zip_code": content["zip_code"],
#             "inspection_score": content["inspection_score"],
#             "self": f"{request.host_url}businesses/{new_business.key.id}"
#         }
#         return jsonify(response), 201

#     except AuthError as e:
#         return jsonify(e.error), e.status_code
#     except Exception as e:
#         return jsonify({"Error": str(e)}), 500

# #get business by id
# @app.route('/businesses/<business_id>', methods=['GET'])
# def get_business(business_id):
#     try:
#         payload = verify_jwt(request)
#     except AuthError as e:
#         return jsonify(e.args[0]), e.status_code

#     # business from Datastore
#     business_key = client.key(BUSINESSES, int(business_id))
#     business = client.get(business_key)

#     # Check if the business exists
#     if not business:
#         return jsonify({"Error": "No business with this business_id exists"}), 403

#     # check if the current user is the owner of the business
#     if business["owner_id"] != payload["sub"]:
#         return jsonify({"Error": "No business with this business_id exists"}), 403

#     response = {
#         "id": business.key.id,
#         "owner_id": business["owner_id"],
#         "name": business["name"],
#         "street_address": business["street_address"],
#         "city": business["city"],
#         "state": business["state"],
#         "zip_code": business["zip_code"],
#         "inspection_score": business["inspection_score"],
#         "self": f"{request.host_url}businesses/{business.key.id}"
#     }

#     return jsonify(response), 200

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)

