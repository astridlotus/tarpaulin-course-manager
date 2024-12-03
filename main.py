import io
from flask import Flask, request, jsonify, send_file
from google.cloud import datastore, storage

import requests
import json

from six.moves.urllib.request import urlopen
from jose import jwt
from authlib.integrations.flask_client import OAuth

USERS = 'users'
COURSES = 'courses'
AVATAR_BUCKET = 'm6_bowden_avatars'

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

def build_next_url(offset, limit):
    return f"{request.host_url}courses?limit={limit}&offset={offset}"

@app.route('/courses', methods=['GET'])
def get_courses():
    offset = int(request.args.get('offset', 0))
    limit = int(request.args.get('limit', 3))

    query = client.query(kind=COURSES)
    query.order = ['subject']

    courses = list(query.fetch(limit=limit, offset=offset))

    course_list = []
    base_url = request.host_url.rstrip('/')


    for course in courses:
        course_data = {
            'id': course.key.id,
            'instructor_id': course['instructor_id'],
            'number': course['number'],
            "self": f"{base_url}/courses/{course.key.id}",
            'subject': course['subject'],
            'term': course['term'],
            'title': course['title']
        }
        course_list.append(course_data)

    next_offset = offset + limit
    next_url = build_next_url(next_offset, limit) if len(courses) == limit else None

    response = {
        'courses': course_list
    }

    if next_url:
        response['next'] = next_url

    return jsonify(response), 200

@app.route('/courses', methods=['POST'])
def create_course():
    try:
        #make sure role is admin
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

@app.route('/courses/<int:course_id>', methods=['PATCH'])
def update_course(course_id):
    try:
        # Ensure the user is an admin
        payload = verify_jwt(request)
        if not payload:
            raise ValueError(401)

        owner_sub = payload['sub']

        query = client.query(kind=USERS)
        query.add_filter('sub', '=', owner_sub)
        results = query.fetch()

        # Check if the user has an admin role
        for entity in results:
            role = entity.get('role')
            if role != 'admin':
                raise ValueError(403)

        course_key = client.key(COURSES, course_id)
        course_entity = client.get(course_key)

        if not course_entity:
            raise ValueError(403)  # Course not found

        content = request.get_json()

        updated_fields = {}
        if 'subject' in content:
            updated_fields['subject'] = content['subject']
        if 'number' in content:
            updated_fields['number'] = content['number']
        if 'title' in content:
            updated_fields['title'] = content['title']
        if 'term' in content:
            updated_fields['term'] = content['term']
        if 'instructor_id' in content:
            instructor_id = int(content['instructor_id'])

            print(instructor_id)
            # Make sure the instructor ID is valid
            query = client.query(kind=USERS)
            query.add_filter('role', '=', 'instructor')
            instructors = list(query.fetch())
            instructor_entity = next((entity for entity in instructors if entity.key.id == instructor_id), None)
            if instructor_entity is None:
                raise ValueError(400)

            updated_fields['instructor_id'] = instructor_id

        # Apply updates to the course entity
        course_entity.update(updated_fields)
        client.put(course_entity)

        base_url = request.host_url.rstrip('/')
        response = {
            "id": course_entity.key.id,
            "subject": course_entity.get("subject"),
            "number": course_entity.get("number"),
            "title": course_entity.get("title"),
            "term": course_entity.get("term"),
            "instructor_id": course_entity.get("instructor_id"),
            "self": f"{base_url}/courses/{course_entity.key.id}"
        }

        return jsonify(response), 200

    except ValueError as e:
        status_code = int(str(e))
        return get_error_message(status_code), status_code
    except AuthError as e:
        _, status_code = e.args
        return get_error_message(status_code), status_code
@app.route('/courses/<int:course_id>', methods=['DELETE'])
def delete_course(course_id):
    try:
        payload = verify_jwt(request)
        if not payload:
            raise ValueError(401)

        owner_sub = payload['sub']

        query = client.query(kind=USERS)
        query.add_filter('sub', '=', owner_sub)
        results = query.fetch()

        for entity in results:
            role = entity.get('role')
            if role != 'admin':
                raise ValueError(403)

        course_key = client.key(COURSES, course_id)
        course = client.get(course_key)
        if not course:
            raise ValueError(403)

        # Delete all students enrolled in the course
        enrollment_query = client.query(kind=COURSES)
        enrollment_query.add_filter('id', '=', course_id)
        enrollments = list(enrollment_query.fetch())

        for enrollment in enrollments:
            client.delete(enrollment.key)  # Remove the enrollment record

        instructor_id = course.get('instructor_id')
        if instructor_id:
            instructor_key = client.key(USERS, instructor_id)
            instructor = client.get(instructor_key)
            if instructor:
                course_ids = instructor.get('course_ids', [])
                if course_id in course_ids:
                    course_ids.remove(course_id)
                    instructor['course_ids'] = course_ids
                    client.put(instructor)

        client.delete(course_key)

        return '', 204

    except ValueError as e:
        status_code = int(str(e))
        return get_error_message(status_code), status_code
    except AuthError as e:
        _, status_code = e.args
        return get_error_message(status_code), status_code

@app.route('/courses/<int:course_id>', methods=['GET'])
def get_course(course_id):
    try:
        course_key = client.key(COURSES, course_id)
        course = client.get(course_key)

        if not course:
            raise ValueError(404)

        course_data = {
            'id': course.key.id,
            'instructor_id': course['instructor_id'],
            'number': course['number'],
            'self': f"{request.host_url}courses/{course.key.id}",
            'subject': course['subject'],
            'term': course['term'],
            'title': course['title']
        }

        return jsonify(course_data), 200
    except ValueError as e:
        status_code = int(str(e))
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

@app.route('/users/<int:user_id>', methods=['GET'])
def get_user(user_id):
    try:
    # Extract the JWT from the Authorization header
        payload = verify_jwt(request)
        if not payload:
            raise ValueError(401)

        user_key = client.key(USERS, user_id)
        user = client.get(user_key)

        if not user:
            raise ValueError(403)

        given_sub = payload['sub']
        user_sub = (user.get('sub'))

        # user_key = client.key(USERS, int(user_id))
        # user = client.get(user_key)
        # print(user)

        # #check the auth sub on the jwt sent and attempted change are the same
        # if user:
        #     user_sub = (user.get('sub'))
        #     if user_sub != owner_sub:
        #         raise ValueError(403)
        # else:
        #     raise ValueError(403)

        # Check if the JWT belongs to the user or if the user is an admin
        if user_sub != given_sub and user.get("role") != "admin":
            print('nope')
            print(user_sub)
            print(given_sub)
            print(user.get('role'))
            raise ValueError(403)

        # Construct the response
        response = {
            "id": user_id,
            "role": user["role"],
            "sub": user["sub"]
        }

        base_url = request.host_url.rstrip('/')
        # Add avatar_url if the user has an avatar
        if user.get("avatar"):
            response["avatar_url"] = f"{base_url}/users/{user_id}/avatar"

        # Add courses if the user is an instructor or student
        if user["role"] in ["instructor", "student"]:
            response["courses"] = []
            courses_query = client.query(kind=COURSES)

            if user["role"] == "instructor":
                courses_query.add_filter("instructor_id", "=", user_id)

            elif user["role"] == "student":
                courses_query.add_filter("students", "=", user_id)

            for course in courses_query.fetch():
                response["courses"].append(f"{base_url}/courses/{course.key.id}")

        return jsonify(response), 200
    except ValueError as e:
        status_code = int(str(e))
        return get_error_message(status_code), status_code
    except AuthError as e:
        _, status_code = e.args
        return get_error_message(status_code), status_code

@app.route('/users/<int:user_id>/avatar', methods=['GET'])
def get_avatar(user_id):
    try:
        payload = verify_jwt(request)
        if not payload:
            raise ValueError(401)

        # The sub on the jwt send in
        owner_sub = payload['sub']

        user_key = client.key(USERS, int(user_id))
        user = client.get(user_key)
        print(user)

        #check the auth sub on the jwt sent and attempted change are the same
        if user:
            user_sub = (user.get('sub'))
            if user_sub != owner_sub:
                raise ValueError(403)
        else:
            raise ValueError(403)

        file_name = user['avatar']
        if not file_name:
            raise ValueError(404)

        storage_client = storage.Client()
        bucket = storage_client.get_bucket(AVATAR_BUCKET)
        # Create a blob with the given file name
        blob = bucket.blob(file_name)
        # Create a file object in memory using Python io package
        file_obj = io.BytesIO()
        # Download the file from Cloud Storage to the file_obj variable
        blob.download_to_file(file_obj)
        # Position the file_obj to its beginning
        file_obj.seek(0)
        # Send the object as a file in the response with the correct MIME type and file
        # name
        return send_file(file_obj, mimetype='image/png', download_name=file_name)

    except ValueError as e:
        status_code = int(str(e))
        return get_error_message(status_code), status_code
    except AuthError as e:
        _, status_code = e.args
        return get_error_message(status_code), status_code

@app.route('/users/<int:user_id>/avatar', methods=['DELETE'])
def delete_avatar(user_id):
    try:
        payload = verify_jwt(request)
        if not payload:
            raise ValueError(401)

        owner_sub = payload['sub']

        user_key = client.key(USERS, int(user_id))
        user = client.get(user_key)

        if not user:
            raise ValueError(404)

        user_sub = user.get('sub')
        if user_sub != owner_sub:
            raise ValueError(403)

        # Check if the user has an avatar
        file_name = user.get('avatar', '')
        if not file_name:
            raise ValueError(404)

        storage_client = storage.Client()

        storage_client = storage.Client()
        bucket = storage_client.get_bucket(AVATAR_BUCKET)
        blob = bucket.blob(file_name)

        if not blob.exists():
            raise ValueError(404)  # Avatar file does not exist

        blob.delete()

        user['avatar'] = ''
        client.put(user)

        return '', 204

    except ValueError as e:
        status_code = int(str(e))
        return get_error_message(status_code), status_code
    except AuthError as e:
        _, status_code = e.args
        return get_error_message(status_code), status_code

@app.route('/users/<int:user_id>/avatar', methods=['POST'])
def upload_user_avatar(user_id):
    try:
        if 'file' not in request.files:
            print('nope')
            raise ValueError(400)

        file_obj = request.files['file']
        print(file_obj)

        payload = verify_jwt(request)
        if not payload:
            raise ValueError(401)

        # The sub on the jwt send in
        owner_sub = payload['sub']

        user_key = client.key(USERS, int(user_id))
        user = client.get(user_key)
        print(user)

        #check the auth sub on the jwt sent and attempted change are the same
        if user:
            user_sub = (user.get('sub'))
            if user_sub != owner_sub:
                raise ValueError(403)
        else:
            raise ValueError(403)

        storage_client = storage.Client()
        bucket = storage_client.get_bucket(AVATAR_BUCKET)
        # Create a blob object for the bucket with the name of the file
        blob = bucket.blob(file_obj.filename)
        # Position the file_obj to its beginning
        file_obj.seek(0)
        # Upload the file into Cloud Storage
        blob.upload_from_file(file_obj)

        user['avatar'] = file_obj.filename
        client.put(user)
        base_url = request.host_url.rstrip('/')
        return ({'avatar_url': f"{base_url}/users/{user_id}/avatar"},200)


    except ValueError as e:
        status_code = int(str(e))
        return get_error_message(status_code), status_code
    except AuthError as e:
        _, status_code = e.args
        return get_error_message(status_code), status_code
# @app.route('/images', methods=['POST'])
# def store_image():
#     # Any files in the request will be available in request.files object
#     # Check if there is an entry in request.files with the key 'file'
#     if 'file' not in request.files:
#         return ('No file sent in request', 400)
#     # Set file_obj to the file sent in the request
#     file_obj = request.files['file']
#     # If the multipart form data has a part with name 'tag', set the
#     # value of the variable 'tag' to the value of 'tag' in the request.
#     # Note we are not doing anything with the variable 'tag' in this
#     # example, however this illustrates how we can extract data from the
#     # multipart form data in addition to the files.
#     if 'tag' in request.form:
#         tag = request.form['tag']
#     # Create a storage client
#     storage_client = storage.Client()
#     # Get a handle on the bucket
#     bucket = storage_client.get_bucket(PHOTO_BUCKET)
#     # Create a blob object for the bucket with the name of the file
#     blob = bucket.blob(file_obj.filename)
#     # Position the file_obj to its beginning
#     file_obj.seek(0)
#     # Upload the file into Cloud Storage
#     blob.upload_from_file(file_obj)
#     return ({'file_name': file_obj.filename},201)

# @app.route('/images/<file_name>', methods=['GET'])
# def get_image(file_name):
#     storage_client = storage.Client()
#     bucket = storage_client.get_bucket(PHOTO_BUCKET)
#     # Create a blob with the given file name
#     blob = bucket.blob(file_name)
#     # Create a file object in memory using Python io package
#     file_obj = io.BytesIO()
#     # Download the file from Cloud Storage to the file_obj variable
#     blob.download_to_file(file_obj)
#     # Position the file_obj to its beginning
#     file_obj.seek(0)
#     # Send the object as a file in the response with the correct MIME type and file
#     # name
#     return send_file(file_obj, mimetype='image/x-png', download_name=file_name)

# @app.route('/images/<file_name>', methods=['DELETE'])
# def delete_image(file_name):
#     storage_client = storage.Client()
#     bucket = storage_client.get_bucket(PHOTO_BUCKET)
#     blob = bucket.blob(file_name)
#     # Delete the file from Cloud Storage
#     blob.delete()
#     return '',204


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

