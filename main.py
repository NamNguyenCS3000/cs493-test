from google.cloud import datastore
from flask import Flask, request, jsonify, _request_ctx_stack, make_response
import requests

from functools import wraps
import json

from six.moves.urllib.request import urlopen
from flask_cors import cross_origin
from jose import jwt

from os import environ as env
from werkzeug.exceptions import HTTPException

from dotenv import load_dotenv, find_dotenv
from flask import Flask
from flask import jsonify
from flask import redirect
from flask import render_template
from flask import session
from flask import url_for
from authlib.integrations.flask_client import OAuth
from six.moves.urllib.parse import urlencode

import re
import string
import constants
import flask

app = Flask(__name__)
app.secret_key = 'SECRET_KEY'

client = datastore.Client()

boats = "boats"

# Update the values of the following 3 variables
CLIENT_ID = '6jdNcevg5zzeCwPAg52lkr5xQWY3md9y'
CLIENT_SECRET = 'Qkpi0ZZsBpTkdDdx1j1x-V7iSRA1UI5UtHd2BA0OMFGBijbr1LvghuJGiR5HSo4f'
DOMAIN = 'cs493-fall.us.auth0.com'
# For example
# DOMAIN = 'fall21.us.auth0.com'

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


# Here we're using the /callback route.
@app.route('/callback')
def callback_handling():
    # Handles response from token endpoint
    id_token = auth0.authorize_access_token()['id_token']
    resp = auth0.get('userinfo')
    userinfo = resp.json()

    # Store the user information in flask session.
    session['jwt_payload'] = userinfo
    session['profile'] = {
        'user_id': userinfo['sub'],
        'name': userinfo['name'],
        'picture': userinfo['picture']
    }
    session['id_token'] = id_token
    return redirect('/dashboard')


@app.route('/login')
def login():
    return auth0.authorize_redirect(redirect_uri='https://hw1-328007.wn.r.appspot.com/callback')



def requires_auth(f):
  @wraps(f)
  def decorated(*args, **kwargs):
    if 'profile' not in session:
      # Redirect to Login page here
      return redirect('/login')
    return f(*args, **kwargs)
  return decorated


@app.route('/')
def home():
    return render_template('home.html')


@app.route('/dashboard')
@requires_auth
def dashboard():
    return render_template('dashboard.html',
                           userinfo=session['profile'],
                           userinfo_pretty=json.dumps(session['jwt_payload'], indent=4),
                           user_token=session['id_token'])


@app.route('/logout')
def logout():
    # Clear session stored data
    session.clear()
    # Redirect user to logout endpoint
    params = {'returnTo': url_for('https://hw1-328007.wn.r.appspot.com'), 'client_id': CLIENT_ID}
    return redirect(auth0.api_base_url + '/v2/logout?' + urlencode(params))


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
        if request.method == 'GET':
            return False
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


# Create a boat if the Authorization header contains a valid JWT
@app.route('/boats', methods=['POST', 'GET'])
def boats_post():
    if request.method == 'POST':
        payload = verify_jwt(request)
        content = request.get_json()
        new_boat = datastore.entity.Entity(key=client.key(constants.boats))
        new_boat.update({"name": content["name"], "type": content["type"], "length": content["length"], "public": True, "id": None, "owner": payload['sub']})
        client.put(new_boat)
        boat_key = client.key(constants.boats, new_boat.key.id)
        new_boat.update({"name": content["name"], "type": content["type"], "length": content["length"], "public": True, "id": new_boat.key.id, "owner": payload['sub']})
        client.put(new_boat)
        boat = client.get(key=boat_key)
        return json.dumps(boat), 201
    elif request.method == 'GET':
        query = client.query(kind=constants.boats)
        results = list(query.fetch())
        payload = verify_jwt(request)
        if payload == False:
            public_boats = []
            for boats in results:
                if boats['public'] == True:
                    public_boats.append(boats)
            return json.dumps(public_boats), 200
        else:
            owners_boats = []
            for e in results:
                e['id'] = e.key.id
            for boats in results:
                for val in boats.values():
                    if val == payload['sub']:
                        owners_boats.append(boats)
            return json.dumps(owners_boats), 200
    else:
        return 'Method not recognized'

@app.route('/owners/<sub>/boats', methods=['GET'])
def owner_get_delete_boats(sub):
    if request.method == 'GET':
        owners_boats = []
        query = client.query(kind=constants.boats)
        results = list(query.fetch())
        for e in results:
            e['id'] = e.key.id
        for boats in results:
            for val in boats.values():
                if val == sub:
                    for val_2 in results:
                        if val_2['public']:
                            owners_boats.append(boats)
                        else:
                            return 200
        return json.dumps(owners_boats), 200
    else:
        return 'Method not recognized'


    #if request.method == 'GET':
        #payload = verify_jwt(request)



# Decode the JWT supplied in the Authorization header
@app.route('/decode', methods=['GET'])
def decode_jwt():
    payload = verify_jwt(request)
    return payload


# Generate a JWT from the Auth0 domain and return it
# Request: JSON body with 2 properties with "username" and "password"
#       of a user registered with this Auth0 domain
# Response: JSON with the JWT as the value of the property id_token
@app.route('/login', methods=['POST'])
def login_user():
    content = request.get_json()
    username = content["username"]
    password = content["password"]
    body = {'grant_type':'password','username':username,
            'password':password,
            'client_id':CLIENT_ID,
            'client_secret':CLIENT_SECRET
           }
    headers = { 'content-type': 'application/json' }
    url = 'https://' + DOMAIN + '/oauth/token'
    r = requests.post(url, json=body, headers=headers)
    return r.text, 200, {'Content-Type':'application/json'}

@app.route('/boats/<id>', methods=['DELETE'])
def boats_delete(id):
    boat_key = client.key(constants.boats, int(id))
    boat = client.get(key=boat_key)
    query = client.query(kind=constants.boats)
    results = list(query.fetch())
    for boats in results:
        if boats['id'] == boat['id']:
            payload = verify_jwt(request)
            if boat['owner'] == payload['sub']:
                client.delete(boat_key)
                return ('', 204)
            else:
                return ('', 403)


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)
