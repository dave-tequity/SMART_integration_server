
import json
from flask import Flask, request, render_template, make_response, redirect, jsonify
import logging
import jwt
from jwcrypto import jwk
import json
from flask_migrate import Migrate
import requests
import urllib
import time
import uuid
import base64
import os
from hashlib import sha256
import secrets
import common
import utilities.config as config
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

#Initialize SQLAlchemy
from models import db, Session

app.config['SQLALCHEMY_DATABASE_URI'] = config.DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
migrate = Migrate(app, db)

#setup shared variables
app.secret_key = os.environ.get('flask_secret')
service_client_id = config.SERVICE_CLIENT_ID
patient_audience_client_id = config.EPIC_PATIENT_CLIENT_ID
baseurl = config.BASE_URL
fhir_epic_url = 'https://fhir.epic.com/interconnect-fhir-oauth/oauth2/authorize'
redirect_extension = '/launch/redirect'

# Store PKCE code_verifiers (in production, use Redis or database)
pkce_store = {}

@app.route('/')
def home():
    return render_template('Home.html', title='SMART on FHIR Viewer')


@app.route('/launch', methods=['GET','POST'])
def provider_launch():
    launch = request.args.get('launch')
    iss = request.args.get("iss")

    #consider implementing an ISS whitelist here
    #if iss not in <whitelist>:
        # return "Invalid issuer"
    
    if launch and iss:
        state = str(uuid.uuid4().int)

        # Grab endpoints from conformance data
        #use the metadata statement if no well known URL
        # endpoints = common.getEndpointsMetadata(iss)
        wellKnownEndpoints = common.getEndpointsWellKnown(iss)

        # Check if we got the required endpoints
        if not wellKnownEndpoints.get('authorize_endpoint'):
            return f"Could not retrieve authorization endpoint from {iss}"

        client_id = os.environ.get(f'provider_client_id')
        redirect_uri = baseurl + '/launch/redirect'

        # PKCE support according to RFC 7636 and SMART on FHIR spec
        # Generate a cryptographically random code_verifier (43-128 characters)
        code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')
        
        # Create code_challenge = BASE64URL(SHA256(code_verifier))
        code_challenge = base64.urlsafe_b64encode(sha256(code_verifier.encode('utf-8')).digest()).decode('utf-8').rstrip('=')
        
        # Store code_verifier for later use in token exchange (use state as key)
        pkce_store[state] = code_verifier

        # Construct the authorization URL
        auth_url = f"""{wellKnownEndpoints['authorize_endpoint']}?scope={urllib.parse.quote("launch openid fhirUser")}&response_type=code&redirect_uri={urllib.parse.quote(redirect_uri)}&client_id={client_id}&launch={launch}&state={state}&aud={iss}&code_challenge={code_challenge}&code_challenge_method=S256"""
        
        print(f'Authorization URL: {auth_url}')
        print(f'Code verifier: {code_verifier}')
        print(f'Code challenge: {code_challenge}')
        
        # resp = make_response(redirect(auth_url)) #+'&code_challenge='+code_challenge+'&code_challenge_method=S256'
        # print(f'Response status: {resp.status_code}')
        # print(f'Response headers: {dict(resp.headers)}')
        # print(f'Redirect location: {resp.location}')
        # session = Session(
        #     id = state,
        #     iss = iss,
        #     endpoint_data = wellKnownEndpoints,
        #     launch_token = launch
        #     )
        
        # db.session.add(session)
        # db.session.commit()

    return auth_url

@app.route('/launch/redirect', methods=['GET', 'POST'])
def SMART_redirect():
    code = request.args.get("code")
    state = request.args.get("state")
    print(f'code: {code}')
    print(f'state: {state}')

    #a provider launch or patient launch from the portal
    #you'll have to hardcode the token_endpoint and bypass the OIDC validation if not using a database
    if code and state:
        # Get the stored code_verifier for PKCE
        code_verifier = pkce_store.get(state)
        print(f'code_verifier: {code_verifier}')
        if not code_verifier:
            return f"Invalid state parameter or expired PKCE code_verifier"
        
        # token_endpoint = session.token_endpoint
        token_endpoint = 'https://fhir.epic.com/interconnect-fhir-oauth/oauth2/token'
        h = {"Content-Type": "application/x-www-form-urlencoded"}
        redirect_uri = baseurl + redirect_extension
        print(f'redirect_uri: {redirect_uri}')
        client_id = os.environ.get('provider_client_id')

        # Include code_verifier for PKCE verification
        b = {'grant_type': 'authorization_code',
        'code': code, #taken directly from inbound request
        'redirect_uri': redirect_uri,
        'code_verifier': code_verifier,
        'client_id': client_id  # Add client_id to the body instead of using Basic auth
        }

        # Remove Basic auth for PKCE flow - code_verifier provides authentication
        # secret = client_id + ':' + os.environ.get('epic_provider_secret')
        # h['Authorization'] = 'Basic '+ str(base64.b64encode(secret.encode('ascii')), 'utf-8')
 
        p = requests.post(token_endpoint, data=b, headers=h)
        print(f'token response: {p.text}')
        resp = json.loads(p.text)
        print(f'token response: {resp}')
        print(f'token response HTTP status: {p.status_code}')
        
        # Clean up the stored code_verifier
        del pkce_store[state]

        if resp:
            return render_template('Authorized.html', title=' SMART on FHIR Viewer', data = resp)
        else:
            return f"OIDC JWKS validation failed"
    return f"There was a problem with the request. Code: {code} State: {state}"

@app.route('/api/config/standalone', methods=['GET'])
def get_standalone_config():

    aud = 'https://fhir.epic.com/interconnect-fhir-oauth/oauth2/authorize'
    redirect =  baseurl + redirect_extension
    state = str(uuid.uuid4().int)
    
    # PKCE support for standalone launch
    # Generate a cryptographically random code_verifier (43-128 characters)
    code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')
    
    # Create code_challenge = BASE64URL(SHA256(code_verifier))
    code_challenge = base64.urlsafe_b64encode(sha256(code_verifier.encode('utf-8')).digest()).decode('utf-8').rstrip('=')
    
    # Store code_verifier for later use in token exchange (use state as key)
    pkce_store[state] = code_verifier
    
    url = f"""https://fhir.epic.com/interconnect-fhir-oauth/oauth2/authorize?state={state}&scope=launch openid fhirUser&response_type=code&redirect_uri={urllib.parse.quote(redirect)}&client_id={patient_audience_client_id}&aud={urllib.parse.quote(aud)}&code_challenge={code_challenge}&code_challenge_method=S256"""

    wellKnownEndpoints = common.getEndpointsWellKnown(aud)


    #comment out if not using a DB
    session = Session(
    id = state,
    iss = aud,
    endpoint_data = wellKnownEndpoints,
    launch_token = None
    )
        
    db.session.add(session)
    db.session.commit()
    #########################################

    return {'url':url}

@app.route('/systemlaunch', methods=['GET','POST'])
def system_launch():
    logging.warn(f"service_client_id: {service_client_id}")
    cert_str="-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDZPp9a7KolkLCI\nnZGKadMxa6/MNehE3ypVhuh8MLfr08G7bAVzt0ukEYM6qW3skjasBLjDVmDt3vi9\neDJWMnNSzA/8AqKGto25wksIz+yZhaTEQHssGfRtq/2hc4dPFTsGFjyuHC8nZpmm\na642B58Os6QpPKVVS9Qv+wVVjR5fUxbvR1iXPsL4rNBPtfwsAFRE1yBO37EHmw3j\n0QAoX9MC2saI4pqf3Mk4hD1ddSMqk72y5DhgQrrlMFDC9VrzXiUZUljS4KCC3xM8\nuYgkmDZeRL42/qsJLgIItRm/kJscn57c1q4PNh9cbdKLbRjl4+oJy15aPLvjU9Yj\nDmfrqHxxAgMBAAECggEAFH/yiSGyh5Nw+R9HS9SjG3OCNgazOYaGh+YQW6G8RUpo\n6l7t38bA4kVNyRQSXaPJeW+DoNkukdu7xKNKOrSNiddcPcdg303sL0Z8jqMSPEVu\ncB92kAmN9WhoqVrNvqJt/KvOA48AyxrFLn1UReBvu7Mrb0G8B0G9zt5E2VcU8eEo\nkot2CNBpESzyjsKuff0cjDR49cfyThEa480uRUAL20bjJE110zHpOgtpzQ4iAtaD\nNmJHv+w3Qjwu5oufK2Tl81O79f4OqLVx5nTanc30w3WMiQfBf+mgKPWhPHBH2eDI\nq7GVcq6a2y8ekhYgXcxHtbd7NJflHZmDIh1vCTElfQKBgQDvSQswny9j+coR1Wi9\n14xcrxOjt2HUFGXq8W2Q7gEFQ7MPsTMnP3toCbbk7VdV74+fnw7cTJZtis1ysKqt\nWDx02i4q61AAF/xRlPB9+mNby+AJOXcMARJuaLhdsGVU1+NjwxzmqrIVKydUzZDf\nLBhdmu3g3YieUagKopj6p8tgPQKBgQDoa3ERDjghPYmETFJ4ND42regdZxgG0i19\nkL5wgPexiFut5KtBDclg77BdWt93urhclsSEO383CFe/RitvtW+EtcCfIevlu8yd\nn+4rHpTowNjNBGOtqHKrdHKpiC18zOu665nA7Ide3YXguFYN6WofvTAZHD95n1jU\nKJVrVcJ8RQKBgQCErsgZqespULUPtnph6kfWjO4i9ei1JKpu4HiUyKSgOq3roaJv\nvO+8/MYBoumuqSvGovgmiAFRtIm/ct7xR+AeG21GNz0hECvFQQUpldHKcP5Fnyu3\n6FBEEKVKrilCJoPcKbC45yXgPxGMIICYf2bzYJlO+whqYXUAkLCrLKfFMQKBgDdC\nhGmHtfTBStb3xovp7/jUNGH5Rw8oHcTDC2R4ZWwCfbnEqqsW+hBgLNClcIhpDriE\n6EiAVOjixOonZuByhQdKp3euewXuNuIrSldaOBF2+JUWPBTn/guh7jk8tYP8vPd+\nWNoz4qO9i704Vs2L972AH9V4j+b86gPXel9AzrL5AoGAV4eYPfwl0oc4MSOGiegM\nHmcOQRsJWzrEoSopGoLXYHwkxQOzcsMYnoGVX7Dqv81bgNm75AuhK/sZXhUVt+yX\nhAy9hrUn0EmnloYbZEWZRQixCx2NOdBaXDrwBmAb59bOnNtZfUGkBVIrSSUeI6yE\njRwJWRwRmno1GBbBc4a/l1g=\n-----END PRIVATE KEY-----"
    epic_token_url = "https://fhir.epic.com/interconnect-fhir-oauth/oauth2/token"
    header = {'alg': 'RS384', 'typ': 'JWT'} 
    current_time = int(time.time())
    payload = {
        'iss': service_client_id,
        'sub': service_client_id,
        'aud': epic_token_url,
        'jti': str(uuid.uuid4().int), #not longer than 151 char. random generated
        'exp': current_time + 299, #nbf + 5 min
        'nbf': current_time, #current UNIX time UTC
        'iat': current_time, #same as nbf
    }
    cert_str = cert_str.encode()
    token = jwt.encode(payload, cert_str, algorithm='RS384',headers=header)
    logging.warn(f"token: {token}")

    body = {'grant_type': 'client_credentials',
    'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
    'client_assertion': token
    }

    head = {'Content-Type': 'application/x-www-form-urlencoded'}
    curl_request = f"curl -X POST {epic_token_url} -H 'Content-Type: application/x-www-form-urlencoded' -d 'grant_type=client_credentials&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer&client_assertion={token}'"
    print(f"curl_request: {curl_request}")

    # r = requests.post(epic_token_url, data=body, headers=head)
    # response_data = json.loads(r.text)
    
    # print(curl_request)
    # logging.warn(f"response_data: {response_data}")

    # access_token = ''
    # if r.status_code == 200:
    #     access_token = response_data['access_token']
    # logging.warn(access_token)
    # display_data = {'Access Token Data' :[('Access Token ', access_token)]}

    #set the patient ID

    return render_template('Authorized.html', title=' SMART on FHIR Viewer', 
    data = {}, token="", patient="e63wRTbPfr1p8UW81d8Seiw3")

@app.route('/api/fhir', methods=['GET'])
def getPatientFHIRResource():
    logging.warn("fetching FHIR resource")
    token = request.args.get("access_token")
    patient = request.args.get("patient")
    logging.warn(patient)
    if token:
        #if the patient value is not provided, assume a patient ID just to show a response
        if not patient:
            url = 'https://fhir.epic.com/interconnect-fhir-oauth/api/FHIR/R4/Patient/e63wRTbPfr1p8UW81d8Seiw3'
            head = {
                "Authorization": "Bearer "+ token,
                "Accept": "application/fhir+json"
            }
            r = requests.get(url, headers=head)
            logging.warn(r.text)
            return r.text
        else:
            url = 'https://fhir.epic.com/interconnect-fhir-oauth/api/FHIR/R4/Patient/'+patient
            head = {
                "Authorization": "Bearer "+ token,
                "Accept": "application/fhir+json"
            }
            r = requests.get(url, headers=head)
            logging.warn(r.text)
            return r.text
    return "access_token not provided"

@app.route('/api/jwks', methods=['GET'])
def getJWKS():
    keys = []
    public_keys_dir = 'public_keys'
    for f in os.listdir(public_keys_dir):
        file_path = os.path.join(public_keys_dir, f)
        with open(file_path, 'rb') as pemfile:
            keys.append(jwk.JWK.from_pem(pemfile.read()))
    jwks = {
        "keys": [json.loads(key.export_public()) for key in keys]
    }
    return jsonify(jwks)


    return jsonify({"message": "hello world"})

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8000, debug=True)