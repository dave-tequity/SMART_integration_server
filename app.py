
import json
from flask import Flask, request, render_template, make_response, redirect
import logging
import jwt
from flask_migrate import Migrate
import requests
import urllib
import time
import uuid
import base64
import os
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


        client_id = os.environ.get(f'provider_client_id')
        redirect_uri = os.environ.get('baseurl') + '/launch/redirect'

        # for native mobile apps add PKCE support
        # code_challenge = sha256(b"randomcontent").hexdigest()

        resp = make_response(redirect(f"""{wellKnownEndpoints['authorize_endpoint']}?scope={urllib.parse.quote("launch openid fhirUser")}&response_type=code&
                                      redirect_uri={urllib.parse.quote(redirect_uri)}&client_id={client_id}&launch={launch}
                                      &state={state}&aud={iss}""")) #+'&code_challenge='+code_challenge+'&code_challenge_method=S256'
        print(f'response url: {resp}')
        session = Session(
            id = state,
            iss = iss,
            endpoint_data = wellKnownEndpoints,
            launch_token = launch
            )
        
        db.session.add(session)
        db.session.commit()

    return resp

@app.route('/launch/redirect', methods=['GET', 'POST'])
def SMART_redirect():
    code = request.args.get("code")
    state = request.args.get("state")

    #remove this if not using a database
    session = Session.query.filter_by(id=state).first()

    #a "standalone" SMART launch by a patient
    if code and state:
        #only supporting Epic for now for standalone patient launches
        token_endpoint = 'https://fhir.epic.com/interconnect-fhir-oauth/oauth2/token'
        jwks_uri = 'https://fhir.epic.com/interconnect-fhir-oauth/api/epic/2019/Security/Open/PublicKeys/530027/OIDC'

        h = {"Content-Type": "application/x-www-form-urlencoded"}
        redirect_extension = '/launch/redirect'
        redirect_uri = baseurl + redirect_extension
        client_id = os.environ.get('patient_client_id')

        b = {'grant_type': 'authorization_code',
        'code': code, #taken directly from inbound request
        'redirect_uri': redirect_uri}

        secret = client_id + ':' + os.environ.get('epic_patient_secret')
        h['Authorization'] = 'Basic '+ str(base64.b64encode(secret.encode('ascii')), 'utf-8')
 
        p = requests.post(token_endpoint, data=b, headers=h)
        print(f'token response: {p.text}')
        resp = json.loads(p.text)

        #Validate the OIDC token with the pre-defined JWKS URI
        if resp:
            validated = common.validate_fhir_token(client_id, token=resp.get("id_token"), jwks_uri=jwks_uri)
        if validated:
            return render_template('Authorized.html', title=' SMART on FHIR Viewer', data = resp)
        else:
            return f"OIDC JWKS validation failed"


    #a provider launch or patient launch from the portal
    #you'll have to hardcode the token_endpoint and bypass the OIDC validation if not using a database
    if code and state and session:
        token_endpoint = session.token_endpoint
        h = {"Content-Type": "application/x-www-form-urlencoded"}
        redirect_uri = baseurl + redirect_extension
        client_id = os.environ.get('provider_client_id')

        b = {'grant_type': 'authorization_code',
        'code': code, #taken directly from inbound request
        'redirect_uri': redirect_uri}

        secret = client_id + ':' + os.environ.get('epic_provider_secret')
        h['Authorization'] = 'Basic '+ str(base64.b64encode(secret.encode('ascii')), 'utf-8')
 
        p = requests.post(token_endpoint, data=b, headers=h)
        print(f'token response: {p.text}')
        resp = json.loads(p.text)

        #Validate the OIDC token with the pre-defined JWKS URI
        if resp:
            validated = common.validate_fhir_token(client_id, token=resp.get("id_token"), jwks_uri=session.get("jwks_uri"))
        if validated:
            return render_template('Authorized.html', title=' SMART on FHIR Viewer', data = resp)
        else:
            return f"OIDC JWKS validation failed"
    return f"There was a problem with the request. Code: {code} State: {state} Session {session}"

@app.route('/api/config/standalone', methods=['GET'])
def get_standalone_config():

    aud = 'https://fhir.epic.com/interconnect-fhir-oauth/oauth2/authorize'
    redirect =  baseurl + redirect_extension
    state = str(uuid.uuid4().int)
    url = f"""https://fhir.epic.com/interconnect-fhir-oauth/oauth2/authorize?
state={state}
&scope=launch openid fhirUser&
response_type=code
&redirect_uri={urllib.parse.quote(redirect)}
&client_id={patient_audience_client_id}
&aud={urllib.parse.quote(aud)}"""

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
    logging.warn(service_client_id)
    cert_str="-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCa3qMnTYsWNYnZ\nKtGyRd8mdk/FO0Ivi3WnMc3pCH5nFW160acSTP1x02eRvYylHpag1SScOhdLSTrM\nTqMj3ra8z/KMyRq6csDCE5AYIyndn5Y01hMnIfsW9jsKaksl3l6fvgPNvb7+ANoI\nM6TDQnnVcHfe9qkCx7t1LpqiZHgakqY0ru3asVAICB93CBVtQlmpTgqmS1UfGKUm\nhBDRmPqHqiXF/2J02ypdiF0Ln3L5Q0aYJZpKG2ZCPoHVDX0/IOb5Yf4L6EpWTNXz\n8e2sZRDUxbNC5CCVKMmaCmWQQ6bTBC0YerUDp+IT5Q56B5ENgHuuaqlohN7LS6nn\nEX+dkPT7AgMBAAECggEAOfzhBEdhq9gyHFGPIPxOmN018zjECH9kd00Lt5TJl5mL\nW7CCqTSQtX0dy5E4x17Tsbb9NU3/CN6LmJJdPYIX1EzcmeB3FJcBG+otSwxnkac+\nm9wIYd+0X52k77prFuvTbGa+j9vbVspE2UtVBxOuAMBS8fZTxEm7JB5mIiYSXogy\nghkQI67sLb1Tkfx6u//O1cSjMrqqs2ToxuT6UWKgIDrN51rBb7hybnH084JTPF0q\n2LyuYu97oC2r1IOQ0Z9sWRJhS6aDpRVfX68RmH34k6HJaEzcIMmCq5nwSy/hl7p+\nOPmWPh8qQX3rtOvY5CQODHWEzrHZC5tdcxj/c5eriQKBgQDfS2nts5a0Lz+RW1IX\nSYsE9Nt3xL6hetxyxCQya8441zH/LuGhjHwwl34vXBSnXqwiU1zvqw5gfFuHOjzR\nYUEHVGjQJ7H6jwjNW36tRmxNrMzRzb84rK206I0WL2VGS5reR1NUvJWb+AsxMHqR\nDqNSYbPC9PGfNMUIqt/0kAhKlQKBgQCxjZV5M8Soa906lVoTdVKrrxnreAxmYPX5\nh6bj3u7uRLQir9rdBJoq2T3gjefCyATorhKBatvsBN0gU4bOgrluPUdFrUxSI+pc\n0MJw1yWJkCq8kVxm0lYtP/1GT7ShBqTIiXxDFJhmIRtrW2URGtK/cov33GHlQn/R\nIBWEHp7tTwKBgQDUKBcRXhzGPk4rkZTBw4Juxybu+OQXEWD7OhkaPwvFPdGnH6gJ\nki09DfM6lEabb3wlcQdQQDp8uitMpKy8U6cxi6W6gLy9z8ERPOlzQQIOGyzP+qjA\n9HBm/r1uYsHatGME5sfqLvQHKPmZVvJdeIb88w+VIJ2iIsVCovf+qgr2sQKBgDti\nv7vqNLygVz5g9d/MPfpudpzrajpT8/GiDY/p4MCQ+i8f4nRKNcZfIvMYg4wCmqG4\nlzfyJdyrQ8qsJUqtLphQpqYHcJ+Io7qnmGFllIiOT70CYYWClJBN9sitoBy7vCHW\n2lkVamO+bw1ZZFR0REkEZwxgCd5Ef7vSn1+xXjbBAoGBAJcipVECi8iVrfcJrM1Q\nPJIHsPkcYd2+F4Bti62ylcWVaaTt95P1NlKysf6EnLpTadXhSLXX9lHtznl5YEm5\nCQ9lecMCDyX+LSskNyNtxANaZTECY0y8MvMMpOfFyyvbxBG6xPQry06gV3v4UB8b\nIu28TT9qHrIAFhn7zQLWZ+GE\n-----END PRIVATE KEY-----"
    epic_token_url = "https://fhir.epic.com/interconnect-fhir-oauth/oauth2/token"
    header = {'alg': 'RS256', 'typ': 'JWT'} 
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
    token = jwt.encode(payload, cert_str, algorithm='RS256',headers=header)

    body = {'grant_type': 'client_credentials',
    'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
    'client_assertion': token
    }

    head = {'Content-Type': 'application/x-www-form-urlencoded'}

    r = requests.post(epic_token_url, data=body, headers=head)
    response_data = json.loads(r.text)
    # logging.warn(response_data)

    access_token = ''
    if r.status_code == 200:
        access_token = response_data['access_token']
    logging.warn(access_token)
    display_data = {'Access Token Data' :[('Access Token ', access_token)]}

    #set the patient ID

    return render_template('Authorized.html', title=' SMART on FHIR Viewer', 
    data = display_data, token=access_token, patient="e63wRTbPfr1p8UW81d8Seiw3")

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

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=80)