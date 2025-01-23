import requests
import json
import urllib
import os
import settings
import jwt


def getEndpointsMetadata(iss):
    conf_headers = {'Accept': 'application/fhir+json'}
    conformance = requests.get(iss + "/metadata", headers=conf_headers)
    conf = json.loads(conformance.text)
    authorize_endpoint = '' 
    token_endpoint = ''
    if conf.get('resourceType') in ['CapabilityStatement','Conformance']:
        uri_extensions = conf.get('rest')[0].get('security').get('extension')[0].get('extension')
        for u in uri_extensions:
            if u.get('url') == 'authorize':
                authorize_endpoint = u.get('valueUri')
            if u.get('url') == 'token':
                token_endpoint = u.get('valueUri')
    endpoints = {
        'authorize_endpoint': authorize_endpoint,
        'token_endpoint': token_endpoint,
    }
    return endpoints


def getEndpointsWellKnown(iss):
    #GET THE JWKS URI instead
    # , RETURN OBJECTS?
    conf_headers = {'Accept': 'application/fhir+json'}
    well_known_url = f'{iss}.well-known/openid-configuration'
    well_known_data = requests.get(well_known_url, headers=conf_headers)
    jwks_uri = None
    well_known_json = None
    token_endpoint = None
    if well_known_data.status_code == 200:
        well_known_json = json.loads(well_known_data.text)
        jwks_uri = well_known_json.get('jwks_uri')
        token_endpoint = well_known_json.get('token_endpoint')
        

    endpoints = {
        'token_endpoint': token_endpoint,
        'well_known_url': well_known_url,
        'well_known_json': well_known_json,
        'jwks_uri': jwks_uri,
    }

    return endpoints



# validate if the token is valid from the jwks public key   
def validate_fhir_token(client_id, token=None,jwks_uri=None):
    
    if not token:
        print("No id token provided")
        return None
    
    try:
        #get the openid-configuration data from a hardcoded endpoint for this customer environment
        #e.g.: https://fhir.epic.com/interconnect-fhir-oauth/oauth2/.well-known/openid-configuration
        openIdhead = {
            'Accept': 'application/json'
        }

        jwks_resp = requests.get(jwks_uri, headers=openIdhead, verify=False)
        jwk_keys = json.loads(jwks_resp.text)
        
        decoded_token = None
        key = None

        pub_keys = {}
        for jwk in jwk_keys['keys']:
            kid = jwk['kid']
            pub_keys[kid] = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk))

            token_header = jwt.get_unverified_header(token)
            if 'kid' in token_header:
                key = pub_keys[token_header['kid']]        
            else:
                key = pub_keys[jwk['kid']]        
            if key:
                decoded_token = jwt.decode(token,audience=client_id,key=key, algorithms=['RS256'])
        # Token is valid
        return decoded_token
    except Exception as e:
        print("Error validating token: ", e)
        # Token is invalid
        return None