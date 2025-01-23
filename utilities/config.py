import os
import logging

def clean(name):
    var = os.environ.get(name, None)
    if var:
        return var
    else:
        logging.error(f"Env variable {name} not found")

BASE_URL = clean('baseUrl')
EPIC_PROVIDER_CLIENT_ID = clean('provider_client_id')
EPIC_PATIENT_CLIENT_ID = clean('patient_client_id')
SERVICE_CLIENT_ID = clean('service_client_id')
EPIC_PATIENT_SECRET = clean('epic_patient_secret')
DATABASE_URL = clean('DATABASE_URL')