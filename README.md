Setup instructions:

1. Ensure Postgres and pgsql are installed on your machine and the service is running
(I used pg 17+. This step is option but requires indicated changes to the code)

2. Create a database in Postgres called smart-on-fhir-app

3. Create and activate a Python virtual environment:

   On macOS/Linux:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```
   On Windows:
   ```cmd
   python -m venv venv
   venv\Scripts\activate
   ```

4. Create a .env file in the root and setup the env variables below

5. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

6. Run database migrations to set up the tables:
   ```bash
   flask db upgrade
   ```

7. Run the flask app


This app has a private key hardcoded for the server-side launch. You can replace that however you'd like or use it. Included is the corresponding public key that can be associated with your app's client_id on the EHR webpage (e.g. fhir.epic.com)

environment variables:
baseUrl=http://127.0.0.1:5000
epic_provider_secret=<can be null if not using>
epic_patient_secret=<can be null if not using>
flask_secret=abc123
service_client_id=<can be null if not using>
provider_client_id=<can be null if not using>
patient_client_id=<can be null if not using>
DATABASE_URL=postgresql://<username, usually postgres>:<password>@localhost:5432/smart-on-fhir-app