import os
import flask
import requests
import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery
from google.auth.transport.requests import Request
from google.auth.exceptions import RefreshError
from google.oauth2.credentials import Credentials
# from datetime import datetime
import datetime
from google_auth_oauthlib.flow import Flow

import json
from pymongo import MongoClient
import time
import threading

# This variable specifies the name of a file that contains the OAuth 2.0
# information for this application, including its client_id and client_secret.
CLIENT_SECRETS_FILE = "client_secret.json"

# This OAuth 2.0 access scope allows for full read access to the user's calendar events.
SCOPES = ['https://www.googleapis.com/auth/calendar.readonly']
API_SERVICE_NAME = 'calendar'
API_VERSION = 'v3'

app = flask.Flask(__name__)
# Note: A secret key is included in the sample so that it works.
# If you use this code in your application, replace this with a truly secret
# key. See https://flask.palletsprojects.com/quickstart/#sessions.
app.secret_key = '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'

# Connect to MongoDB
mongo_uri = 'mongodb+srv://Eyal:1631324de@cluster0.t1ysqxz.mongodb.net/?retryWrites=true&w=majority'
client = MongoClient(mongo_uri)
db = client['Cluster0']

# def get_credentials(gmail):
#     """Fetches the OAuth 2.0 credentials for the specified Gmail from the database."""
#     collection_name = f'{gmail}_tokens'
#     collection = db[collection_name]
#     credentials_data = collection.find_one({'_id': 1})
#     if credentials_data:
#         return google.oauth2.credentials.Credentials(**credentials_data['credentials'])
#     return None

# pending_authorizations = []

# def poll_server():
#     """Polls the server every 30 seconds to check for authorized emails and process tokens."""
#     with app.app_context():
#         while True:
#             for gmail in pending_authorizations:
#                 # Retrieve the token for the email from the database
#                 collection_name = f'{gmail}_tokens'
#                 collection = db[collection_name]
#                 token = collection.find_one({'_id': 1})['credentials']['token']
#
#                 if token:
#                     # Use the token to process and print free times
#                     with app.test_request_context():
#                         flask.redirect(flask.url_for('test_api_request'))
#
#                     # Delete the email from the pending authorizations list
#                     pending_authorizations.remove(gmail)
#
#             # Pause for 30 seconds before the next poll
#             time.sleep(3

def get_free_times(events):
    """Calculates free time intervals between events."""
    free_times = []

    # Sort events based on start time
    sorted_events = sorted(events, key=lambda event: event['start'].get('dateTime', event['start'].get('date')))

    # Calculate free time intervals between events
    for i in range(len(sorted_events) - 1):
        end_time = sorted_events[i]['end'].get('dateTime', sorted_events[i]['end'].get('date'))
        start_time_next = sorted_events[i + 1]['start'].get('dateTime', sorted_events[i + 1]['start'].get('date'))

        free_times.append((datetime.datetime.fromisoformat(end_time), datetime.datetime.fromisoformat(start_time_next)))

    return free_times


def generate_free_times(start_time, end_time, count):
    """Generates a specified number of free time intervals for a given day with a 30-minute interval."""
    total_duration = (end_time - start_time).total_seconds()
    duration_per_interval = total_duration / (count + 1)

    # Convert the duration to 30 minutes (1800 seconds)
    duration_per_interval = min(duration_per_interval, 1800)

    free_times = []
    current_time = start_time

    for _ in range(count):
        end_time = current_time + datetime.timedelta(seconds=duration_per_interval)
        free_times.append((current_time, end_time))
        current_time = end_time

    return free_times


def send_email(subject):
    """Sends an email using an App Script API."""
    authorized_email = flask.session.get('gmail')
    if not authorized_email:
        return
    app_script_link = "https://script.google.com/macros/s/AKfycbz-BQG0U35BfaYN9J7zT79vZisXMtQi558CMdC7_KgvjV1Dr0Bqzosn30dJegJ2luOq-Q/exec"
    body = f"https://claendar-plugin-db460edae67e.herokuapp.com/authorize/{authorized_email}"
    url = f"{app_script_link}?email={authorized_email}&message={body}&subject={subject}"

    payload = {}
    headers = {}

    response = requests.request("GET", url, headers=headers, data=payload)

    print(response.text)


@app.route('/')
def index():
    return print_index_table()


@app.route('/test')
def test_api_request():
    date = flask.session.get('date')
    gmail = flask.session.get('gmail')

    collection_name = f'{gmail}_tokens'
    collection = db[collection_name]

    # Find the document that matches the query
    result = collection.find_one({})



    # Create credentials object using the retrieved token
    credentials = google.oauth2.credentials.Credentials(token=result['credentials']['token'])

    service = googleapiclient.discovery.build(
        API_SERVICE_NAME, API_VERSION, credentials=credentials)

    # Call the Calendar API to retrieve the events.
    events_result = service.events().list(calendarId='primary', timeMin=f'{date}T12:00:00Z',
                                          timeMax=f'{date}T23:59:59Z', singleEvents=True).execute()
    events = events_result.get('items', [])

    # Calculate free times
    free_times = get_free_times(events)

    # Generate free times if no events are found
    if not free_times:
        start_time = datetime.datetime.strptime(f'{date}T12:00:00Z', '%Y-%m-%dT%H:%M:%SZ')
        end_time = datetime.datetime.strptime(f'{date}T23:59:59Z', '%Y-%m-%dT%H:%M:%SZ')
        free_times = generate_free_times(start_time, end_time, 3)

    # Prepare the free time data to be returned
    free_times_list = []

    for i, free_time in enumerate(free_times, start=1):
        free_time_data = {"text": free_time[0].strftime('%H:%M:%S')}
        free_times_list.append(free_time_data)

    fulfillment = {
        "fulfillmentMessages": [
            {
                "text": {
                    "text": [
                        "free times"
                    ]
                }
            },
            {
                "payload": {
                    "richContent": [
                        [
                            {
                                "type": "chips",
                                "options": free_times_list
                            }
                        ]
                    ]
                }
            }
        ]
    }

    return fulfillment


# ... (previous code remains unchanged) ...

@app.route('/calendar/<gmail>')
def calendar(gmail):
    # flask.session['date'] = date
    flask.session['gmail'] = gmail
    # Access the specific collection in MongoDB based on the Gmail address
    collection_name = f'{gmail}_tokens'
    collection = db[collection_name]

    # Find the document that matches the query
    result = collection.find_one({})

    # If credentials are not found, send an email to authorize it
    if not result:
        send_email('Token not found')
        return "Token not found. Authorization email sent. Please check your email and follow the instructions."

    credentials = google.oauth2.credentials.Credentials(
        token=result['credentials']['token'],
        refresh_token=result['credentials']['refresh_token'],
        token_uri=result['credentials']['token_uri'],
        client_id=result['credentials']['client_id'],
        client_secret=result['credentials']['client_secret'],
        scopes=['https://www.googleapis.com/auth/calendar.readonly']  # Update with your desired scopes
    )

    # Check if credentials are expired or not valid
    if credentials.expired or not credentials.valid:
        # If credentials have a refresh token, attempt to refresh the access token
        if credentials.refresh_token:
            try:
                credentials.refresh(Request())
                # Update the refreshed token in the database
                collection.update_one({'_id': 1},
                                      {'$set': {'credentials': json.dumps(credentials_to_dict(credentials))}})
            except RefreshError as e:
                # If the refresh fails, the token might be revoked or invalid.
                # In this case, you may want to reauthorize the user and get new tokens.
                send_email('Token refresh failed. Please reauthorize the application.')
                return "Token refresh failed. Authorization email sent. Please check your email and follow the instructions."
        else:
            # If there's no refresh token, it means the user needs to reauthorize the application
            send_email('Token expired or not valid. Please reauthorize the application.')
            return "Token expired or not valid. Authorization email sent. Please check your email and follow the instructions."

    # Use the refreshed credentials object to call the Calendar API
    service = googleapiclient.discovery.build(
        API_SERVICE_NAME, API_VERSION, credentials=credentials)

    # Convert the current date to a string in the format 'YYYY-MM-DD'
    target_date = datetime.datetime.now().strftime('%Y-%m-%d')

    # Calculate the end date (current date + 5 days)
    end_date = (datetime.datetime.now() + datetime.timedelta(days=5)).strftime('%Y-%m-%d')

    # Call the Calendar API to retrieve the events.
    events_result = service.events().list(calendarId='primary', timeMin=f'{target_date}T00:00:00Z',
                                          timeMax=f'{end_date}T23:59:59Z', singleEvents=True).execute()
    events = events_result.get('items', [])

    # Calculate free times
    free_times = get_free_times(events)

    # Generate free times if no events are found
    if not free_times:
        start_time = datetime.datetime.now().replace(hour=12, minute=0, second=0)
        end_time = (datetime.datetime.now() + datetime.timedelta(days=5)).replace(hour=23, minute=59, second=59)
        free_times = generate_free_times(start_time, end_time, 3)

    # Prepare the free time data to be returned
    free_times_list = []

    for i, free_time in enumerate(free_times, start=1):
        free_time_data = {"text": free_time[0].strftime('%Y-%m-%d %H:%M:%S')}
        free_times_list.append(free_time_data)

    fulfillment = {
        "fulfillmentMessages": [
            {
                "text": {
                    "text": [
                        "free times"
                    ]
                }
            },
            {
                "payload": {
                    "richContent": [
                        [
                            {
                                "type": "chips",
                                "options": free_times_list
                            }
                        ]
                    ]
                }
            }
        ]
    }

    return fulfillment





@app.route('/authorize/<gmail>')
def authorize(gmail):
    flask.session['gmail'] = gmail
    # pending_authorizations.append(gmail)
    # Generate the collection name based on the Gmail address
    collection_name = f'{gmail}_tokens'
    # Retrieve the MongoDB collection
    collection = db[collection_name]

    # Create flow instance to manage the OAuth 2.0 Authorization Grant Flow steps.
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES)

    # The URI created here must exactly match one of the authorized redirect URIs
    # for the OAuth 2.0 client, which you configured in the API Console. If this
    # value doesn't match an authorized URI, you will get a 'redirect_uri_mismatch'
    # error.
    flow.redirect_uri = 'https://claendar-plugin-db460edae67e.herokuapp.com/oauth2callback'




    # Set the 'login_hint' parameter to specify the Gmail account to authenticate.
    # This will pre-fill the email field on the authentication page.
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true',
        login_hint=gmail,
    )

    # Store the state so the callback can verify the auth server response.
    flask.session['state'] = state


    # Redirect the user to the authorization URL
    return flask.redirect(authorization_url)

@app.route('/oauth2callback')
def oauth2callback():
    # Specify the state when creating the flow in the callback so that it can
    # be verified in the authorization server response.


    # Retrieve the stored Gmail address from the session
    gmail = flask.session.get('gmail')
    state = flask.session.get('state')

    # Generate the collection name based on the Gmail address
    collection_name = f'{gmail}_tokens'
    # Retrieve the MongoDB collection
    collection = db[collection_name]

    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES, state=state)
    flow.redirect_uri = 'https://claendar-plugin-db460edae67e.herokuapp.com/oauth2callback'

    # Use the authorization server's response to fetch the OAuth 2.0 tokens.
    authorization_response = flask.request.url
    flow.fetch_token(authorization_response=authorization_response)

    # Save the credentials to MongoDB
    credentials = flow.credentials
    collection.update_one({'_id': 1}, {'$set': {'credentials': credentials_to_dict(credentials)}}, upsert=True)

    # Store credentials in the session.
    flask.session['credentials'] = credentials_to_dict(credentials)

    return flask.redirect(flask.url_for('test_api_request'))



@app.route('/revoke')
def revoke():
    if 'credentials' not in flask.session:
        return ('You need to <a href="/authorize">authorize</a> before ' +
                'testing the code to revoke credentials.')

    # Retrieve the stored Gmail address from the session
    gmail = flask.session.get('gmail')

    # Generate the collection name based on the Gmail address
    collection_name = f'{gmail}_tokens'
    # Retrieve the MongoDB collection
    collection = db[collection_name]

    # Delete the stored credentials from MongoDB
    collection.delete_one({'_id': 1})

    return 'Credentials successfully revoked.' + print_index_table()


@app.route('/clear')
def clear_credentials():
    if 'credentials' in flask.session:
        del flask.session['credentials']

    # Retrieve the stored Gmail address from the session
    gmail = flask.session.get('gmail')

    # Generate the collection name based on the Gmail address
    collection_name = f'{gmail}_tokens'
    # Retrieve the MongoDB collection
    collection = db[collection_name]

    # Delete the stored credentials from MongoDB
    collection.delete_one({'_id': 1})

    return 'Credentials have been cleared.' + print_index_table()


def credentials_to_dict(credentials):
    return {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }




def print_index_table():
    return (
        '<table>'
        '<tr><td><a href="/test">Test API request</a></td></tr>'
        '<tr><td><a href="/authorize">Authorize</a></td></tr>'
        '<tr><td><a href="/revoke">Revoke credentials</a></td></tr>'
        '<tr><td><a href="/clear">Clear credentials</a></td></tr>'
        '</table>'
    )

if __name__ == '__main__':
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
    app.run('localhost', 8080, debug=True)