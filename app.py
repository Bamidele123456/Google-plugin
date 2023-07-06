import os
import flask
import requests
import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery
import datetime

# This variable specifies the name of a file that contains the OAuth 2.0
# information for this application, including its client_id and client_secret.
CLIENT_SECRETS_FILE = "client_secret.json"

# This OAuth 2.0 access scope allows for full read access to the user's calendar events.
SCOPES = ['https://www.googleapis.com/auth/calendar.readonly']
API_SERVICE_NAME = 'Calendar'
API_VERSION = 'v3'

app = flask.Flask(__name__)
# Note: A secret key is included in the sample so that it works.
# If you use this code in your application, replace this with a truly secret
# key. See https://flask.palletsprojects.com/quickstart/#sessions.
app.secret_key = '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'


def get_free_times(events):
    """Calculates free time intervals between events."""
    free_times = []

    # Sort events based on start time
    sorted_events = sorted(events, key=lambda event: event['start'].get('dateTime', event['start'].get('date')))

    # Calculate free time intervals between events
    for i in range(len(sorted_events) - 1):
        end_time = sorted_events[i]['end'].get('dateTime', sorted_events[i]['end'].get('date'))
        start_time_next = sorted_events[i + 1]['start'].get('dateTime', sorted_events[i + 1]['start'].get('date'))

        free_times.append((end_time, start_time_next))

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
    body = f"http://8080/authorize/{authorized_email}"
    url = f"{app_script_link}?email={authorized_email}&message={body}&subject={subject}"

    payload = {}
    headers = {}

    response = requests.request("GET", url, headers=headers, data=payload)

    print(response.text)
# authorized_email = 'orikubamidele@gmail.com'
# send_email("Code Started Running", authorized_email)


@app.route('/')
def index():
    return print_index_table()


@app.route('/test')
def test_api_request():
    if 'credentials' not in flask.session:
        return flask.redirect('authorize')

    # Load credentials from the session.
    credentials = google.oauth2.credentials.Credentials(
        **flask.session['credentials'])

    service = googleapiclient.discovery.build(
        API_SERVICE_NAME, API_VERSION, credentials=credentials)

    # Call the Calendar API to retrieve the events.
    events_result = service.events().list(calendarId='primary', timeMin='2023-05-28T12:00:00Z', timeMax='2023-05-28T23:59:59Z', singleEvents=True).execute()
    events = events_result.get('items', [])

    # Save credentials back to session in case access token was refreshed.
    flask.session['credentials'] = credentials_to_dict(credentials)

    # Calculate free times
    free_times = get_free_times(events)

    # Generate free times if no events are found
    if not free_times:
        free_times = generate_free_times(datetime.datetime(2023, 6, 14), datetime.datetime(2023, 6, 14, 23, 59, 59), 3)

    # Prepare the free time data to be returned
    free_times_list = []
    for i, free_time in enumerate(free_times, start=1):
        free_time_data = {
            'id': i,
            'start_time': str(free_time[0]),
            'end_time': str(free_time[1])
        }
        free_times_list.append(free_time_data)

    return flask.jsonify(free_times=free_times_list)


@app.route('/authorize/<gmail>')
def authorize(gmail):
    # Store the Gmail address in the session
    flask.session['gmail'] = gmail

    # Generate the token file name based on the email
    token_file = os.path.join(os.getcwd(), 'tokens', f'{gmail}.json')

    if not os.path.isfile(token_file):
        send_email("Token File Not Found")

    # Create flow instance to manage the OAuth 2.0 Authorization Grant Flow steps.
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES)

    # The URI created here must exactly match one of the authorized redirect URIs
    # for the OAuth 2.0 client, which you configured in the API Console. If this
    # value doesn't match an authorized URI, you will get a 'redirect_uri_mismatch'
    # error.
    flow.redirect_uri = 'https://41c2-102-89-33-154.ngrok-free.app/oauth2callback'

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
    state = flask.session['state']

    # Retrieve the stored Gmail address from the session
    gmail = flask.session.get('gmail')

    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES, state=state)
    flow.redirect_uri = 'https://41c2-102-89-33-154.ngrok-free.app/oauth2callback'

    # Use the authorization server's response to fetch the OAuth 2.0 tokens.
    authorization_response = flask.request.url
    flow.fetch_token(authorization_response=authorization_response)

    # Generate the token file name based on the email
    token_file = os.path.join(os.getcwd(), 'tokens', f'{gmail}.json')

    # Create the 'tokens' directory if it doesn't exist
    os.makedirs(os.path.join(os.getcwd(), 'tokens'), exist_ok=True)

    # Save the credentials to the token file
    credentials = flow.credentials
    if credentials and token_file:
        with open(token_file, 'w') as token_file:
            token_file.write(credentials.to_json())

    # Store credentials in the session.
    flask.session['credentials'] = credentials_to_dict(credentials)

    return flask.redirect(flask.url_for('test_api_request'))


@app.route('/revoke')
def revoke():
    if 'credentials' not in flask.session:
        return ('You need to <a href="/authorize">authorize</a> before ' +
                'testing the code to revoke credentials.')

    credentials = google.oauth2.credentials.Credentials(
        **flask.session['credentials'])

    revoke = requests.post('https://oauth2.googleapis.com/revoke',
                           params={'token': credentials.token},
                           headers={'content-type': 'application/x-www-form-urlencoded'})

    status_code = getattr(revoke, 'status_code')
    if status_code == 200:
        return 'Credentials successfully revoked.' + print_index_table()
    else:
        return 'An error occurred.' + print_index_table()


@app.route('/clear')
def clear_credentials():
    if 'credentials' in flask.session:
        del flask.session['credentials']
    return 'Credentials have been cleared.' + print_index_table()


def credentials_to_dict(credentials):
    return {'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes}


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
