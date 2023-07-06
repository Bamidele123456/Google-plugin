# import os.path
# import requests
# import datetime
# from google_auth_oauthlib.flow import InstalledAppFlow
# from google.auth.transport.requests import Request
# from googleapiclient.discovery import build
# from google.oauth2.credentials import Credentials
# from requests.structures import CaseInsensitiveDict
# import json
#
# combined_calendar_data = []
# SCOPES = [
#     'https://www.googleapis.com/auth/calendar.readonly',
# ]
#
# def main():
#     creds = None
#     if os.path.exists('token.json'):
#         creds = Credentials.from_authorized_user_file('token.json', SCOPES)
#         if not creds or not creds.valid:
#             if creds and creds.expired and creds.refresh_token:
#                 creds.refresh(Request())
#             else:
#                 # If credentials file doesn't exist or is invalid, start the OAuth flow to authorize the application
#                 flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
#                 creds = flow.run_local_server(port=0)
#             # Save the credentials to a file for future use
#             with open('token.json', 'w') as token:
#                 token.write(creds.to_json())
#
# if __name__ == '__main__':
#     main()
#
