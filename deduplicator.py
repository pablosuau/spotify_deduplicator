''' 
Windows:
set FLASK_APP=oauth.py
flask -m flask run
'''

from flask import (
    abort,
    Flask,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
import json
import logging
import os
import requests
import secrets
import string
from urllib.parse import urlencode

logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s', 
                    level=logging.DEBUG)

# Client info
with open('config.json', 'r') as f:
    config = json.load(f)
CLIENT_ID = config['client_id']
CLIENT_SECRET = config['client_secret']
SECRET_KEY = config['secret_key']
REDIRECT_URI = 'http://127.0.0.1:5000/callback'

# Spotify API endpoints
AUTH_URL = 'https://accounts.spotify.com/authorize'
TOKEN_URL = 'https://accounts.spotify.com/api/token'
ME_URL = 'https://api.spotify.com/v1/me'
PLAYLISTS_URL = 'https://api.spotify.com/v1/users/{USER_ID}/playlists?limit=50'

# Start Flask up
app = Flask(__name__)
app.secret_key = SECRET_KEY
# These three configuration parameters are required if the app is going to be served
# from a server which domain name is an ip. Otherwise, cookies will not be stored
# by Chrome.
app.config['SERVER_NAME'] = '127.0.0.1:5000'
app.config['SESSION_COOKIE_NAME'] = '127.0.0.1:5000'
app.config['SESSION_COOKIE_DOMAIN'] = '127.0.0.1:5000'

@app.route('/')
def index():
    '''
    Initial endpoint.
    '''
    return render_template('index.html')

@app.route('/<loginout>')
def login(loginout):
    '''
    Login or logout user. Login and logout process are essentially the same. Logout 
    forces re-login to appear, even if their token hasn't expired.
    '''
    # redirect_uri can be guessed, so let's generate
    # a random `state` string to prevent csrf forgery.
    state = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(16))

    # Request authorization from user
    scope = 'playlist-read-private playlist-read-collaborative'

    if loginout == 'logout':
        payload = {
            'client_id': CLIENT_ID,
            'response_type': 'code',
            'redirect_uri': REDIRECT_URI,
            'state': state,
            'scope': scope,
            'show_dialog': True,
        }
    elif loginout == 'login':
        payload = {
            'client_id': CLIENT_ID,
            'response_type': 'code',
            'redirect_uri': REDIRECT_URI,
            'state': state,
            'scope': scope,
        }
    else:
        abort(404)

    res = make_response(redirect(f'{AUTH_URL}/?{urlencode(payload)}'))
    res.set_cookie('spotify_auth_state', state)

    return res

@app.route('/callback')
def callback():
    '''
    Deals with Spotify's answer
    '''
    error = request.args.get('error')
    code = request.args.get('code')
    state = request.args.get('state')
    stored_state = request.cookies.get('spotify_auth_state')

    # Check state
    if state is None or state != stored_state:
        app.logger.error('Error message: %s', repr(error))
        app.logger.error('State mismatch: %s != %s', stored_state, state)
        abort(400)

    # Request tokens with the code we obtained
    payload = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': REDIRECT_URI,
    }

    # `auth=(CLIENT_ID, SECRET)` basically wraps an 'Authorization'
    # header with value:
    # b'Basic ' + b64encode((CLIENT_ID + ':' + SECRET).encode())
    res = requests.post(TOKEN_URL, 
                        auth = (CLIENT_ID, CLIENT_SECRET), 
                        data = payload)
    res_data = res.json()

    if res_data.get('error') or res.status_code != 200:
        app.logger.error('Failed to receive token: %s',
                         res_data.get('error', 'No error information received.'))
        abort(res.status_code)

    # Load tokens into session
    session['tokens'] = {
        'access_token': res_data.get('access_token'),
        'refresh_token': res_data.get('refresh_token'),
    }

    return redirect(url_for('playlists'))

@app.route('/refresh')
def refresh():
    '''
    Refresh access token
    '''

    payload = {
        'grant_type': 'refresh_token',
        'refresh_token': session.get('tokens').get('refresh_token'),
    }
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}

    res = requests.post(TOKEN_URL, 
                        auth = (CLIENT_ID, CLIENT_SECRET), 
                        data = payload, 
                        headers = headers)
    res_data = res.json()

    # Load new token into session
    session['tokens']['access_token'] = res_data.get('access_token')

    return json.dumps(session['tokens'])

def _pull_playlists(user_id):
    '''
    Pulls the complete list of playlists by looking at the first API query response

    Parameters:
        - user_id: user's id

    Returns:
        - A list with the playlist names
    '''
    def _read_page(res_data):
        return [res_data['items'][i]['name'] for i in range(len(res_data['items']))]
    headers = {'Authorization': f"Bearer {session['tokens'].get('access_token')}"}
    res = requests.get(PLAYLISTS_URL.replace('{USER_ID}', user_id), headers = headers)
    res_data = res.json()
    playlists = _read_page(res_data)
    while res_data['next'] is not None:
        res = requests.get(res_data['next'], headers = headers)
        res_data = res.json()
        playlists.extend(_read_page(res_data))

    print(str(len(playlists)) + ' playlists pulled...')

    return playlists

@app.route('/playlists')
def playlists():
    '''
    Pulls user's playlists and displays duplicated playlists
    '''

    # Check for tokens
    if 'tokens' not in session:
        app.logger.error('No tokens in session.')
        abort(400)

    # Get profile info
    headers = {'Authorization': f"Bearer {session['tokens'].get('access_token')}"}
    res = requests.get(ME_URL, headers = headers)
    res_data = res.json()
 
    playlists = _pull_playlists(res_data['id'])

    if res.status_code != 200:
        app.logger.error(
            'Failed to get profile info: %s',
            res_data.get('error', 'No error message returned.'),
        )
        abort(res.status_code)

    return render_template('playlists.html', data = playlists, tokens = session.get('tokens'))