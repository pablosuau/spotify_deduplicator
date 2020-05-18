import requests
import json

CONFIG = 'config.json'
SCOPES = ['playlist-read-private', 'playlist-read-collaborative']

def _read_config():
    '''
    Read Configuration file

    Returns:
        - a dictionary containing the configuration data
    '''
    with open(CONFIG, 'r') as f:
        args = json.load(f)

    return args

def _request_token(args):
    '''
    Client credentials flow. Gets an access token and stores it as part 
    of the input arguments dictionary

    Parameters:
        - args: the input arguments dictionary containing the configuration values
    '''
    # I cannot set the scope with client credentials - I need the user permission
    body_params = {'grant_type': 'client_credentials', 'scope': ' '.join(SCOPES)}
    r = requests.post('https://accounts.spotify.com/api/token', 
                      data = body_params, 
                      auth = (args['client_id'], args['client_secret'])) 

    args['oauth'] = json.loads(r.text)['access_token']

def _playlists_query(url, oauth):
    '''
    Queries Spotify's API

    Parameters:
        - url (str): the API endpoint
        - oauth (str): the oauth token
    '''
    return json.loads(requests.get(url,
                                   headers = {'Content-Type': 'application/json', 
                                              'Authorization': 'Bearer ' + oauth}).text)

def _validate_input_data(r):
    '''
    Validates input data by looking at the API query response

    Parameters:
        - r (dict): API query response
    '''
    if 'error' in r.keys():
        if r['error']['status'] == 404:
            raise ValueError('User not found')
        else:
            raise ValueError('Invalid oauth token')

    if len(r['items']) == 0:
        raise(ValueError('The selected user has not created any playlist'))

def _pull_playlists(r, oauth):
    '''
    Pulls the complete list of playlists by looking at the first API query response

    Parameters:
        - r (dict): API query response
        - oauth (str): the oauth token
    Returns:
        - A list with the playlist names
    '''
    def _read_page(page):
        return [r['items'][i]['name'] for i in range(len(r['items']))]
    playlists = _read_page(r)
    while r['next'] is not None:
        r = _playlists_query(r['next'], oauth)
        playlists.extend(_read_page(r))

    print(str(len(playlists)) + ' playlists pulled...')

    return playlists

if __name__ == "__main__":
    args = _read_config()

    _request_token(args)

    
    # The maxmimum value for limit seems to be 50
    r = _playlists_query('https://api.spotify.com/v1/users/' + args['username'] + '/playlists?limit=50', 
                   args['oauth'])
    
    _validate_input_data(r)

    playlists = _pull_playlists(r, args['oauth'])