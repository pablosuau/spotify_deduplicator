import requests
import json

def _read_arguments():
    '''
    Read input arguments

    Returns:
        - a dictionary containing the username and the oauth key
    '''
    args = {}
    args['username'] = input('Spotify username: ')
    args['oauth'] = input('Oauth key: ')

    return args

def _query_api(url, oauth):
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
        r = _query_api(r['next'], oauth)
        playlists.extend(_read_page(r))

    print(str(len(playlists)) + ' playlists pulled...')

    return playlists

if __name__ == "__main__":
    args = _read_arguments()
    
    # The maxmimum value for limit seems to be 50
    r = _query_api('https://api.spotify.com/v1/users/' + args['username'] + '/playlists?limit=50', 
                   args['oauth'])
    
    _validate_input_data(r)

    playlists = _pull_playlists(r, args['oauth'])
    