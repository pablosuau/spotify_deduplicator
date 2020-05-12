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

if __name__ == "__main__":
    args = _read_arguments()
    
    r = json.loads(requests.get('https://api.spotify.com/v1/users/' + args['username'] + '/playlists?limit=50',
                                headers = {'Content-Type': 'application/json', 
                                           'Authorization': 'Bearer ' + args['oauth']}).text)
    
    _validate_input_data(r)
    