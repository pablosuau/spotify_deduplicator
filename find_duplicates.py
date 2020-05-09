import requests

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

if __name__ == "__main__":
    args = _read_arguments()
    
    r = requests.get('https://api.spotify.com/v1/users/' + args['username'] + '/playlists?limit=50',
                     headers = {'Content-Type': 'application/json', 
                                'Authorization': 'Bearer ' + args['oauth']})
    print(r.text)