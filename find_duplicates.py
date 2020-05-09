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
    print(args)