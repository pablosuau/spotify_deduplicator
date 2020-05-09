import sys
import argparse
import json

def _parse_arguments():
    '''
    Parse the input arguments

    Returns:
        - a parameters object
    '''
    parser = argparse.ArgumentParser()

    parser.add_argument('--input', help = 'input json playlists json file')

    args = parser.parse_args()

    return args

if __name__ == "__main__":
    args = _parse_arguments()