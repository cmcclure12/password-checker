# check from lesson 231
import requests
import hashlib  # what we gonna use to convert password to sha1
import sys


# query_char will be the hashed  version of our password
def request_api_data(query_char):
    # second parameter is the hashed password we checking
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    response = requests.get(url)
    if response.status_code != 200:
        raise RuntimeError(
            f'Error fetching: {response.status_code}, check the API and try again.')
    return response


# hash_to_check is our password we are checking
def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:  # h is the tail of the hash
        if h == hash_to_check:  # hash_to_check is the tail end of hashed password on our machine and havent sent to anyone
            return count
    return 0


# will give our actual password here and check if exists in api
def pwned_api_check(password):
    # is converting pass to sha1. check documentation
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    # to get the first 5 characters and the rest
    first5_char, tail = sha1password[:5], sha1password[5:]
    res = request_api_data(first5_char)
    return get_password_leaks_count(res, tail)


def main(args):  # is how we going to give the arguments in our command prompt
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(
                f'{password} was found {count} times... you should change your password')
        else:
            print(f'{password} was not found. Your password is secure')


if __name__ == '__main__':
    main(sys.argv[1:])
