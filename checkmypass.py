import hashlib #sha1 password hashing
import requests
import sys

# check password against API
def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}, check the API and try again.')
    return res

# obtain number of password leaks
def get_password_leak_count(hashes, hash_to_check):
    
    #tuple comprehension = line.split(':') = split everything in the line from the ':'
    hashes = (line.split(':') for line in hashes.text.splitlines())
    
    # iterate through h (tail end of hashed pw in API database)
    for h, count in hashes:
        
        # if h matches user input tail end hashed pw -> return count
        if h == hash_to_check:
            return count
    
    # return 0 if no password breaches
    return 0


# securely check password by converting to has object
def pwned_api_check(password):

    # split first 5 characters, and tail (rest of hash)
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]

    # Check first 5 characters of hashed pw against API; return response and hashed tail
    response = request_api_data(first5_char)
    return get_password_leak_count(response, tail)


# main receives all the arguments (1 or more passwords) at command line
def main(args):
    
    #iterate through API with args (passwords)
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'{password} was found {count} times.. you should probably change your password')
        else:
            print(f'{password} was NOT hacked, carry on!')
    
    # return when action is completed
    return 'done'


# run if __main__; exit file in case terminal doesn't exit, and brings user back to command line
# [1:] -> accept any number of arguments when checking python3 checkmypass.py (add pw)
if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))

