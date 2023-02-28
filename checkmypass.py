import hashlib
import requests
import sys

def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}, check the API and try again.')
    return res

# query_char to call the function with (make it dynamic)
# Raise runtime error if not 200; if not return res (response)
# request_api_data funct --> Supposed to get a response number

def get_password_leak_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0

# hash = hash PWs in response to 1st 5 characters (the response: these are already tailed)
# -> doesn't have first 5 char
# hash to check = the TAIL: our pw that we have to check
# Use hash to check to loop thru all hashes
# tuple comprehension = line.split(':') = split everything in the line from the ':'
# ->for each line -> Remove ':'
# splitlines() = returns a list in the line as a string (so it's not broken into individual elements)
# -> or else for loop runs it individually
# h = each tailed hash pw within hashes (list of pw based on 1st 5 char)
# count = # of times hacked
# for h, count --> each item (hashed pw and # of times hacked are separated)
# if h (found hashed pw) matches hash_to_check(our pw) -> return count, if not return 0


def pwned_api_check(password):
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)
    return get_password_leak_count(response, tail)

# haslib.sha1 wraps password.encode(utf-8) in a hash -> Object location
# Hexdigest - returns string object of double length, containing only hexadecimal digits
# -> converts hash object location into actual sha1 hash
# pwned_api_check -> converts pw to hash
# + calls get_pw_leak_count (returns response as txt (Hashed pw:count - how many times it got pwned))
# + calls request_api_data (checks response (if >5 characters -> 400+ status code))
# also breaking into hash bc it's more secure to check

def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'{password} was found {count} times.. you should probably change your password')
        else:
            print(f'{password} was NOT hacked, carry on!')
    return 'done'

# print out all the results of every calculation
# main receives all the arguments that we give it in command line
# args = can give it multiple pws
# loop thru passwords from args we give

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
# only run if this is the __main__ file
# sys.exit = exits file in case terminal doesn't exit, and brings user back to command line
# --> exiting out of the file -> Return done (for security reasons)

# [1:] -> accept any number of arguments when checking python3 checkmypass.py (add pw)


