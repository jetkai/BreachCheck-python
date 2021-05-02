import requests
import sys
import hashlib

password = ""  # CHANGE ME
hash_type = "SHA-1"  # MD5, SHA-1, SHA-256, SHA-512 & PLAIN-TEXT
using_https = True  # //True = HTTPS, False = HTTP

api_url = "api.rsps.tools/jetkai/breachcheck"  # DO NOT CHANGE
token = "39439e74fa27c09a4"  # DO NOT CHANGE

returned_json = ""  # Data that is returned from the api


# /**
#  * Sends HTTP Request to return data
#  * @return The data from HTTP Request and checks if it contains "breached":true
#  */
def is_breached(password, hash_type, using_https, token, api_url):
    connect(password, hash_type, using_https, token, api_url)
    return '"breached":true' in returned_json


# /**
#  * Sends HTTP Request to the API, setting the returned_json string with returned JSON data
#  * HTTP is ~2x faster than HTTPS
#  *
#  * URL Request Example:
#  * https://api.rsps.tools/jetkai/breachcheck?token=39439e74fa27c09a4&hash=ed8779a2222dc578f2cffbf308411b41381a94ef25801f9dfbe04746ea0944cd
#  *
#  * Returned JSON Data Example:
#  * {
#  * 	"token": "39439e74fa27c09a4",
#  * 	"hash": "ed8779a2222dc578f2cffbf308411b41381a94ef25801f9dfbe04746ea0944cd",
#  * 	"hashPos": 2,
#  * 	"severity": "Top 100 Common Passwords",
#  * 	"databaseBreach": "Stoned 2021 ~800K Unique Passwords (15+ RSPS Databases)",
#  * 	"hash_type": "SHA-256",
#  * 	"breached": true
#  * }
#  */

def connect(password, hash_type, using_https, token, api_url):
    global returned_json
    protocol = "https://" if using_https else "http://"
    request_url = protocol + api_url + "?token=" + token + "&" + get_hash_or_password(hash_type) + "=" + get_hashed_password(password, hash_type)
    returned_json = requests.get(request_url).text


# /**
#  * Hex's the plain-text password, either using:
#  * MD5, SHA-1, SHA256, SHA-512
#  * @return The hexed password, fallsback to plain-text if an incorrect hash_type is set
#  */
def get_hashed_password(password, hash_type):
    password = password.encode("utf-8")
    hash_type = hash_type.upper()
    if hash_type == "MD5":
        return hashlib.md5(password).hexdigest()
    elif hash_type == "SHA-1":
        return hashlib.sha1(password).hexdigest()
    elif hash_type == "SHA-256":
        return hashlib.sha256(password).hexdigest()
    elif hash_type == "SHA-512":
        return hashlib.sha512(password).hexdigest()
    return password.decode("utf-8")


# /**
#  * This is checking the hash_type and returning as string
#  * @return Either "hash" or "password", depending if the password is plain-text or hexed
#  */
def get_hash_or_password(hash_type):
    hash_types = ["MD5", "SHA-1", "SHA-256", "SHA-512"]
    return "hash" if hash_type.upper() in hash_types else "password"


# /**
# * Checks Fields
# * @return The string output if the password /or token field is null/empty
# */
def check_fields(password, token):
    if password is None or password == "":
        return "Password field can't be empty"
    elif token is None or token == "":
        return "Token field can't be empty"
    return ""


# This is an example of how you can call the methods for checking if your password is breached
def init_example():
    global password, hash_type, using_https, token, api_url, returned_json
    return_field = check_fields(password, token)
    if len(return_field) > 0:
        return print(return_field)

    breached = is_breached(password, hash_type, using_https, token, api_url)
    has_returned_json = len(returned_json) > 0
    if breached and has_returned_json:
        print("You have been breached : " + returned_json)
    elif not breached and has_returned_json:
        print("You have not been breached : " + returned_json)


# /**
#  * Main function (if running from IDE or shell for testing)
#  * @param argv - Can parse password as sys.argv[1] and hash_type as sys.argv[2]
#  */
def main():
    global password, hash_type, using_https, token, api_url
    if len(sys.argv) > 1:
        password = sys.argv[1]
    if len(sys.argv) > 2:
        hash_type = sys.argv[2]
    if len(sys.argv) > 3:
        using_https = sys.argv[3].lower() == 'true'
    init_example()


# Calls main()
if __name__ == "__main__":
    main()
