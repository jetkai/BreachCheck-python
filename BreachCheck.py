import requests
import sys
import hashlib

password = ""  # CHANGE ME
hashType = "SHA-1"  # MD5, SHA-1, SHA-256, SHA-512 & PLAIN-TEXT
usingHttps = True  # //True = HTTPS, False = HTTP

apiUrl = "api.rsps.tools/jetkai/breachcheck"  # DO NOT CHANGE
token = "39439e74fa27c09a4"  # DO NOT CHANGE

returnedJson = ""  # Data that is returned from the api


# /**
#  * Sends HTTP Request to return data
#  * @return The data from HTTP Request and checks if it contains "breached":true
#  */
def isBreached(password, hashType, usingHttps, token, apiUrl):
    connect(password, hashType, usingHttps, token, apiUrl)
    return "\"breached\":true" in returnedJson


# /**
#  * Sends HTTP Request to the API, setting the returnedJson string with returned JSON data
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
#  * 	"hashType": "SHA-256",
#  * 	"breached": true
#  * }
#  */

def connect(password, hashType, usingHttps, token, apiUrl):
    global returnedJson
    requestUrl = getProtocol(usingHttps) + apiUrl + "?token=" + token + "&" + getHashOrPassword(
        hashType) + "=" + getHashedPassword(password, hashType)

    returnedJson = requests.get(requestUrl).text


# /**
#  * Hex's the plain-text password, either using:
#  * MD5, SHA-1, SHA256
#  * @return The hexed password, fallsback to plain-text if an incorrect hashType is set
#  */
def getHashedPassword(password, hashType):
    password = password.encode("utf-8")
    hashType = hashType.upper()
    if hashType == "MD5":
        return hashlib.md5(password).hexdigest()
    elif hashType == "SHA-1":
        return hashlib.sha1(password).hexdigest()
    elif hashType == "SHA-256":
        return hashlib.sha256(password).hexdigest()
    elif hashType == "SHA-512":
        return hashlib.sha512(password).hexdigest()
    return password.decode("utf-8")


# /**
#  * This is checking the hashType and returning as string
#  * @return Either "hash" or "password", depending if the password is plain-text or hexed
#  */
def getHashOrPassword(hashType):
    hashTypes = ["MD5", "SHA-1", "SHA-256", "SHA-512"]
    if hashType.upper() in hashTypes:
        return "hash"
    return "password"


# Returns protocol that is requested, http is faster than https but less secure
def getProtocol(isUsingHttps):
    if isUsingHttps:
        return "https://"
    return "http://"


# /**
# * Checks Fields
# * @return The string output if the password /or token field is null/empty
# */
def checkFields(password, token):
    if password is None or password == "":
        return "Password field can't be empty"
    elif token is None or token == "":
        return "Token field can't be empty"
    return ""


# This is an example of how you can call the methods for checking if your password is breached
def initExample():
    global password, hashType, usingHttps, token, apiUrl, returnedJson
    returnField = checkFields(password, token)
    if len(returnField) > 0:
        return print(returnField)

    breached = isBreached(password, hashType, usingHttps, token, apiUrl)
    hasReturnedJson = len(returnedJson) > 0
    if breached and hasReturnedJson:
        print("You have been breached : " + returnedJson)
    elif not breached and hasReturnedJson:
        print("You have not been breached : " + returnedJson)


# /**
#  * Main function (if running from IDE or shell for testing)
#  * @param argv - Can parse password as sys.argv[1] and hashType as sys.argv[2]
#  */
def main():
    global password, hashType, usingHttps, token, apiUrl
    if len(sys.argv) > 1:
        password = sys.argv[1]
    if len(sys.argv) > 2:
        hashType = sys.argv[2]
    if len(sys.argv) > 3:
        usingHttps = sys.argv[3].lower() == 'true'
    initExample()

# Calls main()
if __name__ == "__main__":
    main()
