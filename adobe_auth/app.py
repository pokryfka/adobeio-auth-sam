import logging
import json
import requests
import urllib.parse
from typing import Optional
from os import getenv

ADOBE_API_KEY = getenv("ADOBE_API_KEY")
ADOBE_API_SECRET = getenv("ADOBE_API_SECRET")
LOG_LEVEL = getenv("LOG_LEVEL", "INFO")

logger = logging.getLogger("adobe-auth")
logger.setLevel(LOG_LEVEL)


def lambda_handler(event, context) -> dict:
    logger.debug(f"{json.dumps(event, indent=4)}")
    try:
        path = event["rawPath"]
        if path.endswith("authorize"):
            logger.info("Authorizing")
            host = event["requestContext"]["domainName"]
            path = event["requestContext"]["http"]["path"]
            redirect_uri = f"https://{host}{path}/callback"
            return authorize(redirect_uri)
        elif path.endswith("authorize/callback"):
            logger.info("Authenticating")
            try:
                code = event["queryStringParameters"]["code"]
            except KeyError:
                return {"statusCode": 400}
            return token("authorization_code", code=code)
        elif path.endswith("token"):
            logger.info("Refreshing token")
            try:
                refresh_token = event["queryStringParameters"]["refresh_token"]
            except KeyError:
                return {"statusCode": 400}
            return token("refresh_token", refresh_token=refresh_token)
        else:
            logger.warning(f"Invalid path: {path}")
            return {"statusCode": 404}
    except Exception as e:
        logger.error(f"{e}")
        return {"statusCode": 500}


def authorize(redirect_uri: str) -> dict:
    # Adobe OAuth2.0 authorization url
    authorization_url = "https://ims-na1.adobelogin.com/ims/authorize?"

    # Store required parameters in a dictionary
    params = {
        "client_id": ADOBE_API_KEY,
        "scope": "openid,lr_partner_apis",
        "response_type": "code",
        "redirect_uri": redirect_uri,
    }
    logger.debug(f"{json.dumps(params, indent=4)}")

    return {
        "statusCode": 302,
        "headers": {"Location": authorization_url + urllib.parse.urlencode(params)},
    }


def token(
    grant_type: str, code: Optional[str] = None, refresh_token: Optional[str] = None
) -> dict:
    # Adobe OAuth2.0 token url
    token_url = "https://ims-na1.adobelogin.com/ims/token"

    # Store required parameters in a dictionary
    # And include the authorization code in it
    params = {
        "grant_type": grant_type,
        "client_id": ADOBE_API_KEY,
        "client_secret": f"{ADOBE_API_SECRET}",
    }
    if code:
        params["code"] = code
    if refresh_token:
        params["refresh_token"] = refresh_token
    logger.debug(f"{json.dumps(params, indent=4)}")

    # Use requests library to send the POST request
    response = requests.post(
        token_url,
        params=params,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )

    return {
        "statusCode": response.status_code,
        "body": json.dumps(response.json(), indent=4),
        "headers": {"Content-Type": "application/json"},
    }
