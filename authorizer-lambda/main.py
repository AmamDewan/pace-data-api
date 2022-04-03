import os
import boto3
import json
import time
import urllib.request
from jose import jwk, jwt
from jose.utils import base64url_decode

# envs
TABLE_NAME = os.environ['TABLE_NAME']
AWS_REGION = os.environ['AWS_REGION']
COGNITO_USER_POOL_ID = os.environ['COGNITO_USER_POOL_ID']
COGNITO_APP_CLIENT_ID = os.environ['COGNITO_APP_CLIENT_ID']

keys_url = 'https://cognito-idp.{}.amazonaws.com/{}/.well-known/jwks.json'.format(AWS_REGION, COGNITO_USER_POOL_ID)
# instead of re-downloading the public keys every time
# we download them only on cold start
# https://aws.amazon.com/blogs/compute/container-reuse-in-lambda/
with urllib.request.urlopen(keys_url) as f:
    response = f.read()
keys = json.loads(response.decode('utf-8'))['keys']


def handler(event, context):
    print(event)

    token_data = parse_token_data(event)
    if token_data['valid'] is False:
        return get_deny_policy()

    try:
        claims = validate_token(token_data['token'])
        groups = claims['cognito:groups']

        results = batch_query_wrapper(TABLE_NAME, 'group', groups)
        print(results)

        if len(results) > 0:
            policy = {
                'Version': results[0]['policy']['Version'],
                'Statement': []
            }
            for item in results:
                policy['Statement'] = policy['Statement'] + item['policy']['Statement']

            return get_response_object(policy)

        return get_deny_policy()

    except Exception as e:
        print(e)

    return get_deny_policy()


def get_response_object(policyDocument, principalId='yyyyyyyy', context={}):
    return {
        "principalId": principalId,
        "policyDocument": policyDocument,
        "context": context,
        "usageIdentifierKey": "{api-key}"
    }


def get_deny_policy():
    return {
        "principalId": "yyyyyyyy",
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": "execute-api:Invoke",
                    "Effect": "Deny",
                    "Resource": "arn:aws:execute-api:*:*:*/ANY/*"
                }
            ]
        },
        "context": {},
        "usageIdentifierKey": "{api-key}"
    }


def batch_query_wrapper(table, key, values):
    results = []

    dynamodb = boto3.resource('dynamodb', region_name=AWS_REGION)
    values_list = [values[x:x + 25] for x in range(0, len(values), 25)]

    for vlist in values_list:
        response = dynamodb.batch_get_item(RequestItems={table: {'Keys': [{key: val} for val in vlist]}})
        results.extend(response['Responses'][table])

        while response['UnprocessedKeys']:
            response = dynamodb.batch_get_item(RequestItems={table: {'Keys': [{key: val} for val in vlist]}})
            results.extend(response['Response'][table])

    return results


def parse_token_data(event):
    response = {'valid': False}

    if 'Authorization' not in event['headers']:
        return response

    auth_header = event['headers']['Authorization']
    auth_header_list = auth_header.split(' ')

    # deny request of header isn't made out of two strings, or
    # first string isn't equal to "Bearer" (enforcing following standards,
    # but technically could be anything or could be left out completely)
    if len(auth_header_list) != 2 or auth_header_list[0] != 'Bearer':
        return response

    access_token = auth_header_list[1]
    return {
        'valid': True,
        'token': access_token
    }


def validate_token(token):
    # get the kid from the headers prior to verification
    headers = jwt.get_unverified_headers(token)
    kid = headers['kid']

    # search for the kid in the downloaded public keys
    key_index = -1
    for i in range(len(keys)):
        if kid == keys[i]['kid']:
            key_index = i
            break

    if key_index == -1:
        print('Public key not found in jwks.json')
        return False

    # construct the public key
    public_key = jwk.construct(keys[key_index])

    # get the last two sections of the token,
    # message and signature (encoded in base64)
    message, encoded_signature = str(token).rsplit('.', 1)

    # decode the signature
    decoded_signature = base64url_decode(encoded_signature.encode('utf-8'))

    # verify the signature
    if not public_key.verify(message.encode("utf8"), decoded_signature):
        print('Signature verification failed')
        return False

    print('Signature successfully verified')

    # since we passed the verification, we can now safely
    # use the unverified claims
    claims = jwt.get_unverified_claims(token)

    # additionally we can verify the token expiration
    if time.time() > claims['exp']:
        print('Token is expired')
        return False

    # and the Audience  (use claims['client_id'] if verifying an access token)
    if claims['client_id'] != COGNITO_APP_CLIENT_ID:
        print('Token was not issued for this audience')
        return False

    # now we can use the claims
    print(claims)
    return claims
# import json
# import jwt
# import os
#
# from http.cookies import SimpleCookie
#
# COGNITO_REGION = os.getenv("COGNITO_REGION")
# COGNITO_USER_POOL_ID = os.getenv("COGNITO_USER_POOL_ID")
# COGNITO_CLIENT_ID = os.getenv("COGNITO_CLIENT_ID")
# JWT_TOKEN_COOKIE_NAME = "idToken"
# TENANT_ID_HEADER_NAME = "x-tenant-id"
# TENANT_IDS_ATTRIBUTE = "custom:tenant_id_list"
#
# JWK_CLIENT = jwt.PyJWKClient(
#   'https://cognito-idp.{region}.amazonaws.com/{pool}/.well-known/jwks.json'.format(
#     region = COGNITO_REGION,
#     pool = COGNITO_USER_POOL_ID
#   )
# )
#
# def handler(event, context):
#   # Read ID token from cookie and get JWK signing key
#   token = get_token_value(event)
#   signing_key = JWK_CLIENT.get_signing_key_from_jwt(token)
#
#   try:
#     # Decode token - will throw an exception on failure.
#     data = jwt.decode(
#       token,
#       signing_key.key,
#       algorithms=["RS256"],
#       audience=COGNITO_CLIENT_ID,
#       options={
#         "verify_signature": True,
#         "verify_exp": True,
#         "verify_aud": True
#       }
#     )
#
#     # Get the tenant ID for the user.  To handle cases where a user can access multiple tenants,
#     # we'll require the "active" tenant ID to be declared via the x-tenant-id header. Can expand
#     # this to handle object admin user cross-tenant access.
#     username = data.get("cognito:username")
#     tenant_id = get_tenant_id(
#       data[TENANT_IDS_ATTRIBUTE].split(",") if TENANT_IDS_ATTRIBUTE in data else [],
#       event["headers"].get(TENANT_ID_HEADER_NAME)
#     )
#
#     print(f"Resolved tenant ID {tenant_id} for user {data.get('email')} ({username})")
#
#     # Only grant access if we can resolve a tenant ID.
#     if tenant_id:
#       policy = get_allow_policy(
#         username,
#         tenant_id,
#         event["requestContext"]["accountId"],
#         event["requestContext"]["apiId"]
#       )
#
#       return policy
#   except jwt.PyJWTError as jwt_error:
#     print(jwt_error)
#
#   return get_deny_policy()
#
#
# def get_tenant_id(assigned_tenant_ids, declared_tenant_id):
#   if declared_tenant_id in assigned_tenant_ids:
#     return declared_tenant_id
#   else:
#     return assigned_tenant_ids[0]
#
#
# def get_token_value(event):
#   if ("headers" in event and "cookie" in event["headers"]):
#     cookie = SimpleCookie()
#     cookie.load(event["headers"]["cookie"])
#     return cookie[JWT_TOKEN_COOKIE_NAME].value
#   return ""
#
#
# def get_allow_policy(principalId, tenantId, accountId, apiId):
#   policy_json = {
#     "principalId": principalId,
#     "policyDocument": {
#       "Version": "2012-10-17",
#       "Statement": [
#         {
#           "Action": "execute-api:Invoke",
#           "Effect": "Allow",
#           "Resource": [
#               f"arn:aws:execute-api:*:{accountId}:{apiId}/*/*/*"
#           ]
#         }
#       ]
#     },
#     "context": {
#       "tenantId": tenantId,
#       "userId": principalId,
#     }
#   }
#
#   return policy_json
#
# def get_deny_policy():
#   return {
#     "principalId": "user",
#     "policyDocument": {
#       "Version": "2012-10-17",
#       "Statement": [
#         {
#           "Action": "execute-api:Invoke",
#           "Effect": "Deny",
#           "Resource": f"arn:aws:execute-api:*"
#         }
#       ]
#     }
#   }
