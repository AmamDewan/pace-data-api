# Pace Data API

## Installation

Configuring a python environment is recommended.

```bash
pip install awscli aws-sam-cli
sam build
sam deploy --config-env <dev|stg|prod>
```


## Cognito User and JWT

```bash
aws cognito-idp sign-up \
        --client-id <value> \
        --username <value> \
        --password <value>

aws cognito-idp admin-confirm-sign-up \
        --user-pool-id <value> \
        --username <value>

aws cognito-idp initiate-auth \
        --client-id <value> \
        --auth-flow USER_PASSWORD_AUTH \
        --auth-parameters USERNAME=<value>,PASSWORD=<value>
```
