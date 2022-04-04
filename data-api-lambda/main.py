import json
from aws_lambda_powertools.event_handler.api_gateway import APIGatewayRestResolver, CORSConfig, Response


cors_config = CORSConfig(allow_origin="*")
app = APIGatewayRestResolver(cors=cors_config)


@app.get(".+")
def catch_all_route():
    return Response(
        status_code=200,
        content_type="application/json",
        body=json.dumps({"path": app.current_event.path})
    )


def handler(event, context):
    print(context)
    print(event)
    return app.resolve(event, context)
