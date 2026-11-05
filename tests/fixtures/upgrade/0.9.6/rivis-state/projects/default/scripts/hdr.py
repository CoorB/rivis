def on_request(context, url, request):
    request["headers"]["X-QA"] = "enabled"
    return request
