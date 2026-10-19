"""Benign loopback applications for bench_frameworks.py; isolated dependencies."""
from __future__ import annotations

import argparse
import hashlib
from importlib.metadata import distributions
import json
import socket


def policy(path):
    valid = {
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Cross-Origin-Resource-Policy": "same-origin",
        "Cross-Origin-Opener-Policy": "same-origin",
        "Cross-Origin-Embedder-Policy": "require-corp",
    }
    if path in ("/policy/valid", "/policy/repeated", "/policy/referrer-invalid", "/policy/referrer-unknown"):
        if path == "/policy/referrer-invalid":
            valid["Referrer-Policy"] = "no-referrer, origin no-referrer"
        elif path == "/policy/referrer-unknown":
            valid["Referrer-Policy"] = "no-referrer, future-policy"
        return valid
    if path == "/policy/invalid":
        return dict.fromkeys(valid, "invalid-policy")
    return {}


def cookies(response, path):
    if path == "/cookies":
        response.set_cookie("first", "ordinary", httponly=True, samesite="Lax")
        response.set_cookie("second", "another", httponly=True, samesite="Lax")
    return response


def record(method, path, raw, query, form, files, data):
    return {"method": method, "path": path, "body_sha256": hashlib.sha256(raw).hexdigest(),
            "query": query, "form": form, "files": files, "json": data}


def upload(name, raw):
    return {"filename": name, "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def is_json(content_type):
    media = content_type.split(";", 1)[0].strip().lower()
    return media == "application/json" or media.endswith("+json")


def django_app():
    from django.conf import settings
    settings.configure(
        SECRET_KEY="loopback-benchmark-only", DEBUG=False, ROOT_URLCONF=__name__,
        ALLOWED_HOSTS=["fixture.local", "127.0.0.1"],
        MIDDLEWARE=["django.middleware.security.SecurityMiddleware"],
    )
    import django
    django.setup()
    from django.core.asgi import get_asgi_application
    from django.http import JsonResponse
    from django.urls import re_path

    def echo(request):
        raw = request.body
        files = {k: [upload(f.name, f.read()) for f in values]
                 for k, values in request.FILES.lists()}
        payload = record(request.method, request.path, raw, dict(request.GET.lists()),
                         dict(request.POST.lists()), files,
                         json.loads(raw) if raw and is_json(request.content_type) else None)
        return cookies(JsonResponse(payload, headers=policy(request.path)), request.path)

    global urlpatterns
    urlpatterns = [re_path(r"^.*$", echo)]
    return get_asgi_application()


def flask_app():
    from asgiref.wsgi import WsgiToAsgi
    from flask import Flask, jsonify, request
    app = Flask(__name__)

    @app.route("/", defaults={"path": ""}, methods=["GET", "POST"])
    @app.route("/<path:path>", methods=["GET", "POST"])
    def echo(path):
        raw = request.get_data()
        files = {k: [upload(f.filename, f.read()) for f in values]
                 for k, values in request.files.lists()}
        payload = record(request.method, request.path, raw, dict(request.args.lists()),
                         dict(request.form.lists()), files,
                         request.get_json() if raw and request.is_json else None)
        response = jsonify(payload)
        response.headers.update(policy(request.path))
        return cookies(response, request.path)

    return WsgiToAsgi(app)


def fastapi_app():
    from fastapi import FastAPI, Request
    from starlette.datastructures import UploadFile
    from starlette.responses import JSONResponse
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    # Explicit annotation avoids resolution of a function-local postponed type.
    async def echo(request):
        raw = await request.body()
        fields, files = {}, {}
        async with request.form() as form:
            for key, value in form.multi_items():
                if isinstance(value, UploadFile):
                    files.setdefault(key, []).append(upload(value.filename, await value.read()))
                else:
                    fields.setdefault(key, []).append(value)
        query = {k: request.query_params.getlist(k) for k in request.query_params}
        data = await request.json() if raw and is_json(request.headers.get("content-type", "")) else None
        return cookies(JSONResponse(record(request.method, request.url.path, raw, query, fields, files, data),
                                    headers=policy(request.url.path)), request.url.path)

    echo.__annotations__["request"] = Request
    app.add_api_route("/{path:path}", echo, methods=["GET", "POST"])
    return app


def repeated_policy_fields(app):
    # Django's response mapping cannot express duplicate fields; append in ASGI.
    async def wrapped(scope, receive, send):
        async def emit(message):
            if scope.get("path") == "/policy/repeated" and message["type"] == "http.response.start":
                message = {**message, "headers": [*message["headers"],
                           (b"cross-origin-opener-policy", b"unsafe-none"),
                           (b"referrer-policy", b"unsafe-url")]}
            await send(message)
        await app(scope, receive, emit)
    return wrapped


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("framework", choices=["django", "flask", "fastapi"])
    args = parser.parse_args()
    import uvicorn
    app = repeated_policy_fields({"django": django_app, "flask": flask_app, "fastapi": fastapi_app}[args.framework]())
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        sock.listen(64)
        versions = {d.metadata["Name"].lower(): d.version for d in distributions()}
        print(json.dumps({"framework": args.framework, "port": sock.getsockname()[1],
                          "packages": versions}), flush=True)
        server = uvicorn.Server(uvicorn.Config(app, log_level="error", lifespan="off", access_log=False))
        server.run(sockets=[sock])


if __name__ == "__main__":
    main()
