def register_security_headers(app):
    @app.after_request
    def add_headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' https://cdn.jsdelivr.net; "
            "style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
            "img-src 'self' data:; font-src 'self' https://cdn.jsdelivr.net"
        )
        if not app.debug and not app.testing:
            resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return resp