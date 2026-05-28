# API Reference

The KilasOS JSON HTTP API is documented in [openapi.yaml](openapi.yaml).

## Rendering locally

Use Swagger UI in Docker:

```bash
docker run -p 8080:8080 -v $(pwd)/docs/api:/api swaggerapi/swagger-ui
open http://localhost:8080/?url=http://localhost:8080/api/openapi.yaml
```

Or use Redoc:

```bash
docker run -p 8080:80 -v $(pwd)/docs/api:/usr/share/nginx/html/api nginx
open http://localhost:8080/api/openapi.yaml
```

## Quick reference

- **Base URL:** `http://localhost:8080/api/v1`
- **Auth:** Bearer token in `Authorization` header
- **Content-Type:** `application/json`
- **Errors:** `{"error": "<message>"}` with appropriate HTTP status
