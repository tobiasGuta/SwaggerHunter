**SwaggerHunter** A Swagger/OpenAPI enumerator and lightweight endpoint probing tool. Automatically parses Swagger/OpenAPI specifications, lists all API endpoints, applies optional filters (HTTP methods, limits), and can generate:

-   JSON reports of endpoints

-   Postman collections (v2.1)

-   Burp Suite XML sitemap

It also supports **conservative probing** of endpoints with optional JWT tokens, making it useful for security testing, API discovery, and penetration testing.

**Features**:

-   Fetch Swagger/OpenAPI spec from URL or local file

-   Enumerate endpoints with path templates and examples

-   Filter endpoints by HTTP method or limit

-   Export to JSON, Postman, or Burp XML

-   Optional probing with status codes and results summary

-   Concurrency and rate-limiting options

-   Handles JWT Bearer tokens

**Use cases**:

-   API security assessments

-   Automated Postman collection generation

-   Rapid endpoint discovery for bug hunting
