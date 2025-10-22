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

## Setup

```bash
pip install -r requirements.txt
```

# Interactive Mode (TUI):

```bash
python3 swaggerhunter.py
```

<img width="1315" height="347" alt="image" src="https://github.com/user-attachments/assets/cb1c4b1e-69d0-43ad-8def-777bf201d57a" />

## Screenshot

```bash
python3 swaggerhunter.py -h
```

<img width="1909" height="540" alt="image" src="https://github.com/user-attachments/assets/cf14ca64-87ab-489b-80ea-86b6e370915f" />

```bash
python3 swaggerhunter.py -u 'http://IP:PORT/swagger/v1/swagger.json'
```

<img width="1908" height="980" alt="image" src="https://github.com/user-attachments/assets/363fb27d-6d0b-4318-8940-3df5a1502c06" />

## Video

```bash
python3 swaggerhunter.py -u 'http://94.237.123.178:32175/swagger/v1/swagger.json' --probe
```

https://github.com/user-attachments/assets/733cd15e-9248-45e0-bd58-f20081309d5c

```bash
python3 swaggerhunter.py -u 'http://94.237.123.178:32175/swagger/v1/swagger.json' --probe --limit 5 --method GET
```

https://github.com/user-attachments/assets/f42cbf94-1498-4db9-8a3e-30ce5dabb3fe

```bash
python3 swaggerhunter.py -u 'http://94.237.123.178:32175/swagger/v1/swagger.json' --probe --method GET --token 'xxxxxxxxxxxxxxxxxxxxxx'
```

https://github.com/user-attachments/assets/12aa259b-23c7-459e-9873-cdf05d631d60

```bash
python3 swaggerhunter.py -u 'http://94.237.123.178:32175/swagger/v1/swagger.json' --probe --method GET --token 'xxxxxxxxxxxxxxxxxxxxx' --limit 5 --postman /mnt/d/autoswagger/swaggerapi.json
```

https://github.com/user-attachments/assets/a37f2d10-035b-4120-999d-f4a2f7e13b31

# Support
If my tool helped you land a bug bounty, consider buying me a coffee ☕️ as a small thank-you! Everything I build is free, but a little support helps me keep improving and creating more cool stuff ❤️
---

<div align="center">
  <h3>☕ Support My Journey</h3>
</div>


<div align="center">
  <a href="https://www.buymeacoffee.com/tobiasguta">
    <img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" width="200" />
  </a>
</div>

---





