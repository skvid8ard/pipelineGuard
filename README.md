# PipelineGuard MVP

A minimal multi-tenant SaaS API for static checks on GitLab CI YAML.

## Run

```bash
docker build -t pipelineguard .
docker run --rm --name pipelineguard -p 8080:8080 -v pipelineguard-data:/data pipelineguard
```

SQLite is created automatically in the Docker volume. For a clean demo, remove the volume after stopping the container: `docker volume rm pipelineguard-data`.

API documentation: http://localhost:8080/docs

## Demo tenants

- A: `Authorization: Bearer token-a` — Free, 2 scans
- B: `Authorization: Bearer token-b` — Pro, 5 scans

These are deliberately hard-coded *test credentials*.

## Examples

```bash
curl -s http://localhost:8080/me -H 'Authorization: Bearer token-a'
curl -s -X POST http://localhost:8080/scans \
  -H 'Authorization: Bearer token-b' -H 'Content-Type: application/json' \
  -d '{"filename":".gitlab-ci.yml","content":"image: nginx:latest"}'
curl -s http://localhost:8080/scans -H 'Authorization: Bearer token-b'
curl -s http://localhost:8080/scans/1 -H 'Authorization: Bearer token-a'
```

### Acceptance tests

1. Both tenants can create and read their own scans.
2. B creates a scan; A receives HTTP 404 for its ID; B can still read the scan.
3. A can create 2 scans and receives HTTP 409 on the third. Its `used` count stays 2. B can create at least 3 scans.

The scanner is a demonstration of rules, not a complete security analyzer. No user-supplied YAML is executed.
