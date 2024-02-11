# Wl-mc launcher and minecraft api server

## Setup (docker compose)
**Requirements:**
  - Docker with docker compose plugin

1. Clone the git repository
    ```shell
    git clone https://github.com/W-Lands/api
    ```
2. Rename example config
    ```shell
    mv .env.example .env
    ```
3. Change config variables
4. Run:
    ```shell
    docker compose up
    ```
5. Log in into minio admin and change wlands-updates bucket policy to:
```json
{
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"AWS": ["*"]},
        "Action": ["s3:GetObject"],
        "Resource": ["arn:aws:s3:::wlands-updates/*"]
    }]
}
```

## Setup (without docker)
**Requirements:**
  - Python 3.11+
  - Poetry

1. Clone the git repository
    ```shell
    git clone https://github.com/W-Lands/api
    ```
2. Install dependencies:
    ```shell
    poetry install
    ```
3. Set the following environment variables:
    - `DATABASE_URL` - Database connection string, for example: `mysql://username:password@127.0.0.1/wlands`
    - `S3_ENDPOINT` - S3 endpoint, for example: `http://127.0.0.1:9000`
    - `S3_ACCESS_KEY_ID` - S3 access key
    - `S3_SECRET_ACCESS_KEY` - S3 secret key
4. Run:
    ```shell
    poetry run uvicorn --workers 4 --host 127.0.0.1 --port 8080 wlands.main:app
    ```