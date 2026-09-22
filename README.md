# AI Jenkins Troubleshooter

A local AI-assisted application that retrieves Jenkins build logs and provides a short troubleshooting analysis.

## Features

- Lists available Jenkins pipelines
- Shows the latest 10 builds
- Displays build number, date, duration and status
- Supports Success, Failure, Aborted, Unstable, Not Built and Running
- Retrieves the selected build log automatically
- Masks sensitive values before AI analysis
- Produces a short description and key points
- Runs locally without a paid AI API
- Does not automatically execute remediation commands

## Architecture

- Jenkins provides pipeline and build information
- Flask provides the application API and web interface
- Ollama runs the local AI model
- Qwen2.5-Coder analyzes Jenkins logs
- Docker Compose manages the AI application and Ollama

## Requirements

- Docker Desktop
- Docker Compose
- An existing Jenkins container
- Jenkins API token
- Approximately 2 GB of storage for the AI model

## Configuration

Copy the example environment file:

```bash
cp .env.example .env
```

Update `.env`:

```text
JENKINS_URL=http://jenkins:8080
JENKINS_USERNAME=your-jenkins-username
JENKINS_API_TOKEN=your-jenkins-api-token
```

Never commit the `.env` file.

## Docker Network and Volume

Create the shared network:

```bash
docker network create ai-troubleshooting
```

Connect the existing Jenkins container:

```bash
docker network connect ai-troubleshooting jenkins
```

Create the Ollama volume:

```bash
docker volume create ollama-data
```

## Start the Application

```bash
docker compose up -d --build
```

Download the local AI model:

```bash
docker exec ollama ollama pull qwen2.5-coder:3b
```

Open:

```text
http://localhost:5000
```

## Usage

1. Select a Jenkins pipeline.
2. Select a build number.
3. Review its status.
4. Click **Analyze Selected Build**.
5. Review the short description and key points.

## Stop the Application

```bash
docker compose stop
```

## Start It Again

```bash
docker compose start
```

## View Logs

```bash
docker compose logs -f
```

## Security

- Jenkins credentials are loaded through `.env`.
- `.env` is excluded from Git and the Docker image.
- Common passwords, tokens, API keys and AWS access keys are removed.
- Potentially unsafe recommendations are filtered.
- AI recommendations must be reviewed before executing any command.
- For shared environments, use a dedicated read-only Jenkins account.

## Important Note

This project is a proof of concept. AI-generated troubleshooting recommendations may be incomplete or inaccurate and require human review.