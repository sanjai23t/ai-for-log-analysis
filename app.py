import os
import re

from urllib.parse import quote

import requests
from flask import Flask, jsonify, render_template, request

app = Flask(__name__)

# Limit the complete HTTP request body to 256 KB.
app.config["MAX_CONTENT_LENGTH"] = 256 * 1024

OLLAMA_URL = os.getenv(
    "OLLAMA_URL",
    "http://ollama:11434/api/generate"
)

OLLAMA_MODEL = os.getenv(
    "OLLAMA_MODEL",
    "qwen2.5-coder:3b"
)

MAX_LOG_LENGTH = int(os.getenv("MAX_LOG_LENGTH", "12000"))

JENKINS_URL = os.getenv(
    "JENKINS_URL",
    "http://jenkins:8080"
).rstrip("/")

JENKINS_USERNAME = os.getenv("JENKINS_USERNAME", "")
JENKINS_API_TOKEN = os.getenv("JENKINS_API_TOKEN", "")


def mask_sensitive_data(log_text):
    patterns = [
        (
            r"(?i)(password|passwd|pwd|token|api[_-]?key|secret)"
            r"\s*[:=]\s*[^\s]+",
            r"\1=[REDACTED]"
        ),
        (
            r"(?i)authorization:\s*bearer\s+[^\s]+",
            "Authorization: Bearer [REDACTED]"
        ),
        (
            r"\bAKIA[0-9A-Z]{16}\b",
            "[REDACTED_AWS_ACCESS_KEY]"
        )
    ]

    sanitized_log = log_text

    for pattern, replacement in patterns:
        sanitized_log = re.sub(
            pattern,
            replacement,
            sanitized_log
        )

    # Completely remove lines where sensitive values were detected.
    # This prevents the model from discussing the redacted value.
    safe_lines = [
        line
        for line in sanitized_log.splitlines()
        if "[REDACTED" not in line
    ]

    return "\n".join(safe_lines)


def filter_unsafe_recommendations(ai_response):
    unsafe_patterns = [
        # Unsafe Docker socket permissions
        r"(?im)^.*\bchmod\s+(?:666|777)\b.*$",
        r"(?im)^.*\bpermissions?\b.{0,30}\b(?:666|777)\b.*$",
        r"(?im)^.*-rw-rw-rw-.*$",

        # User/group modification suggestions
        r"(?im)^.*\bsudo\s+usermod\b.*$",

        # Inappropriate systemd restart suggestions
        r"(?im)^.*\bsystemctl\s+restart\s+(?:jenkins|docker)\b.*$",

        # Changing ownership of the Docker socket
        r"(?im)^.*\bchown\b.*?/var/run/docker\.sock.*$"
    ]

    filtered_response = ai_response
    unsafe_content_found = False

    for pattern in unsafe_patterns:
        filtered_response, replacements = re.subn(
            pattern,
            "[Potentially unsafe recommendation removed]",
            filtered_response
        )

        if replacements:
            unsafe_content_found = True

    if unsafe_content_found:
        safety_notice = (
            "SAFETY NOTICE\n"
            "Potentially unsafe recommendations were automatically removed. "
            "Review all remaining commands before execution.\n\n"
        )

        return safety_notice + filtered_response

    return filtered_response


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/health")
def health():
    return jsonify(
        {
            "status": "healthy",
            "application": "AI Jenkins Troubleshooter"
        }
    )

@app.route("/api/jenkins/jobs")
def get_jenkins_jobs():
    if not JENKINS_USERNAME or not JENKINS_API_TOKEN:
        return jsonify(
            {
                "error": (
                    "Jenkins credentials are not configured "
                    "in the application container."
                )
            }
        ), 500

    try:
        jenkins_response = requests.get(
            f"{JENKINS_URL}/api/json",
            params={
                "tree": "jobs[name,color]"
            },
            auth=(
                JENKINS_USERNAME,
                JENKINS_API_TOKEN
            ),
            timeout=15
        )

        jenkins_response.raise_for_status()
        response_data = jenkins_response.json()

        jobs = [
            {
                "name": job.get("name"),
                "status": job.get("color")
            }
            for job in response_data.get("jobs", [])
        ]

        jobs.sort(
            key=lambda job: (job.get("name") or "").lower()
        )

        return jsonify(
            {
                "jobs": jobs,
                "count": len(jobs)
            }
        )

    except requests.Timeout:
        return jsonify(
            {"error": "The Jenkins API request timed out."}
        ), 504

    except requests.RequestException:
        app.logger.exception("Unable to retrieve Jenkins jobs")

        return jsonify(
            {
                "error": (
                    "Unable to retrieve Jenkins jobs. "
                    "Check the Jenkins URL and credentials."
                )
            }
        ), 502

    except ValueError:
        return jsonify(
            {"error": "Jenkins returned an invalid response."}
        ), 502

@app.route("/api/jenkins/builds", methods=["POST"])
def get_jenkins_builds():
    request_data = request.get_json(silent=True) or {}
    job_name = str(request_data.get("job_name", "")).strip()

    if not job_name:
        return jsonify(
            {"error": "Please select a Jenkins pipeline."}
        ), 400

    if not JENKINS_USERNAME or not JENKINS_API_TOKEN:
        return jsonify(
            {"error": "Jenkins credentials are not configured."}
        ), 500

    encoded_job_name = quote(job_name, safe="")

    builds_url = (
        f"{JENKINS_URL}/job/{encoded_job_name}/api/json"
    )

    try:
        jenkins_response = requests.get(
            builds_url,
            params={
                "tree": (
                    "builds["
                    "number,result,building,timestamp,duration,url"
                    "]{0,10}"
                )
            },
            auth=(
                JENKINS_USERNAME,
                JENKINS_API_TOKEN
            ),
            timeout=15
        )

        if jenkins_response.status_code == 404:
            return jsonify(
                {"error": "The selected pipeline was not found."}
            ), 404

        jenkins_response.raise_for_status()
        response_data = jenkins_response.json()

        builds = []

        for build in response_data.get("builds", []):
            if build.get("building"):
                status = "RUNNING"
            elif build.get("result"):
                status = build.get("result")
            else:
                status = "NOT_BUILT"

            builds.append(
                {
                    "number": build.get("number"),
                    "status": status,
                    "timestamp": build.get("timestamp"),
                    "duration": build.get("duration")
                }
            )

        return jsonify(
            {
                "job_name": job_name,
                "builds": builds,
                "count": len(builds)
            }
        )

    except requests.Timeout:
        return jsonify(
            {"error": "The Jenkins builds request timed out."}
        ), 504

    except requests.RequestException:
        app.logger.exception("Unable to retrieve Jenkins builds")

        return jsonify(
            {
                "error": (
                    "Unable to retrieve builds for the "
                    "selected pipeline."
                )
            }
        ), 502

    except ValueError:
        return jsonify(
            {"error": "Jenkins returned invalid build information."}
        ), 502


@app.route("/api/jenkins/build-log", methods=["POST"])
def get_selected_build_log():
    request_data = request.get_json(silent=True) or {}

    job_name = str(request_data.get("job_name", "")).strip()
    build_number = request_data.get("build_number")

    if not job_name:
        return jsonify(
            {"error": "Please select a Jenkins pipeline."}
        ), 400

    try:
        build_number = int(build_number)

        if build_number <= 0:
            raise ValueError

    except (TypeError, ValueError):
        return jsonify(
            {"error": "Please select a valid Jenkins build number."}
        ), 400

    if not JENKINS_USERNAME or not JENKINS_API_TOKEN:
        return jsonify(
            {"error": "Jenkins credentials are not configured."}
        ), 500

    encoded_job_name = quote(job_name, safe="")

    build_url = (
        f"{JENKINS_URL}/job/{encoded_job_name}"
        f"/{build_number}/api/json"
    )

    console_url = (
        f"{JENKINS_URL}/job/{encoded_job_name}"
        f"/{build_number}/consoleText"
    )

    try:
        build_response = requests.get(
            build_url,
            params={
                "tree": "number,result,building,timestamp,duration,url"
            },
            auth=(
                JENKINS_USERNAME,
                JENKINS_API_TOKEN
            ),
            timeout=15
        )

        if build_response.status_code == 404:
            return jsonify(
                {"error": "The selected Jenkins build was not found."}
            ), 404

        build_response.raise_for_status()
        build_information = build_response.json()

        console_response = requests.get(
            console_url,
            auth=(
                JENKINS_USERNAME,
                JENKINS_API_TOKEN
            ),
            timeout=30
        )

        console_response.raise_for_status()
        console_log = console_response.text

        if len(console_log) > 50000:
            console_log = (
                "[Earlier console lines omitted]\n"
                + console_log[-50000:]
            )

        if build_information.get("building"):
            status = "RUNNING"
        elif build_information.get("result"):
            status = build_information.get("result")
        else:
            status = "NOT_BUILT"

        return jsonify(
            {
                "job_name": job_name,
                "build_number": build_number,
                "status": status,
                "timestamp": build_information.get("timestamp"),
                "duration": build_information.get("duration"),
                "console_log": console_log
            }
        )

    except requests.Timeout:
        return jsonify(
            {"error": "The selected build request timed out."}
        ), 504

    except requests.RequestException:
        app.logger.exception(
            "Unable to retrieve selected Jenkins build"
        )

        return jsonify(
            {
                "error": (
                    "Unable to retrieve the selected Jenkins build."
                )
            }
        ), 502

    except ValueError:
        return jsonify(
            {"error": "Jenkins returned invalid build information."}
        ), 502


@app.route("/api/analyze", methods=["POST"])
def analyze():
    request_data = request.get_json(silent=True) or {}

    jenkins_log = str(
        request_data.get("jenkins_log", "")
    ).strip()

    job_name = str(
        request_data.get("job_name", "Unknown pipeline")
    ).strip()

    build_number = request_data.get(
        "build_number",
        "Unknown"
    )

    build_status = str(
        request_data.get("build_status", "UNKNOWN")
    ).strip().upper()

    if not jenkins_log:
        return jsonify(
            {"error": "Please provide a Jenkins build log."}
        ), 400

    sanitized_log = mask_sensitive_data(jenkins_log)

    if not sanitized_log.strip():
        return jsonify(
            {
                "error": (
                    "The submitted log contained only sensitive data "
                    "and cannot be analyzed."
                )
            }
        ), 400

    # Jenkins failures normally appear near the end of the console log.
    if len(sanitized_log) > MAX_LOG_LENGTH:
        sanitized_log = (
            "[Earlier log lines omitted]\n"
            + sanitized_log[-MAX_LOG_LENGTH:]
        )


    environment_context = (
        "Jenkins runs in a Docker container on Docker Desktop with WSL 2."
    )

    if re.search(
        r"docker\.sock|docker daemon socket|permission denied.*docker",
        sanitized_log,
        re.IGNORECASE
    ):
        environment_context += """
The log contains a Docker socket problem.
Check whether /var/run/docker.sock is mounted and whether its group ID
matches a group available to the Jenkins container user.
Never recommend permissions 666 or 777 for the Docker socket.
Do not recommend changing socket ownership without inspection.
"""

    if build_status == "SUCCESS":
        status_guidance = """
This build succeeded.
Do not describe any stage as failed unless the log explicitly proves it.
Do not invent a timeout, network issue or root cause.
Mention downstream warnings only when directly supported by the log.
"""

    elif build_status == "ABORTED":
        status_guidance = """
This build was aborted.
If the log identifies who or what aborted it, state that evidence.
Do not describe the build as failed.
Do not recommend permission changes.
The normal next action is to confirm whether the abort was intentional
and rerun only when appropriate.
"""

    elif build_status == "FAILURE":
        status_guidance = """
This build failed.
Identify the first meaningful error and the stage where it occurred.
Recommend one safe and evidence-based next action.
"""

    elif build_status == "UNSTABLE":
        status_guidance = """
This build is unstable, not failed.
Identify warnings, failed tests or quality thresholds from the log.
"""

    else:
        status_guidance = """
Describe the build status using only evidence from Jenkins and the log.
"""

    prompt = f"""
You are an AI-assisted Jenkins and DevOps troubleshooting agent.

Authoritative Jenkins build information:
- Pipeline: {job_name}
- Build number: {build_number}
- Overall build status: {build_status}

Status-specific guidance:
{status_guidance}

The overall build status above comes directly from Jenkins and is final.
Never contradict it.

A downstream pipeline can fail while the selected pipeline still finishes
successfully, especially when failure propagation is disabled. Mention such
an event as a warning, but do not change the selected build's overall status.

For an aborted build, do not recommend changing user permissions merely
because a user manually stopped it.

Environment context:
{environment_context}

Analyze the selected Jenkins build using only evidence from the log.

Return exactly this format:

SHORT DESCRIPTION
Write a maximum of two short sentences describing the build outcome
and primary cause.

KEY POINTS
- Overall build status
- Most important stage or event
- Direct evidence from the log
- Impact on this pipeline or downstream pipeline
- One practical next action

Rules:
- Keep the complete response under 120 words.
- Return only SHORT DESCRIPTION and KEY POINTS.
- Use plain text without Markdown formatting symbols.
- Use only three to five short key points.
- Focus on the first meaningful error that caused the failure.
- Do not introduce unrelated infrastructure, tools or causes.
- Every proposed cause must be supported by the log.
- If the build succeeded, do not invent a problem.
- If the build was aborted, distinguish manual cancellation from timeout
  only when the log provides evidence.
- If evidence is insufficient, clearly say so.
- Do not request or expose credentials or secret values.
- Do not automatically execute or recommend destructive commands.
- Do not invent timeout, networking, authentication or permission issues.

Jenkins build log:
--- BEGIN LOG ---
{sanitized_log}
--- END LOG ---
"""


    try:
        ollama_response = requests.post(
            OLLAMA_URL,
            json={
                "model": OLLAMA_MODEL,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0.2
                }
            },
            timeout=180
        )

        ollama_response.raise_for_status()
        result = ollama_response.json()

        ai_analysis = result.get(
            "response",
            "The AI model returned an empty response."
        ).strip()

        safe_analysis = filter_unsafe_recommendations(ai_analysis)

        return jsonify(
            {
                "analysis": safe_analysis,
                "model": OLLAMA_MODEL
            }
        )

    except requests.Timeout:
        app.logger.exception("Ollama analysis timed out")

        return jsonify(
            {
                "error": (
                    "The local AI model took too long to respond. "
                    "Please try again with a shorter log."
                )
            }
        ), 504

    except requests.RequestException:
        app.logger.exception("Unable to communicate with Ollama")

        return jsonify(
            {
                "error": (
                    "Unable to communicate with the local AI model. "
                    "Check whether the Ollama container is running."
                )
            }
        ), 502

    except ValueError:
        app.logger.exception("Ollama returned an invalid JSON response")

        return jsonify(
            {
                "error": "The local AI model returned an invalid response."
            }
        ), 502


if __name__ == "__main__":
    port = int(os.getenv("PORT", "5000"))
    app.run(host="0.0.0.0", port=port)