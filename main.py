import os

import requests
import re
from typing import List, Dict

GITHUB_API_URL = "https://api.github.com"


def get_user_repos(username: str, token: str) -> List[Dict]:
    headers = {"Authorization": f"token {token}"}
    repos_url = f"{GITHUB_API_URL}/users/{username}/repos"
    response = requests.get(repos_url, headers=headers)
    response.raise_for_status()
    return response.json()


def get_repo_files(owner: str, repo: str, token: str) -> List[Dict]:
    headers = {"Authorization": f"token {token}"}
    repo_url = f"{GITHUB_API_URL}/repos/{owner}/{repo}/git/trees/main?recursive=1"
    response = requests.get(repo_url, headers=headers)
    response.raise_for_status()
    tree = response.json()["tree"]

    files = []
    for item in tree:
        if item["type"] == "blob":
            file_url = f"{GITHUB_API_URL}/repos/{owner}/{repo}/contents/{item['path']}"
            file_response = requests.get(file_url, headers=headers)
            file_response.raise_for_status()
            content = file_response.json()["content"]
            files.append({"path": item["path"], "content": content})
    return files


def find_secrets(content: str) -> List[str]:
    secrets = []
    patterns = [
        r'aws_secret_access_key\s*=\s*["\']?([a-zA-Z0-9/+=]{40})["\']?',  # AWS secret key
        r'aws_access_key_id\s*=\s*["\']?([A-Z0-9]{20})["\']?',  # AWS access key
        r'ghp_[A-Za-z0-9]{36}',  # GitHub personal access token
        r'slack_api_token\s*=\s*["\']?([a-zA-Z0-9-]{24,36})["\']?',  # Slack API token
        r'api_key\s*=\s*["\']?([a-zA-Z0-9-]{32,64})["\']?',  # Generic API key
    ]

    for pattern in patterns:
        matches = re.findall(pattern, content)
        secrets.extend(matches)
    return secrets


def scan_all_repos(username: str, token: str) -> Dict[str, Dict[str, List[str]]]:
    repos = get_user_repos(username, token)
    all_secrets = {}

    for repo in repos:
        repo_name = repo["name"]
        print(f"Scanning repository: {repo_name}")
        try:
            files = get_repo_files(username, repo_name, token)
            secrets_dict = {}
            for file in files:
                secrets = find_secrets(file["content"])
                if secrets:
                    secrets_dict[file["path"]] = secrets
            if secrets_dict:
                all_secrets[repo_name] = secrets_dict
        except Exception as e:
            print(f"Error scanning {repo_name}: {e}")

    return all_secrets


def display_secrets(all_secrets: Dict[str, Dict[str, List[str]]]) -> None:
    for repo_name, secrets_dict in all_secrets.items():
        print(f"Secrets found in repository {repo_name}:")
        for file_path, secrets in secrets_dict.items():
            print(f"  - {file_path}:")
            for secret in secrets:
                print(f"    - {secret}")


if __name__ == "__main__":
    username = os.getenv('username')
    token = os.getenv('token')

    all_secrets = scan_all_repos(username, token)
    display_secrets(all_secrets)
