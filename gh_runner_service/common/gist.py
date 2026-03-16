import requests
from typing import cast
from .exceptions import AppError

def create_gist(token: str, content: str, filename: str = "nat.enc") -> str:
    headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github.v3+json"}
    payload = {"public": False, "files": {filename: {"content": content}}}
    r = requests.post("https://api.github.com/gists", json=payload, headers=headers)
    if r.status_code != 201:
        raise AppError(f"Failed to create gist: {r.text}")
    return cast(str, r.json()["id"])

def read_gist(token: str, gist_id: str, filename: str = "nat.enc") -> str:
    headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github.v3+json"}
    r = requests.get(f"https://api.github.com/gists/{gist_id}", headers=headers)
    if r.status_code != 200:
        raise AppError(f"Failed to read gist: {r.text}")
    return cast(str, r.json()["files"][filename]["content"])

def update_gist(token: str, gist_id: str, content: str, filename: str = "nat.enc") -> None:
    headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github.v3+json"}
    payload = {"files": {filename: {"content": content}}}
    r = requests.patch(f"https://api.github.com/gists/{gist_id}", json=payload, headers=headers)
    if r.status_code != 200:
        raise AppError(f"Failed to update gist: {r.text}")

def delete_gist(token: str, gist_id: str) -> None:
    headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github.v3+json"}
    requests.delete(f"https://api.github.com/gists/{gist_id}", headers=headers)
