# Push this project to GitHub

This folder is already a git repository with one commit. You only need to
create an empty repo on GitHub and push to it.

## 1. Create an empty repo on GitHub

Go to https://github.com/new and create a repository named:

    log-triage-ioc

Do NOT add a README, .gitignore or licence there (this folder already has them),
so the repo stays empty and the push goes through cleanly.

Suggested description:

    Log triage and IOC scanner: parses auth/access logs, detects attack patterns, reconstructs an incident timeline and reports.

## 2. Connect and push

Open a terminal in this folder and run (replace YOUR-USERNAME if needed):

    git remote add origin https://github.com/Sieber-1/log-triage-ioc.git
    git branch -M main
    git push -u origin main

That is it. Refresh the GitHub page and the code is there.

## If git asks for a password

GitHub no longer accepts your account password on the command line. Use a
Personal Access Token instead: https://github.com/settings/tokens (create a
token with the "repo" scope, then paste it when git asks for the password).
Or install the GitHub CLI (https://cli.github.com) and run `gh auth login` once.

## Run it locally first (optional)

    pip install -r requirements.txt
    python demo.py
    python -m pytest tests/ -q
