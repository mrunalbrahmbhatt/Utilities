#!/bin/bash

# Path to the workflow file
WORKFLOW_FILE="msdevopssec.yml"

# Ensure the workflow file exists
if [ ! -f "$WORKFLOW_FILE" ]; then
  echo "Error: Workflow file $WORKFLOW_FILE not found!"
  exit 1
fi

# List all repositories you have access to (personal and orgs) and loop through them
gh repo list --no-archived --json nameWithOwner -q '.[] | .nameWithOwner' | while read -r repo; do
  echo "Processing $repo..."

  # Get the default branch for the repository
  DEFAULT_BRANCH=$(gh api "repos/$repo" --jq '.default_branch')
  if [ -z "$DEFAULT_BRANCH" ]; then
    echo "Failed to fetch default branch for $repo, skipping..."
    continue
  fi
  echo "Default branch for $repo is $DEFAULT_BRANCH"

  # Clone the repository
  gh repo clone "$repo" temp_repo
  cd temp_repo || exit

  # Create .github/workflows directory if it doesn't exist
  mkdir -p .github/workflows

  # Copy the workflow file
  cp "../$WORKFLOW_FILE" .github/workflows/

  # Add, commit, and push changes
  git add .github/workflows/"$WORKFLOW_FILE"
  git commit -m "Add $WORKFLOW_FILE workflow" || {
    echo "Commit failed for $repo (possibly no changes or Git config issue)"
    cd ..
    rm -rf temp_repo
    continue
  }
  git push origin "$DEFAULT_BRANCH" || {
    echo "Failed to push to $repo (possibly no write access)"
    cd ..
    rm -rf temp_repo
    continue
  }

  # Navigate back and clean up
  cd ..
  rm -rf temp_repo

  echo "Finished processing $repo"
done
