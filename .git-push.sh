#!/bin/bash
set -e
cd /workspaces/crypto-lab-shamir-gate
git add -A
git commit -F .commit-msg
rm .commit-msg
git push origin main
echo "Done: committed and pushed to origin/main"
