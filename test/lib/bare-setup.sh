#!/bin/sh
# bare-setup.sh -- the push-bare fixture: a bare repo the denied twin pushes
# to, and a worktree commit the allowed twin makes. Sourced by conformance.sh
# after cd "$D/repo".
git init -q --bare "$D/bare.git"
git config user.email cell@x
git config user.name cell
echo base > base.txt
git add base.txt
git commit -qm base
git remote add bare "$D/bare.git"
