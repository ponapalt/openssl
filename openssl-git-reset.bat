git fetch origin
git reset --hard origin/master
git submodule sync --recursive
git submodule update --init --recursive --force
