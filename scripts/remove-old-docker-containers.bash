set -eu
set -o pipefail

THIS_FILE_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
CI="${THIS_FILE_DIR}/../../wg-app-platform-runtime-ci"
. "$CI/shared/helpers/git-helpers.bash"
REPO_NAME=$(git_get_remote_name)

# Remove existing containers
if docker ps -a | grep "$REPO_NAME-docker-container"; then
  docker ps -a | grep "$REPO_NAME-docker-container" | cut -d' ' -f1 | xargs -n1 docker rm -f
fi
