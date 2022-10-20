docker network inspect frontnet >/dev/null 2>&1 || docker network create --driver bridge frontnet

docker network inspect backnet >/dev/null 2>&1 || docker network create --driver bridge backnet
