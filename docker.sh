docker kill lgcc-test-rig || true
docker rm lgcc-test-rig || true
docker build --no-cache -t lgcc-test-rig .
docker run -d -v /Volumes/Linux\ kernel:/alpine --privileged --cap-add=NET_ADMIN -it --name lgcc-test-rig lgcc-test-rig
docker exec -it lgcc-test-rig /bin/sh
