docker kill libvirt-container && docker rm libvirt-container
docker build -t libvirt-experiment .
docker run -d -v /Volumes/Linux\ kernel:/alpine --privileged --cap-add=NET_ADMIN -it --name libvirt-container libvirt-experiment
docker exec -it libvirt-container /bin/sh
