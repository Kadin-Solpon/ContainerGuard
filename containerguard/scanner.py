import docker
from docker.errors import NotFound, DockerException

def get_client():
    try:
        return docker.from_env()
    except DockerException:
        print("Error: Docker is not running. Start Docker Desktop first.")
        exit(1)

def scan_image(image_name):
    client = get_client()
    try:
        image = client.images.get(image_name)
        print(f"Connected to image: {image_name}")
        print(f"Tags: {image.tags}")
        print(f"Full attrs keys: {list(image.attrs.keys())}")
        # Week 2 Day 10: pass attrs to image_checks.py
    except docker.errors.ImageNotFound:
        print(f"Image '{image_name}' not found. Pull it first with: docker pull {image_name}")

def scan_runtime(container_id):
    client = get_client()
    try:
        container = client.containers.get(container_id)
        print(f"Connected to container: {container_id}")
        print(f"Status: {container.status}")
        print(f"Full attrs keys: {list(container.attrs.keys())}")
        # Week 2 Day 11: pass attrs to runtime_checks.py
    except NotFound:
        print(f"Container '{container_id}' not found. Is it running?")
