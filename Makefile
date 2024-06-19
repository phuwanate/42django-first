export DJANGO_APP=mydjango
# export MYUID=$(shell id -u)

all:
# @mkdir -p srcs/app
	docker compose -f docker-compose.yaml up --build
down:
	docker compose -f docker-compose.yaml down

test:
	python3 srcs/app/manage.py test app1