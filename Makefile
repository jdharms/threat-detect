.PHONY : clean clean_db run docker docker_run docker_volume docker_clean test

detect: server.go internal graph
	go build -o detect server.go

data.db:
	touch ./data.db

run: detect data.db
	./detect

clean:
	$(RM) detect data.db

clean_db:
	$(RM) data.db

test:
	go test ./...

docker:
	docker build -t detect:latest .

docker_run:
	docker run -v detect-data:/app/data -p 8080:8080 --rm --name detect detect

docker_volume:
	docker volume create detect-data

docker_clean:
	docker volume remove detect-data
	docker rmi detect