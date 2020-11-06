# Import processed log to mongodb container

## 1. Copy file to container

```shell
docker cp access_log.json mongodb:/tmp/access_log.json
```

## 2. Import to mongodb

```shell
docker exec -it mongodb mongoimport -d ===database_name=== -c ===collection_name=== --file /tmp/access_log.json
```

## 3. Access to container's shell

```shell
docker exec -it mongodb /bin/bash
```

## 4. Delete tmp file

```shell
rm -rf /tmp/access_log.json
```
