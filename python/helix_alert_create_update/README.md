## Implementation


Create the subfolder & cache file in the shared directory:

```json
cd /var/opt/morpheus/morpheus-ui/
```

```
mkdir caches
```

``` 
touch caches/incidentStateCache.json
```

Create empty JSON object in the file:

```
{}
```

Change ownership:

```json
chown -R morpheus-app:morpheus-local caches
```

Change permissions: 

```json
chmod 666 caches/incidentStateCache.json
```

Implement Cypher secrets on the following mounts:

```json
## Username 
secret/helixUser

## Password
secret/helixPassword
```