
COOKIE=$(curl -d 'username=admin&password=rigid' localhost:5000/login -v 2>&1  | grep Set-Cookie|cut -d : -f 2 |cut -d';' -f1)
SSHTOKEN=$(curl -H "Cookie: $COOKIE" localhost:5000/api/ingest/add/ssh|jq -r .token)

echo Token: $SSHTOKEN
curl -d "sshd login root 192.168.1.3 SUCCESS" localhost:5000/api/ingest/ssh/$SSHTOKEN
curl -d "sshd login root 192.168.1.6 FAIL" localhost:5000/api/ingest/ssh/$SSHTOKEN
curl -d "sshd login root 192.168.1.3 SUCCESS" localhost:5000/api/ingest/ssh/$SSHTOKEN

WEBTOKEN=$(curl -H "Cookie: $COOKIE" localhost:5000/api/ingest/add/web|jq -r .token)

curl -d "GET / 192.168.1.4 200" localhost:5000/api/ingest/web/$WEBTOKEN
curl -d "GET /admin 192.168.1.4 401" localhost:5000/api/ingest/web/$WEBTOKEN
curl -d "POST /login 192.168.1.6 302" localhost:5000/api/ingest/web/$WEBTOKEN

# bad token
curl -d "random log" localhost:5000/api/ingest/bla/$WEBTOKEN

# correlation search between web and ssh based on delim space (delim=^^ ^^) and the 3rd field (index 0) (field=3)

curl -H "Cookie: $COOKIE"  "http://localhost:5000/api/search?q=source%3Dssh+keyword%3D%22FAIL%22+delim%3D%5E%5E+%5E%5E+field%3D3+AND+source%3Dweb+"
