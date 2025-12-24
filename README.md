Docker：一键安装
```
touch data.json && chmod 666 data.json && docker run -d --name webssh --restart=always --network host -v $(pwd)/data.json:/app/data.json jhtone/webssh
```
