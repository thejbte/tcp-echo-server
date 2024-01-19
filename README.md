# TCP-Echo-Server
TCP Echo Server
## Build:
```vim
g++ cryptogr.cpp client.cpp -o client && g++ cryptogr.cpp server.cpp -o  server
```

## Run:

```vim
./server -d 1
```
```vim
./client "This is a message" "testu" "testp"
```
## Run with extra information
```vim
./server -d 2
```
```vim
./client "This is a message" "testu" "testp"
```

## Output:
![Screenshot from 2024-01-18 19-46-20](https://github.com/thejbte/TCP-Echo-Server/assets/17997755/5f33cbc3-2a5c-489b-a20a-6c0e4a2616d1)
