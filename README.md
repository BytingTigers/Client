# client

## To build
> docker build --platform=linux/amd64 -t client .

## To execute
> docker run --network="host" -it client

## TroubleShoot
1. "Screen is too small. Minimum size required: 30 x 80"
If you get message "Screen is too small. Minimum size required: 30 x 80", you can follow these steps.
> docker run --network="host" -it client /bin/bash

After entering into shell, you should resize the shell to fit the minimum size before running client.

> /client/client

2. "Network Unreachable"
Check if you entered --network="host"

3. "Connection Failed"
You should run server program before running client.

