#docker build -t http_sniffer .
#docker run --net=host -t http_sniffer
FROM node:11.10.1
RUN apt-get update && apt-get install -y libpcap-dev
WORKDIR /app
COPY package.json /app
RUN npm install -g node-gyp
RUN npm install
COPY . /app
RUN node-gyp configure build
CMD node test_http.js
