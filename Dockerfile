FROM ubuntu:18.04
COPY . .
RUN chmod +x setup.sh && ./setup.sh
