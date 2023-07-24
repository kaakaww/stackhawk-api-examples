ARG ELASTIC_VERSION

# https://www.docker.elastic.co/
FROM docker.elastic.co/logstash/logstash:${ELASTIC_VERSION}

# Add your logstash plugins setup here
# Example: RUN logstash-plugin install logstash-filter-json


user root
RUN apt install -y python3 python3-requests python3-ratelimiter python3-dotenv

USER logstash
