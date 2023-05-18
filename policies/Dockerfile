FROM docker.io/openpolicyagent/opa:0.52.0

WORKDIR /app/opa/policies

COPY . .

CMD ["run", "--server", "--bundle", "."]