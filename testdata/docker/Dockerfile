FROM alpine:latest

ENV OPENAI_API_KEY=sk-test_abcdefghijklmnopqrstuvwxyz123456
ARG ANTHROPIC_API_KEY=sk-ant-test_abcdefghijklmnopqrstuvwxyz123456

ENV NODE_ENV=production
ARG BUILD_NUMBER=42

RUN echo "GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz1234567890"

COPY .env /app/.env
ADD --chown=app:app .env /app/.env

RUN apk add --no-cache curl

RUN export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE && echo "configured"

CMD ["node", "app.js"]
