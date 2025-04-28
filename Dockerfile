FROM gcc:14.2.0
VOLUME [ "/app/contest/" ]
WORKDIR /app/contest
COPY ./build/linux/release/judgecli /app
ENTRYPOINT [ "/app/judgecli" ]
