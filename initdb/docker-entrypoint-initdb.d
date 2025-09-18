services:
  zerodaydb:
    image: postgres:17
    container_name: zerodaydb
    environment:
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: postgres
    ports:
      - "5432:5432"
    volumes:
      - zerodaydb_data:/var/lib/postgresql/data
      - ./initdb:/docker-entrypoint-initdb.d

volumes:
  zerodaydb_data:
