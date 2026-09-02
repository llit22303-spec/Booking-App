from dotenv import load_dotenv
import os
import psycopg2
import psycopg2.extras

load_dotenv()


class DatabaseManager:

    def get_connection(self):
        try:
            database_url = os.getenv("DATABASE_URL")

            if not database_url:
                raise Exception("DATABASE_URL is not set")

            connection = psycopg2.connect(
                database_url,
                sslmode="require"
            )

            cursor = connection.cursor(
                cursor_factory=psycopg2.extras.RealDictCursor
            )

            return connection, cursor

        except Exception as e:
            print(f"Error connecting to database: {e}")
            return None, None
